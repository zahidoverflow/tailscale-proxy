from __future__ import annotations

import ipaddress
import json
import os
import re
import select
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import textwrap
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TextIO

import typer
from rich import print
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

app = typer.Typer(add_completion=False, help="Friendly wizard for 9proxy + Tailscale")
console = Console()
APP_TITLE = "Tailscale-Proxy"
APP_ID = "tailscale-proxy"
LEGACY_APP_ID = "proxy-tailscale"
AUTO_HEAL_SERVICE = f"{APP_ID}-doctor.service"
AUTO_HEAL_TIMER = f"{APP_ID}-doctor.timer"
LEGACY_AUTO_HEAL_SERVICE = f"{LEGACY_APP_ID}-doctor.service"
LEGACY_AUTO_HEAL_TIMER = f"{LEGACY_APP_ID}-doctor.timer"
SOCKS_VERSION = 5
LOCAL_SOCKS_SERVICE = f"{APP_ID}-local-socks.service"
FORWARD_SERVICE = f"{APP_ID}-forward.service"
HTTP_PROXY_SERVICE = f"{APP_ID}-http.service"
ALLOWLIST_SERVICE = f"{APP_ID}-allowlist.service"


@dataclass
class CmdResult:
    cmd: str
    returncode: int
    stdout: str
    stderr: str


def run_cmd(cmd: str | list[str], sudo: bool = False, capture: bool = True) -> CmdResult:
    if isinstance(cmd, str):
        args = shlex.split(cmd)
    else:
        args = cmd

    if sudo and os.geteuid() != 0:
        args = ["sudo"] + args
        capture = False

    if capture:
        proc = subprocess.run(args, text=True, capture_output=True)
        return CmdResult(" ".join(args), proc.returncode, proc.stdout, proc.stderr)

    proc = subprocess.run(args)
    return CmdResult(" ".join(args), proc.returncode, "", "")


def log_line(log_fp: TextIO | None, text: str) -> None:
    if not log_fp:
        return
    log_fp.write(text + "\n")
    log_fp.flush()


def log_block(log_fp: TextIO | None, text: str) -> None:
    if not log_fp:
        return
    log_fp.write(text)
    if not text.endswith("\n"):
        log_fp.write("\n")
    log_fp.flush()


def print_section(title: str, log_fp: TextIO | None) -> None:
    header = f"\n=== {title} ==="
    print(header)
    log_line(log_fp, header)


def run_stream(cmd: list[str], log_fp: TextIO | None) -> int:
    if log_fp:
        log_line(log_fp, f"$ {' '.join(shlex.quote(part) for part in cmd)}")
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=False,
            bufsize=0,
        )
    except FileNotFoundError:
        msg = f"(command not found: {cmd[0]})"
        print(msg)
        log_line(log_fp, msg)
        return 127

    if not proc.stdout:
        return proc.wait()

    last_text = ""
    while True:
        chunk = proc.stdout.read(4096)
        if not chunk:
            break
        text = chunk.decode(errors="replace")
        last_text = text
        sys.stdout.write(text)
        sys.stdout.flush()
        if log_fp:
            log_fp.write(text)
            log_fp.flush()
    if log_fp and last_text and not last_text.endswith("\n"):
        log_fp.write("\n")
        log_fp.flush()
    return proc.wait()


def maybe_sudo(cmd: list[str], use_sudo: bool) -> list[str]:
    if use_sudo and os.geteuid() != 0:
        return ["sudo"] + cmd
    return cmd


def cmd_exists(name: str) -> bool:
    return shutil.which(name) is not None


def systemd_is_active(name: str) -> bool:
    res = run_cmd(["systemctl", "is-active", name], capture=True)
    return res.returncode == 0 and res.stdout.strip() == "active"


def detect_distro() -> str:
    path = Path("/etc/os-release")
    if not path.exists():
        return "unknown"
    data: dict[str, str] = {}
    for line in path.read_text().splitlines():
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        data[k] = v.strip().strip('"')
    distro_id = data.get("ID", "").lower()
    id_like = data.get("ID_LIKE", "").lower()
    if "arch" in id_like or distro_id in {"arch", "manjaro"}:
        return "arch"
    if "debian" in id_like or distro_id in {"debian", "ubuntu", "linuxmint"}:
        return "debian"
    return "unknown"


def tailscale_ip() -> str | None:
    res = run_cmd(["tailscale", "ip", "-4"], capture=True)
    ip = res.stdout.strip() if res.returncode == 0 else ""
    return ip or None


def tailscale_status() -> str:
    res = run_cmd(["tailscale", "status"], capture=True)
    return res.stdout.strip() if res.returncode == 0 else res.stderr.strip()


def tailscale_status_json() -> dict:
    res = run_cmd(["tailscale", "status", "--json"], capture=True)
    if res.returncode != 0:
        return {}
    try:
        return json.loads(res.stdout)
    except json.JSONDecodeError:
        return {}


def tailscale_dns_enabled() -> bool | None:
    res = run_cmd(["tailscale", "dns", "status"], capture=True)
    out = (res.stdout + res.stderr).lower()
    if "tailscale dns: enabled" in out:
        return True
    if "tailscale dns: disabled" in out:
        return False
    return None


def read_resolv_conf() -> tuple[list[str], str | None]:
    path = Path("/etc/resolv.conf")
    if not path.exists():
        return [], None
    target = None
    try:
        if path.is_symlink():
            target = str(path.resolve())
    except OSError:
        target = None
    nameservers: list[str] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line.startswith("nameserver"):
            continue
        parts = line.split()
        if len(parts) > 1:
            nameservers.append(parts[1])
    return nameservers, target


def tailscale_host_ip_map() -> dict[str, str]:
    data = tailscale_status_json()
    mapping: dict[str, str] = {}
    nodes = []
    self_node = data.get("Self")
    if isinstance(self_node, dict):
        nodes.append(self_node)
    peers = data.get("Peer", {})
    if isinstance(peers, dict):
        nodes.extend(peers.values())

    for node in nodes:
        if not isinstance(node, dict):
            continue
        ips = node.get("TailscaleIPs", []) or []
        ip4 = next((ip for ip in ips if "." in ip), None)
        if not ip4:
            continue
        names: set[str] = set()
        host = node.get("HostName") or ""
        if host:
            names.add(host.lower())
        dns = node.get("DNSName") or ""
        if dns:
            dns = dns.rstrip(".").lower()
            names.add(dns)
            names.add(dns.split(".")[0])
        for name in names:
            mapping[name] = ip4
    return mapping


def tailscale_dns_map() -> dict[str, str]:
    data = tailscale_status_json()
    mapping: dict[str, str] = {}
    nodes = []
    self_node = data.get("Self")
    if isinstance(self_node, dict):
        nodes.append(self_node)
    peers = data.get("Peer", {})
    if isinstance(peers, dict):
        nodes.extend(peers.values())

    for node in nodes:
        if not isinstance(node, dict):
            continue
        dns = node.get("DNSName") or ""
        host = node.get("HostName") or ""
        if not dns:
            continue
        dns = dns.rstrip(".")
        if host:
            mapping[host.lower()] = dns
        mapping[dns.lower()] = dns
        mapping[dns.split(".")[0].lower()] = dns
    return mapping


def tailscale_self_dns() -> str | None:
    data = tailscale_status_json()
    self_node = data.get("Self", {})
    if isinstance(self_node, dict):
        dns = self_node.get("DNSName") or ""
        return dns.rstrip(".") if dns else None
    return None


def tailscale_self_host() -> str | None:
    data = tailscale_status_json()
    self_node = data.get("Self", {})
    if isinstance(self_node, dict):
        host = self_node.get("HostName") or ""
        return host.strip() or None
    return None


def resolve_tshost(host: str, mapping: dict[str, str]) -> str:
    if not host.endswith(".tshost"):
        return host
    base = host[: -len(".tshost")].lower()
    return mapping.get(base, host)


def split_host_port(value: str, default_host: str = "0.0.0.0") -> tuple[str, int]:
    raw = value.strip()
    if raw.startswith(":"):
        host, port = default_host, raw[1:]
    elif raw.startswith("["):
        if "]" not in raw:
            raise ValueError("invalid IPv6 address format")
        host, rest = raw[1:].split("]", 1)
        if not rest.startswith(":"):
            raise ValueError("missing port")
        port = rest[1:]
    else:
        if raw.count(":") == 0:
            raise ValueError("missing port")
        if raw.count(":") > 1:
            raise ValueError("IPv6 must be in [addr]:port format")
        host, port = raw.rsplit(":", 1)
    try:
        port_num = int(port)
    except ValueError as exc:
        raise ValueError("invalid port") from exc
    return host or default_host, port_num


def resolve_host_port(
    value: str,
    mapping: dict[str, str],
    default_host: str = "0.0.0.0",
) -> tuple[str, int]:
    host, port = split_host_port(value, default_host=default_host)
    host = resolve_tshost(host, mapping)
    return host, port


def is_ip_addr(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def sockaddr(host: str, port: int, family: int) -> tuple:
    if family == socket.AF_INET6:
        return (host, port, 0, 0)
    return (host, port)

def is_9proxy_logged_in() -> bool:
    res = run_cmd(["9proxy", "setting", "--display"], capture=True)
    out = res.stdout.lower()
    return "user logged" in out and "true" in out


def fetch_port_status() -> tuple[CmdResult, dict[int, dict[str, str]]]:
    res = run_cmd(["9proxy", "port", "--status"], capture=True)
    return res, parse_port_status(res.stdout)


def port_is_online(info: dict[str, str] | None) -> bool:
    if not info:
        return False
    return info.get("online", "").strip().lower() == "online"


def restart_9proxy_daemon() -> bool:
    for unit in ("9proxyd.service", "9proxy.service"):
        res = run_cmd(["systemctl", "restart", unit], sudo=True, capture=True)
        if res.returncode == 0:
            return True

    bin_path = shutil.which("9proxy") or "/usr/bin/9proxy"
    run_cmd(["pkill", "-f", f"{bin_path} -daemon"], sudo=True, capture=False)
    start_cmd = f"nohup {shlex.quote(bin_path)} -daemon >/var/log/9proxy.log 2>&1 &"
    res = run_cmd(["sh", "-c", start_cmd], sudo=True, capture=False)
    return res.returncode == 0


def parse_port_status(output: str) -> dict[int, dict[str, str]]:
    ports: dict[int, dict[str, str]] = {}
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cols = [c.strip() for c in line.strip("|").split("|")]
        if len(cols) < 5:
            continue
        binding = cols[0]
        if ":" not in binding:
            continue
        try:
            port = int(binding.split(":")[-1])
        except ValueError:
            continue
        ports[port] = {
            "binding": binding,
            "city": cols[1],
            "public_ip": cols[2],
            "online": cols[3],
            "status": cols[4],
        }
    return ports


def pick_default_port() -> tuple[str, dict[int, dict[str, str]]]:
    _, ports = fetch_port_status()
    used_ports = [p for p, info in ports.items() if info["status"].lower() == "used"]
    if used_ports:
        used_ports.sort()
        return str(used_ports[0]), ports
    return "60000", ports


def ensure_binary(name: str, distro: str, why: str) -> bool:
    if cmd_exists(name):
        return True
    print(f"[red]Missing:[/red] {name} ({why})")
    if name == "tailscale":
        if distro == "debian":
            print("Install: curl -fsSL https://tailscale.com/install.sh | sh")
        elif distro == "arch":
            print("Install: sudo pacman -S tailscale")
        else:
            print("Install tailscale from https://tailscale.com/download")
    elif name in {"redsocks", "redsocks2"}:
        if distro == "debian":
            print("Install: sudo apt install redsocks")
        elif distro == "arch":
            print("Install: pamac build redsocks2")
        else:
            print("Install a redsocks package for your distro")
    elif name == "9proxy":
        print("Install 9proxy from your account dashboard")
    return False


def write_file(path: Path, content: str, mode: int = 0o644) -> None:
    if os.geteuid() == 0:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        os.chmod(path, mode)
        return

    run_cmd(["mkdir", "-p", str(path.parent)], sudo=True, capture=False)
    subprocess.run(
        ["sudo", "tee", str(path)],
        input=content,
        text=True,
        stdout=subprocess.DEVNULL,
    )
    run_cmd(["chmod", f"{mode:o}", str(path)], sudo=True, capture=False)


def backup_file(path: Path) -> None:
    if not path.exists():
        return
    backup = path.with_suffix(path.suffix + f".bak.{APP_ID}")
    if backup.exists():
        return
    if os.geteuid() == 0:
        shutil.copy2(path, backup)
    else:
        run_cmd(["cp", str(path), str(backup)], sudo=True, capture=False)


def render_redsocks_config(ip: str, port: int, udp: bool) -> str:
    base = textwrap.dedent(
        f"""
        # Managed by {APP_ID}. Manual edits may be overwritten.
        base {{
          log_debug = off;
          log_info = on;
          log = \"syslog:daemon\";
          daemon = on;
          user = redsocks;
          group = redsocks;
          redirector = iptables;
        }}

        redsocks {{
          bind = \"0.0.0.0:12345\";
          relay = \"{ip}:{port}\";
          type = socks5;
          autoproxy = 0;
        }}
        """
    ).strip()
    if not udp:
        return base + "\n"
    redudp = textwrap.dedent(
        f"""

        redudp {{
          bind = \"0.0.0.0:12346\";
          relay = \"{ip}:{port}\";
          type = socks5;
          udp_timeout = 30;
          udp_timeout_stream = 180;
        }}
        """
    ).rstrip()
    return base + redudp + "\n"


def tcp_redirect_script() -> str:
    return textwrap.dedent(
        """
        #!/bin/sh
        set -e
        CHAIN=TS_9PROXY
        IFACE=tailscale0
        REDSOCKS_PORT=12345
        case "${1:-}" in
          start)
            iptables -t nat -N "$CHAIN" 2>/dev/null || true
            iptables -t nat -F "$CHAIN"
            iptables -t nat -A "$CHAIN" -d 100.64.0.0/10 -j RETURN
            iptables -t nat -A "$CHAIN" -d 127.0.0.0/8 -j RETURN
            iptables -t nat -A "$CHAIN" -d 10.0.0.0/8 -j RETURN
            iptables -t nat -A "$CHAIN" -d 172.16.0.0/12 -j RETURN
            iptables -t nat -A "$CHAIN" -d 192.168.0.0/16 -j RETURN
            iptables -t nat -A "$CHAIN" -d 169.254.0.0/16 -j RETURN
            iptables -t nat -A "$CHAIN" -p tcp -j REDIRECT --to-ports "$REDSOCKS_PORT"
            if ! iptables -t nat -C PREROUTING -i "$IFACE" -p tcp -j "$CHAIN" 2>/dev/null; then
              iptables -t nat -A PREROUTING -i "$IFACE" -p tcp -j "$CHAIN"
            fi
            ;;
          stop)
            iptables -t nat -D PREROUTING -i "$IFACE" -p tcp -j "$CHAIN" 2>/dev/null || true
            iptables -t nat -F "$CHAIN" 2>/dev/null || true
            iptables -t nat -X "$CHAIN" 2>/dev/null || true
            ;;
          *)
            echo "Usage: $0 {start|stop}" >&2
            exit 1
            ;;
        esac
        """
    ).lstrip()


def tcp_redirect_unit(service_name: str) -> str:
    return textwrap.dedent(
        f"""
        [Unit]
        Description=Redirect tailnet TCP to 9proxy via redsocks
        After=network-online.target tailscaled.service {service_name}
        Wants=network-online.target tailscaled.service {service_name}

        [Service]
        Type=oneshot
        RemainAfterExit=yes
        ExecStart=/usr/local/sbin/ts-9proxy-redirect.sh start
        ExecStop=/usr/local/sbin/ts-9proxy-redirect.sh stop

        [Install]
        WantedBy=multi-user.target
        """
    ).lstrip()


def udp_redirect_script() -> str:
    return textwrap.dedent(
        """
        #!/bin/sh
        set -e
        CHAIN=TS_9PROXY_UDP
        IFACE=tailscale0
        REDUDP_PORT=12346
        MARK=0x1
        TABLE=100
        case "${1:-}" in
          start)
            modprobe xt_TPROXY 2>/dev/null || true
            modprobe nf_tproxy_ipv4 2>/dev/null || true
            iptables -t mangle -N "$CHAIN" 2>/dev/null || true
            iptables -t mangle -F "$CHAIN"
            iptables -t mangle -A "$CHAIN" -d 100.64.0.0/10 -j RETURN
            iptables -t mangle -A "$CHAIN" -d 127.0.0.0/8 -j RETURN
            iptables -t mangle -A "$CHAIN" -d 10.0.0.0/8 -j RETURN
            iptables -t mangle -A "$CHAIN" -d 172.16.0.0/12 -j RETURN
            iptables -t mangle -A "$CHAIN" -d 192.168.0.0/16 -j RETURN
            iptables -t mangle -A "$CHAIN" -d 169.254.0.0/16 -j RETURN
            iptables -t mangle -A "$CHAIN" -p udp -j TPROXY --on-port "$REDUDP_PORT" --tproxy-mark "$MARK/$MARK"
            if ! iptables -t mangle -C PREROUTING -i "$IFACE" -p udp -j "$CHAIN" 2>/dev/null; then
              iptables -t mangle -A PREROUTING -i "$IFACE" -p udp -j "$CHAIN"
            fi
            ip rule add fwmark "$MARK" lookup "$TABLE" priority 100 2>/dev/null || true
            ip route replace local 0.0.0.0/0 dev lo table "$TABLE"
            ;;
          stop)
            iptables -t mangle -D PREROUTING -i "$IFACE" -p udp -j "$CHAIN" 2>/dev/null || true
            iptables -t mangle -F "$CHAIN" 2>/dev/null || true
            iptables -t mangle -X "$CHAIN" 2>/dev/null || true
            ip rule del fwmark "$MARK" lookup "$TABLE" priority 100 2>/dev/null || true
            ip route del local 0.0.0.0/0 dev lo table "$TABLE" 2>/dev/null || true
            ;;
          *)
            echo "Usage: $0 {start|stop}" >&2
            exit 1
            ;;
        esac
        """
    ).lstrip()


def udp_redirect_unit(service_name: str) -> str:
    return textwrap.dedent(
        f"""
        [Unit]
        Description=Redirect tailnet UDP to 9proxy via redudp (TPROXY)
        After=network-online.target tailscaled.service {service_name}
        Wants=network-online.target tailscaled.service {service_name}

        [Service]
        Type=oneshot
        RemainAfterExit=yes
        ExecStart=/usr/local/sbin/ts-9proxy-udp-tproxy.sh start
        ExecStop=/usr/local/sbin/ts-9proxy-udp-tproxy.sh stop

        [Install]
        WantedBy=multi-user.target
        """
    ).lstrip()


def udp_block_script() -> str:
    return textwrap.dedent(
        """
        #!/bin/sh
        set -e
        IFACE=tailscale0
        MODE="${UDP_BLOCK_MODE:-443}"
        case "${1:-}" in
          start)
            if [ "$MODE" = "all" ]; then
              iptables -C FORWARD -i "$IFACE" -p udp -j REJECT 2>/dev/null || \\
                iptables -I FORWARD -i "$IFACE" -p udp -j REJECT
            else
              iptables -C FORWARD -i "$IFACE" -p udp --dport 443 -j REJECT 2>/dev/null || \\
                iptables -I FORWARD -i "$IFACE" -p udp --dport 443 -j REJECT
            fi
            ;;
          stop)
            if [ "$MODE" = "all" ]; then
              iptables -D FORWARD -i "$IFACE" -p udp -j REJECT 2>/dev/null || true
            else
              iptables -D FORWARD -i "$IFACE" -p udp --dport 443 -j REJECT 2>/dev/null || true
            fi
            ;;
          *)
            echo "Usage: $0 {start|stop}" >&2
            exit 1
            ;;
        esac
        """
    ).lstrip()


def udp_block_unit(mode: str) -> str:
    return textwrap.dedent(
        f"""
        [Unit]
        Description=Block UDP from tailnet (mode: {mode})
        After=network-online.target tailscaled.service
        Wants=network-online.target tailscaled.service

        [Service]
        Type=oneshot
        RemainAfterExit=yes
        Environment=UDP_BLOCK_MODE={mode}
        ExecStart=/usr/local/sbin/ts-udp-block.sh start
        ExecStop=/usr/local/sbin/ts-udp-block.sh stop

        [Install]
        WantedBy=multi-user.target
        """
    ).lstrip()


def no_leak_script() -> str:
    return textwrap.dedent(
        """
        #!/bin/sh
        set -e
        IFACE=tailscale0
        CHAIN=TS_NO_LEAK
        case "${1:-}" in
          start)
            iptables -t filter -N "$CHAIN" 2>/dev/null || true
            iptables -t filter -F "$CHAIN"
            iptables -t filter -A "$CHAIN" -j DROP
            if ! iptables -t filter -C FORWARD -i "$IFACE" -j "$CHAIN" 2>/dev/null; then
              iptables -t filter -I FORWARD -i "$IFACE" -j "$CHAIN"
            fi
            if command -v ip6tables >/dev/null 2>&1; then
              ip6tables -t filter -N "$CHAIN" 2>/dev/null || true
              ip6tables -t filter -F "$CHAIN"
              ip6tables -t filter -A "$CHAIN" -j DROP
              if ! ip6tables -t filter -C FORWARD -i "$IFACE" -j "$CHAIN" 2>/dev/null; then
                ip6tables -t filter -I FORWARD -i "$IFACE" -j "$CHAIN"
              fi
            fi
            ;;
          stop)
            iptables -t filter -D FORWARD -i "$IFACE" -j "$CHAIN" 2>/dev/null || true
            iptables -t filter -F "$CHAIN" 2>/dev/null || true
            iptables -t filter -X "$CHAIN" 2>/dev/null || true
            if command -v ip6tables >/dev/null 2>&1; then
              ip6tables -t filter -D FORWARD -i "$IFACE" -j "$CHAIN" 2>/dev/null || true
              ip6tables -t filter -F "$CHAIN" 2>/dev/null || true
              ip6tables -t filter -X "$CHAIN" 2>/dev/null || true
            fi
            ;;
          *)
            echo "Usage: $0 {start|stop}" >&2
            exit 1
            ;;
        esac
        """
    ).lstrip()


def no_leak_unit() -> str:
    return textwrap.dedent(
        """
        [Unit]
        Description=No-leak strict mode (block forwarding from tailnet)
        After=network-online.target tailscaled.service
        Wants=network-online.target tailscaled.service

        [Service]
        Type=oneshot
        RemainAfterExit=yes
        ExecStart=/usr/local/sbin/ts-no-leak.sh start
        ExecStop=/usr/local/sbin/ts-no-leak.sh stop

        [Install]
        WantedBy=multi-user.target
        """
    ).lstrip()


def ensure_redsocks_caps_if_needed(distro: str) -> None:
    if distro != "arch":
        return
    override = textwrap.dedent(
        """
        [Service]
        AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
        CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
        """
    ).lstrip()
    path = Path("/etc/systemd/system/redsocks2.service.d/override.conf")
    write_file(path, override)
    run_cmd(["systemctl", "daemon-reload"], sudo=True, capture=False)


def redsocks_config_path(distro: str) -> Path:
    return Path("/etc/redsocks2.conf" if distro == "arch" else "/etc/redsocks.conf")


def redsocks_service_name(distro: str) -> str:
    return "redsocks2.service" if distro == "arch" else "redsocks.service"


def update_redsocks_relay(path: Path, ip: str, port: int) -> str:
    if not path.exists():
        return "missing"
    content = path.read_text()
    updated = re.sub(r'relay\s*=\s*\"[^\"]+\";', f'relay = \"{ip}:{port}\";', content)
    if content == updated:
        return "unchanged"
    write_file(path, updated)
    return "updated"


def current_relay_port(path: Path) -> int | None:
    if not path.exists():
        return None
    content = path.read_text()
    match = re.search(r'relay\s*=\s*\"[^\"]+:(\d+)\";', content)
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def recv_exact(sock: socket.socket, count: int) -> bytes:
    buf = b""
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def build_socks_address(host: str) -> tuple[int, bytes]:
    try:
        ip = ipaddress.ip_address(host)
        if ip.version == 4:
            return 1, ip.packed
        return 4, ip.packed
    except ValueError:
        data = host.encode("idna")
        if len(data) > 255:
            raise ValueError("domain too long")
        return 3, bytes([len(data)]) + data


def read_socks_address(sock: socket.socket, atyp: int) -> tuple[str, int]:
    if atyp == 1:
        addr = socket.inet_ntoa(recv_exact(sock, 4))
    elif atyp == 3:
        ln = recv_exact(sock, 1)[0]
        addr = recv_exact(sock, ln).decode(errors="ignore")
    elif atyp == 4:
        addr = socket.inet_ntop(socket.AF_INET6, recv_exact(sock, 16))
    else:
        raise ValueError("invalid ATYP")
    port = int.from_bytes(recv_exact(sock, 2), "big")
    return addr, port


def send_socks_reply(sock: socket.socket, rep: int, host: str, port: int) -> None:
    atyp, addr_bytes = build_socks_address(host)
    sock.sendall(bytes([SOCKS_VERSION, rep, 0, atyp]) + addr_bytes + port.to_bytes(2, "big"))


def socks_handshake(sock: socket.socket) -> None:
    sock.sendall(bytes([SOCKS_VERSION, 1, 0]))
    resp = recv_exact(sock, 2)
    if resp != bytes([SOCKS_VERSION, 0]):
        raise ConnectionError("upstream auth failed")


def socks_connect_upstream(
    upstream_host: str,
    upstream_port: int,
    cmd: int,
    dest_host: str,
    dest_port: int,
    timeout: int = 10,
) -> tuple[socket.socket, bytes]:
    upstream = socket.create_connection((upstream_host, upstream_port), timeout=timeout)
    socks_handshake(upstream)
    atyp, addr_bytes = build_socks_address(dest_host)
    req = bytes([SOCKS_VERSION, cmd, 0, atyp]) + addr_bytes + dest_port.to_bytes(2, "big")
    upstream.sendall(req)
    header = recv_exact(upstream, 4)
    ver, rep, _, atyp = header
    if ver != SOCKS_VERSION:
        raise ConnectionError("invalid upstream response")
    addr = b""
    if atyp == 1:
        addr = recv_exact(upstream, 4)
    elif atyp == 3:
        ln = recv_exact(upstream, 1)
        addr = ln + recv_exact(upstream, ln[0])
    elif atyp == 4:
        addr = recv_exact(upstream, 16)
    else:
        raise ConnectionError("invalid upstream ATYP")
    port = recv_exact(upstream, 2)
    resp = header + addr + port
    if rep != 0:
        raise ConnectionError(f"upstream error {rep}")
    return upstream, resp


def socks_udp_associate(
    upstream_host: str,
    upstream_port: int,
    bind_host: str,
    bind_port: int,
    timeout: int = 10,
) -> tuple[socket.socket, tuple[str, int]]:
    upstream = socket.create_connection((upstream_host, upstream_port), timeout=timeout)
    socks_handshake(upstream)
    atyp, addr_bytes = build_socks_address(bind_host)
    req = bytes([SOCKS_VERSION, 3, 0, atyp]) + addr_bytes + bind_port.to_bytes(2, "big")
    upstream.sendall(req)
    header = recv_exact(upstream, 4)
    ver, rep, _, atyp = header
    if ver != SOCKS_VERSION or rep != 0:
        raise ConnectionError(f"udp associate failed ({rep})")
    if atyp == 1:
        relay_host = socket.inet_ntoa(recv_exact(upstream, 4))
    elif atyp == 3:
        ln = recv_exact(upstream, 1)[0]
        relay_host = recv_exact(upstream, ln).decode(errors="ignore")
    elif atyp == 4:
        relay_host = socket.inet_ntop(socket.AF_INET6, recv_exact(upstream, 16))
    else:
        raise ConnectionError("invalid upstream ATYP")
    relay_port = int.from_bytes(recv_exact(upstream, 2), "big")
    if relay_host in {"0.0.0.0", "::"}:
        relay_host = upstream_host
    if relay_port == 0:
        relay_port = upstream_port
    return upstream, (relay_host, relay_port)


def parse_udp_datagram(data: bytes) -> tuple[int, str, int, bytes]:
    if len(data) < 4:
        raise ValueError("short UDP datagram")
    if data[2] != 0:
        raise ValueError("fragmentation not supported")
    atyp = data[3]
    idx = 4
    if atyp == 1:
        if len(data) < idx + 4:
            raise ValueError("short IPv4")
        host = socket.inet_ntoa(data[idx : idx + 4])
        idx += 4
    elif atyp == 3:
        if len(data) < idx + 1:
            raise ValueError("short domain")
        ln = data[idx]
        idx += 1
        host = data[idx : idx + ln].decode(errors="ignore")
        idx += ln
    elif atyp == 4:
        if len(data) < idx + 16:
            raise ValueError("short IPv6")
        host = socket.inet_ntop(socket.AF_INET6, data[idx : idx + 16])
        idx += 16
    else:
        raise ValueError("invalid ATYP")
    if len(data) < idx + 2:
        raise ValueError("short port")
    port = int.from_bytes(data[idx : idx + 2], "big")
    idx += 2
    payload = data[idx:]
    return atyp, host, port, payload


def build_udp_datagram(host: str, port: int, payload: bytes) -> bytes:
    atyp, addr_bytes = build_socks_address(host)
    return b"\x00\x00\x00" + bytes([atyp]) + addr_bytes + port.to_bytes(2, "big") + payload


def relay_tcp(a: socket.socket, b: socket.socket, timeout: int) -> None:
    a.settimeout(timeout)
    b.settimeout(timeout)
    sockets = [a, b]
    while True:
        readable, _, _ = select.select(sockets, [], [], timeout)
        if not readable:
            continue
        for s in readable:
            try:
                data = s.recv(65536)
            except OSError:
                return
            if not data:
                return
            other = b if s is a else a
            try:
                other.sendall(data)
            except OSError:
                return


def parse_http_request(sock: socket.socket) -> tuple[str, str, int, bytes]:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > 65536:
            break
    if not data:
        raise ConnectionError("empty request")
    header, _, rest = data.partition(b"\r\n\r\n")
    lines = header.split(b"\r\n")
    if not lines:
        raise ConnectionError("invalid request")
    first = lines[0].decode(errors="ignore")
    parts = first.split()
    if len(parts) < 2:
        raise ConnectionError("invalid request line")
    method, target = parts[0], parts[1]
    host = ""
    port = 80
    if method.upper() == "CONNECT":
        if target.startswith("[") and "]" in target:
            host = target[1:target.index("]")]
            port = int(target.split("]:", 1)[1])
        else:
            host, port_str = target.rsplit(":", 1)
            port = int(port_str)
        return method, host, port, b""
    if target.startswith("http://"):
        target = target[7:]
        host_part, _, path = target.partition("/")
        target_host = host_part
        if ":" in target_host:
            host, port_str = target_host.rsplit(":", 1)
            port = int(port_str)
        else:
            host = target_host
        rebuilt = f"{method} /{path} HTTP/1.1".encode()
    else:
        rebuilt = lines[0]
        for line in lines[1:]:
            if line.lower().startswith(b"host:"):
                host_line = line.decode(errors="ignore").split(":", 1)[1].strip()
                if host_line.startswith("[") and "]" in host_line:
                    host = host_line[1:host_line.index("]")]
                    rest = host_line.split("]:", 1)
                    if len(rest) == 2:
                        port = int(rest[1])
                elif ":" in host_line:
                    host, port_str = host_line.rsplit(":", 1)
                    port = int(port_str)
                else:
                    host = host_line
        if not host:
            raise ConnectionError("missing host header")
    new_header = b"\r\n".join([rebuilt] + lines[1:]) + b"\r\n\r\n" + rest
    return method, host, port, new_header


def serve_http_proxy(
    listen: str,
    upstream: str,
    tcp_timeout: int,
) -> None:
    mapping = tailscale_host_ip_map()
    listen_host, listen_port = resolve_host_port(listen, mapping, default_host="127.0.0.1")
    upstream_host, upstream_port = resolve_host_port(upstream, mapping, default_host="127.0.0.1")
    family = socket.AF_INET6 if ":" in listen_host else socket.AF_INET
    server = socket.socket(family, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(sockaddr(listen_host, listen_port, family))
    server.listen(128)
    print(f"[green]HTTP proxy listening on {listen_host}:{listen_port}[/green]")
    print(f"Upstream SOCKS: {upstream_host}:{upstream_port}")

    while True:
        client, _ = server.accept()

        def handler(sock: socket.socket) -> None:
            try:
                method, host, port, payload = parse_http_request(sock)
                host = resolve_tshost(host, mapping)
                upstream, _ = socks_connect_upstream(
                    upstream_host,
                    upstream_port,
                    1,
                    host,
                    port,
                    timeout=tcp_timeout,
                )
                if method.upper() == "CONNECT":
                    sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                else:
                    upstream.sendall(payload)
                relay_tcp(sock, upstream, tcp_timeout)
                upstream.close()
            except Exception:
                try:
                    sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                except OSError:
                    pass
            finally:
                try:
                    sock.close()
                except OSError:
                    pass

        threading.Thread(target=handler, args=(client,), daemon=True).start()


def handle_udp_associate(
    client: socket.socket,
    upstream_host: str,
    upstream_port: int,
    mapping: dict[str, str],
    listen_host: str,
    tcp_timeout: int,
    udp_timeout: int,
) -> None:
    local_host = listen_host if listen_host not in ("0.0.0.0", "::") else client.getsockname()[0]
    family = socket.AF_INET6 if ":" in local_host else socket.AF_INET
    udp_sock = socket.socket(family, socket.SOCK_DGRAM)
    udp_sock.bind(sockaddr(local_host, 0, family))
    bound_host, bound_port = udp_sock.getsockname()[:2]

    upstream, relay = socks_udp_associate(
        upstream_host,
        upstream_port,
        bound_host,
        bound_port,
        timeout=tcp_timeout,
    )
    relay_host, relay_port = relay
    send_socks_reply(client, 0, local_host, bound_port)

    stop = threading.Event()
    last_activity = time.time()
    client_addr: tuple[str, int] | None = None

    def udp_loop() -> None:
        nonlocal last_activity, client_addr
        while not stop.is_set():
            readable, _, _ = select.select([udp_sock], [], [], 1)
            if not readable:
                if time.time() - last_activity > udp_timeout:
                    break
                continue
            data, addr = udp_sock.recvfrom(65536)
            last_activity = time.time()
            if addr[0] == relay_host and addr[1] == relay_port:
                if client_addr:
                    udp_sock.sendto(data, client_addr)
                continue
            client_addr = addr
            try:
                _, host, port, payload = parse_udp_datagram(data)
                resolved = resolve_tshost(host, mapping)
                if resolved != host:
                    data = build_udp_datagram(resolved, port, payload)
            except ValueError:
                pass
            relay_addr = sockaddr(relay_host, relay_port, family if ":" in relay_host else socket.AF_INET)
            udp_sock.sendto(data, relay_addr)

    thread = threading.Thread(target=udp_loop, daemon=True)
    thread.start()

    client.settimeout(1)
    while not stop.is_set():
        try:
            chunk = client.recv(1)
            if not chunk:
                break
        except socket.timeout:
            if not thread.is_alive():
                break
            continue
        except OSError:
            break
    stop.set()
    try:
        udp_sock.close()
    except OSError:
        pass
    try:
        upstream.close()
    except OSError:
        pass
    thread.join(timeout=2)


def handle_socks_client(
    client: socket.socket,
    upstream_host: str,
    upstream_port: int,
    mapping: dict[str, str],
    listen_host: str,
    allow_udp: bool,
    tcp_timeout: int,
    udp_timeout: int,
) -> None:
    try:
        client.settimeout(tcp_timeout)
        ver = recv_exact(client, 1)[0]
        if ver != SOCKS_VERSION:
            return
        nmethods = recv_exact(client, 1)[0]
        methods = recv_exact(client, nmethods)
        if 0 not in methods:
            client.sendall(bytes([SOCKS_VERSION, 0xFF]))
            return
        client.sendall(bytes([SOCKS_VERSION, 0x00]))

        header = recv_exact(client, 4)
        ver, cmd, _, atyp = header
        if ver != SOCKS_VERSION:
            return
        dest_host, dest_port = read_socks_address(client, atyp)
        dest_host = resolve_tshost(dest_host, mapping)

        if cmd == 1:
            upstream, resp = socks_connect_upstream(
                upstream_host,
                upstream_port,
                cmd,
                dest_host,
                dest_port,
                timeout=tcp_timeout,
            )
            client.sendall(resp)
            relay_tcp(client, upstream, tcp_timeout)
            upstream.close()
            return
        if cmd == 3:
            if not allow_udp:
                send_socks_reply(client, 7, "0.0.0.0", 0)
                return
            handle_udp_associate(
                client,
                upstream_host,
                upstream_port,
                mapping,
                listen_host,
                tcp_timeout,
                udp_timeout,
            )
            return
        send_socks_reply(client, 7, "0.0.0.0", 0)
    except Exception:
        try:
            send_socks_reply(client, 1, "0.0.0.0", 0)
        except OSError:
            pass
    finally:
        try:
            client.close()
        except OSError:
            pass


def serve_local_socks(
    listen: str,
    upstream: str,
    allow_udp: bool,
    tcp_timeout: int,
    udp_timeout: int,
) -> None:
    mapping = tailscale_host_ip_map()
    listen_host, listen_port = resolve_host_port(listen, mapping, default_host="127.0.0.1")
    upstream_host, upstream_port = resolve_host_port(upstream, mapping, default_host="127.0.0.1")
    family = socket.AF_INET6 if ":" in listen_host else socket.AF_INET
    server = socket.socket(family, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(sockaddr(listen_host, listen_port, family))
    server.listen(128)
    print(f"[green]Local SOCKS forwarder listening on {listen_host}:{listen_port}[/green]")
    print(f"Upstream: {upstream_host}:{upstream_port} (UDP: {'on' if allow_udp else 'off'})")

    while True:
        client, _ = server.accept()
        thread = threading.Thread(
            target=handle_socks_client,
            args=(client, upstream_host, upstream_port, mapping, listen_host, allow_udp, tcp_timeout, udp_timeout),
            daemon=True,
        )
        thread.start()


def profile_store_path() -> Path:
    return Path.home() / ".config" / APP_ID / "profiles.json"


def load_profiles() -> dict:
    path = profile_store_path()
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        defaults = {
            "phone_stable": {"action": "stable"},
            "desktop_socks": {"action": "local_socks"},
            "strict_no_leak": {"action": "strict"},
        }
        path.write_text(json.dumps(defaults, indent=2))
        return defaults
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return {}


def save_profiles(data: dict) -> None:
    path = profile_store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))


def apply_profile(name: str, data: dict) -> None:
    action = data.get("action")
    if action == "stable":
        stable_mode()
        strict_mode()
    elif action == "local_socks":
        ip = tailscale_ip() or "127.0.0.1"
        install_local_socks_service("127.0.0.1:1080", f"{ip}:60000", True, 1100, 330)
    elif action == "strict":
        strict_mode()
    else:
        print(f"[red]Unknown profile action: {action}[/red]")


def profile_menu() -> None:
    profiles = load_profiles()
    if not profiles:
        print("[yellow]No profiles found.[/yellow]")
        return
    names = sorted(profiles.keys())
    print("Profiles:")
    for idx, name in enumerate(names, 1):
        print(f"{idx}) {name}")
    choice = Prompt.ask("Choose profile", default="1")
    try:
        idx = int(choice) - 1
        if idx < 0 or idx >= len(names):
            raise ValueError
    except ValueError:
        print("[red]Invalid choice.[/red]")
        return
    apply_profile(names[idx], profiles[names[idx]])


def cert_dir() -> Path:
    if os.geteuid() == 0:
        return Path("/var/lib") / APP_ID / "certs"
    return Path.home() / ".local" / "share" / APP_ID / "certs"


def ensure_tls_cert(domain: str) -> tuple[Path, Path]:
    cert_path = cert_dir() / f"{domain}.crt"
    key_path = cert_dir() / f"{domain}.key"
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    if not cert_path.exists() or not key_path.exists():
        res = run_cmd(
            [
                "tailscale",
                "cert",
                "--cert-file",
                str(cert_path),
                "--key-file",
                str(key_path),
                domain,
            ],
            capture=True,
        )
        if res.returncode != 0:
            raise RuntimeError(res.stderr.strip() or "Failed to fetch Tailscale cert")
    if not cert_path.exists() or not key_path.exists():
        raise RuntimeError("Tailscale cert files missing")
    return cert_path, key_path


def parse_tcp_rule(rule: str) -> tuple[str, str, bool]:
    if "=TLS=" in rule:
        bind, connect = rule.split("=TLS=", 1)
        return bind.strip(), connect.strip(), True
    if "=" not in rule:
        raise ValueError("rule must be bind=connect")
    bind, connect = rule.split("=", 1)
    return bind.strip(), connect.strip(), False


def tls_domain_for_bind(bind_host: str, dns_map: dict[str, str]) -> str | None:
    if bind_host.endswith(".tshost"):
        base = bind_host[: -len(".tshost")].lower()
        return dns_map.get(base)
    if is_ip_addr(bind_host):
        return tailscale_self_dns()
    return dns_map.get(bind_host.lower(), bind_host)


def forward_tcp_server(
    bind: str,
    connect: str,
    use_tls: bool,
    tcp_timeout: int,
    mapping: dict[str, str],
    dns_map: dict[str, str],
) -> None:
    bind_host, bind_port = resolve_host_port(bind, mapping, default_host="0.0.0.0")
    connect_host, connect_port = resolve_host_port(connect, mapping, default_host="127.0.0.1")
    family = socket.AF_INET6 if ":" in bind_host else socket.AF_INET
    server = socket.socket(family, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(sockaddr(bind_host, bind_port, family))
    server.listen(128)

    ssl_ctx: ssl.SSLContext | None = None
    if use_tls:
        domain = tls_domain_for_bind(bind_host, dns_map)
        if not domain:
            raise RuntimeError("TLS requires a valid tailnet DNS name")
        cert_path, key_path = ensure_tls_cert(domain)
        ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    print(f"[green]TCP forward[/green] {bind_host}:{bind_port} -> {connect_host}:{connect_port}")

    while True:
        client, _ = server.accept()
        if ssl_ctx:
            try:
                client = ssl_ctx.wrap_socket(client, server_side=True)
            except ssl.SSLError:
                client.close()
                continue
        try:
            upstream = socket.create_connection((connect_host, connect_port), timeout=tcp_timeout)
        except OSError:
            client.close()
            continue
        thread = threading.Thread(target=relay_tcp, args=(client, upstream, tcp_timeout), daemon=True)
        thread.start()


def forward_udp_server(
    bind: str,
    connect: str,
    udp_timeout: int,
    mapping: dict[str, str],
) -> None:
    bind_host, bind_port = resolve_host_port(bind, mapping, default_host="0.0.0.0")
    connect_host, connect_port = resolve_host_port(connect, mapping, default_host="127.0.0.1")
    listen_family = socket.AF_INET6 if ":" in bind_host else socket.AF_INET
    connect_family = socket.AF_INET6 if ":" in connect_host else socket.AF_INET
    sock = socket.socket(listen_family, socket.SOCK_DGRAM)
    sock.bind(sockaddr(bind_host, bind_port, listen_family))
    print(f"[green]UDP forward[/green] {bind_host}:{bind_port} -> {connect_host}:{connect_port}")

    sessions: dict[str, tuple[socket.socket, float]] = {}
    lock = threading.Lock()

    while True:
        data, addr = sock.recvfrom(65536)
        now = time.time()
        key = f"{addr[0]}:{addr[1]}"

        with lock:
            for k, (s, last) in list(sessions.items()):
                if now - last > udp_timeout:
                    s.close()
                    sessions.pop(k, None)

            if key not in sessions:
                out = socket.socket(connect_family, socket.SOCK_DGRAM)
                out.connect(sockaddr(connect_host, connect_port, connect_family))
                sessions[key] = (out, now)

                def reply_loop(out_sock: socket.socket, target: tuple[str, int]) -> None:
                    while True:
                        try:
                            packet = out_sock.recv(65536)
                        except OSError:
                            return
                        try:
                            sock.sendto(packet, target)
                        except OSError:
                            return

                thread = threading.Thread(target=reply_loop, args=(sessions[key][0], addr), daemon=True)
                thread.start()

            out_sock, _ = sessions[key]
            sessions[key] = (out_sock, now)
            out_sock.send(data)


def attempt_switch_to_used_port(
    desired_port: int | None,
    ip: str,
    distro: str,
    open_ui: bool = True,
) -> int | None:
    if open_ui:
        print("[bold]Opening 9proxy Today list UI[/bold]")
        print("Pick a USED proxy there, then close the UI to continue.")
        run_cmd(["9proxy", "proxy", "--today", "--ui"], capture=False)

    _, ports = fetch_port_status()
    used = sorted([p for p, info in ports.items() if info["status"].lower() == "used"])
    if not used:
        print("[red]No used ports found.[/red]")
        return None

    if len(used) == 1 and (desired_port is None or desired_port == used[0]):
        info = ports.get(used[0])
        if not port_is_online(info):
            print("[yellow]Only one used port and it is offline. Nothing to switch.[/yellow]")
            return None
        print("[green]Only one used port available; staying on it.[/green]")
        return used[0]

    online_used = [p for p in used if port_is_online(ports.get(p))]
    default_port = desired_port or (online_used[0] if online_used else used[0])

    table = Table(title="Used ports (Today list)")
    table.add_column("Port")
    table.add_column("Online")
    table.add_column("City")
    table.add_column("Public IP")
    for p in used:
        info = ports.get(p, {})
        table.add_row(
            str(p),
            "online" if port_is_online(info) else "offline",
            info.get("city", ""),
            info.get("public_ip", ""),
        )
    console.print(table)
    port = int(Prompt.ask("Choose port to use", default=str(default_port)))

    info = ports.get(port)
    if not info or info["status"].lower() != "used":
        print("[red]That port is not in the USED list. Aborting.[/red]")
        return None

    if not port_is_online(info):
        print("[yellow]Selected port is offline. It may not work.[/yellow]")
        if not Confirm.ask("Use it anyway?", default=False):
            return None

    cfg_path = redsocks_config_path(distro)
    current_port = current_relay_port(cfg_path)
    if current_port == port:
        print(f"[green]Already using port {port}. No changes needed.[/green]")
        return port

    status = update_redsocks_relay(cfg_path, ip, port)
    if status == "updated":
        svc_name = redsocks_service_name(distro)
        run_cmd(["systemctl", "restart", svc_name], sudo=True, capture=False)
        print(f"[green]Switched relay to {ip}:{port} and restarted {svc_name}.[/green]")
    elif status == "missing":
        print("[yellow]Redsocks config not found. Skipping relay update.[/yellow]")
    else:
        print("[yellow]Redsocks relay already set; no change.[/yellow]")

    return port


def resolve_log_dir(primary: Path, legacy: Path | None = None) -> Path:
    fallback = Path.home() / "Downloads"
    for candidate in (primary, legacy, fallback):
        if candidate and candidate.exists() and candidate.is_dir():
            return candidate
    for candidate in (primary, fallback):
        if not candidate:
            continue
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            if candidate.is_dir():
                return candidate
        except OSError:
            continue
    return fallback


def safe_output_path(path: Path) -> Path:
    parent = path.parent
    if parent.exists() and not parent.is_dir():
        fallback = resolve_log_dir(Path.home() / "Downloads")
        return fallback / path.name
    parent.mkdir(parents=True, exist_ok=True)
    return path


def write_setup_log(lines: list[str], output_path: Path | None) -> Path:
    if output_path is None:
        base = Path.home() / ".local" / "share" / APP_ID
        legacy = Path.home() / ".local" / "share" / LEGACY_APP_ID
        base_dir = resolve_log_dir(base, legacy)
        output_path = base_dir / "LAST-SETUP.md"
    output_path = safe_output_path(output_path)
    content = "\n".join(lines) + "\n"
    output_path.write_text(content)
    return output_path


def diagnostics_path(output_path: Path | None) -> Path:
    if output_path is not None:
        return output_path
    base = Path.home() / ".local" / "share" / APP_ID
    legacy = Path.home() / ".local" / "share" / LEGACY_APP_ID
    base_dir = resolve_log_dir(base, legacy)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    return base_dir / f"diagnostics-{ts}.txt"


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        try:
            menu()
        except KeyboardInterrupt:
            print("\n[bold yellow]Exiting.[/bold yellow]")
            raise typer.Exit(0)


def menu() -> None:
    show_dashboard()
    print()
    console.print(
        Panel(
            "[bold]1[/bold] Dashboard (refresh)     [bold]5[/bold] Modes & security       [bold]9[/bold]  Diagnostics\n"
            "[bold]2[/bold] Quick setup             [bold]6[/bold] Local proxies          [bold]10[/bold] Profiles\n"
            "[bold]3[/bold] Fix / switch            [bold]7[/bold] Share & allowlist\n"
            "[bold]4[/bold] Auto-heal               [bold]8[/bold] Undo / cleanup          [bold]0[/bold]  Exit",
            title="[bold cyan]Menu[/bold cyan]",
            border_style="cyan",
            padding=(0, 2),
        )
    )

    choice = Prompt.ask("Enter number", default="1")
    if choice == "1":
        show_dashboard()
    elif choice == "2":
        wizard()
    elif choice == "3":
        fix_switch_submenu()
    elif choice == "4":
        auto_heal_submenu()
    elif choice == "5":
        modes_submenu()
    elif choice == "6":
        local_proxies_submenu()
    elif choice == "7":
        share_allowlist_submenu()
    elif choice == "8":
        undo()
    elif choice == "9":
        diagnostics_submenu()
    elif choice == "10":
        profile_menu()
    else:
        raise typer.Exit(0)


def fix_switch_submenu() -> None:
    """Sub-menu for fix and port switching options."""
    console.print(
        Panel(
            "[bold]1[/bold] Fix offline (no new IP)\n"
            "[bold]2[/bold] Switch to another USED port (Today list)\n"
            "[bold]0[/bold] Back",
            title="[bold]Fix / Switch[/bold]",
            border_style="yellow",
        )
    )
    choice = Prompt.ask("Choice", default="0")
    if choice == "1":
        doctor()
    elif choice == "2":
        switch_port()


def auto_heal_submenu() -> None:
    """Sub-menu for auto-heal service management."""
    console.print(
        Panel(
            "[bold]1[/bold] Enable auto-heal (restart on failure)\n"
            "[bold]2[/bold] Disable auto-heal\n"
            "[bold]0[/bold] Back",
            title="[bold]Auto-heal[/bold]",
            border_style="green",
        )
    )
    choice = Prompt.ask("Choice", default="0")
    if choice == "1":
        enable_auto_heal()
    elif choice == "2":
        disable_auto_heal()


def modes_submenu() -> None:
    """Sub-menu for mode toggles and security settings."""
    console.print(
        Panel(
            "[bold]1[/bold] Enable TCP redirect (fix missing redirect)\n"
            "[bold]2[/bold] Stable mode (recommended for phone)\n"
            "[bold]3[/bold] No-leak strict mode (toggle)\n"
            "[bold]0[/bold] Back",
            title="[bold]Modes & Security[/bold]",
            border_style="magenta",
        )
    )
    choice = Prompt.ask("Choice", default="0")
    if choice == "1":
        enable_redirect()
    elif choice == "2":
        stable_mode()
    elif choice == "3":
        toggle_strict_mode()


def local_proxies_submenu() -> None:
    """Sub-menu for local proxy services."""
    console.print(
        Panel(
            "[bold]1[/bold] Local SOCKS forwarder (desktop)\n"
            "[bold]2[/bold] Port forwarding (TCP/UDP)\n"
            "[bold]3[/bold] HTTP proxy + PAC\n"
            "[bold]0[/bold] Back",
            title="[bold]Local Proxies[/bold]",
            border_style="blue",
        )
    )
    choice = Prompt.ask("Choice", default="0")
    if choice == "1":
        local_socks_menu()
    elif choice == "2":
        forward_menu()
    elif choice == "3":
        http_proxy_menu()


def share_allowlist_submenu() -> None:
    """Sub-menu for sharing and access control."""
    console.print(
        Panel(
            "[bold]1[/bold] Share (QR + info)\n"
            "[bold]2[/bold] Allowlist (tailnet IPs)\n"
            "[bold]0[/bold] Back",
            title="[bold]Share & Allowlist[/bold]",
            border_style="cyan",
        )
    )
    choice = Prompt.ask("Choice", default="0")
    if choice == "1":
        share_menu()
    elif choice == "2":
        allowlist_menu()


def diagnostics_submenu() -> None:
    """Sub-menu for diagnostics and testing."""
    console.print(
        Panel(
            "[bold]1[/bold] Self-test (quick health check)\n"
            "[bold]2[/bold] Diagnostics (full logs)\n"
            "[bold]0[/bold] Back",
            title="[bold]Diagnostics[/bold]",
            border_style="yellow",
        )
    )
    choice = Prompt.ask("Choice", default="0")
    if choice == "1":
        self_test()
    elif choice == "2":
        diagnostics_menu()


def prompt_int(label: str, default: int) -> int:
    while True:
        value = Prompt.ask(label, default=str(default))
        try:
            return int(value)
        except ValueError:
            print("[red]Please enter a number.[/red]")


def local_socks_menu() -> None:
    ip = tailscale_ip()
    default_upstream = f"{ip}:60000" if ip else "127.0.0.1:60000"
    listen = Prompt.ask("Local listen address", default="127.0.0.1:1080")
    upstream = Prompt.ask("Upstream SOCKS (tailscale IP:port)", default=default_upstream)
    allow_udp = Confirm.ask("Enable UDP associate?", default=True)
    tcp_timeout = prompt_int("TCP timeout (sec)", 1100)
    udp_timeout = prompt_int("UDP timeout (sec)", 330)
    if Confirm.ask("Run in background (systemd)?", default=True):
        install_local_socks_service(listen, upstream, allow_udp, tcp_timeout, udp_timeout)
    else:
        serve_local_socks(listen, upstream, allow_udp, tcp_timeout, udp_timeout)


def forward_menu() -> None:
    tcp_rules: list[str] = []
    udp_rules: list[str] = []

    print("TCP rule syntax: bind=connect or bind=TLS=connect (TLS uses Tailscale cert)")
    while True:
        rule = Prompt.ask("Add TCP rule (blank to skip)", default="")
        if not rule.strip():
            break
        tcp_rules.append(rule.strip())
        if not Confirm.ask("Add another TCP rule?", default=False):
            break

    print("UDP rule syntax: bind=connect")
    while True:
        rule = Prompt.ask("Add UDP rule (blank to skip)", default="")
        if not rule.strip():
            break
        udp_rules.append(rule.strip())
        if not Confirm.ask("Add another UDP rule?", default=False):
            break

    if not tcp_rules and not udp_rules:
        print("[yellow]No rules provided.[/yellow]")
        return

    tcp_timeout = prompt_int("TCP timeout (sec)", 1100)
    udp_timeout = prompt_int("UDP timeout (sec)", 330)

    if Confirm.ask("Run in background (systemd)?", default=True):
        install_forward_service(tcp_rules, udp_rules, tcp_timeout, udp_timeout)
    else:
        run_forwarders(tcp_rules, udp_rules, tcp_timeout, udp_timeout)


def http_proxy_menu() -> None:
    ip = tailscale_ip()
    default_upstream = f"{ip}:60000" if ip else "127.0.0.1:60000"
    listen = Prompt.ask("HTTP listen address", default="127.0.0.1:8080")
    upstream = Prompt.ask("Upstream SOCKS (tailscale IP:port)", default=default_upstream)
    tcp_timeout = prompt_int("TCP timeout (sec)", 1100)
    if Confirm.ask("Run in background (systemd)?", default=True):
        install_http_service(listen, upstream, tcp_timeout)
    else:
        serve_http_proxy(listen, upstream, tcp_timeout)
    if Confirm.ask("Generate PAC file now?", default=True):
        pac_path = generate_pac_file(listen)
        print(f"[green]PAC saved to {pac_path}[/green]")


def share_menu() -> None:
    ip = tailscale_ip()
    port = Prompt.ask("Proxy port", default="60000")
    if not ip:
        print("[red]Tailscale IP not found.[/red]")
        return
    share_info(ip, int(port))


def allowlist_menu() -> None:
    ip = tailscale_ip()
    if not ip:
        print("[red]Tailscale IP not found.[/red]")
        return
    port = prompt_int("Proxy port to protect", 60000)
    if Confirm.ask("Disable allowlist and remove rules?", default=False):
        allowlist_off()
        return
    allowed_raw = Prompt.ask("Allowed tailnet IPs (comma-separated)", default=ip)
    allowed = [a.strip() for a in allowed_raw.split(",") if a.strip()]
    if not allowed:
        print("[red]No IPs provided.[/red]")
        return
    allowlist_on(port, allowed)


def ok_label(value: bool) -> str:
    return "[green]ok[/green]" if value else "[red]missing[/red]"


def state_label(value: bool, on: str = "on", off: str = "off") -> str:
    return f"[green]{on}[/green]" if value else f"[red]{off}[/red]"


def value_label(value: str | None, fallback: str = "unknown") -> str:
    if value:
        return value
    return f"[yellow]{fallback}[/yellow]"


def online_label(value: str | None) -> str:
    if not value:
        return "[yellow]unknown[/yellow]"
    lowered = value.strip().lower()
    if lowered == "online":
        return "[green]online[/green]"
    if lowered == "offline":
        return "[red]offline[/red]"
    return f"[yellow]{value}[/yellow]"


def port_status_label(value: str | None) -> str:
    if not value:
        return "[yellow]unknown[/yellow]"
    lowered = value.strip().lower()
    if lowered == "used":
        return "[green]used[/green]"
    if lowered == "remaining":
        return "[yellow]remaining[/yellow]"
    return value


def backend_label(value: str | None, installed: bool) -> str:
    if not installed:
        return "[red]missing[/red]"
    if not value:
        return "[yellow]unknown[/yellow]"
    lowered = value.strip().lower()
    if lowered == "running":
        return f"[green]{value}[/green]"
    return f"[yellow]{value}[/yellow]"


def kv_table(rows: list[tuple[str, str]], key_width: int = 14) -> Table:
    table = Table.grid(padding=(0, 1))
    table.add_column(style="bold cyan", no_wrap=True, width=key_width)
    table.add_column()
    for key, value in rows:
        table.add_row(key, value)
    return table


def kv_table_2col(rows: list[tuple[str, str]]) -> Table:
    """Two-column key-value layout for compact display."""
    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold cyan", no_wrap=True, width=14)
    table.add_column(width=12)
    table.add_column(style="bold cyan", no_wrap=True, width=14)
    table.add_column(width=12)
    # Pair up rows
    for i in range(0, len(rows), 2):
        if i + 1 < len(rows):
            table.add_row(rows[i][0], rows[i][1], rows[i + 1][0], rows[i + 1][1])
        else:
            table.add_row(rows[i][0], rows[i][1], "", "")
    return table


def show_dashboard() -> None:
    if console.is_terminal:
        console.clear()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    distro = detect_distro()
    ts_installed = cmd_exists("tailscale")
    proxy_installed = cmd_exists("9proxy")
    redsocks_installed = cmd_exists("redsocks") or cmd_exists("redsocks2")

    ts_data = tailscale_status_json() if ts_installed else {}
    self_node = ts_data.get("Self", {})
    if not isinstance(self_node, dict):
        self_node = {}

    host = self_node.get("HostName") or ""
    dns = self_node.get("DNSName") or ""
    dns = dns.rstrip(".") if dns else ""
    ip = tailscale_ip() if ts_installed else None
    if not ip:
        ips = self_node.get("TailscaleIPs", []) or []
        if isinstance(ips, list):
            ip = next((addr for addr in ips if "." in addr), None)
    backend_state = ts_data.get("BackendState", "") if ts_installed else ""
    allowed = self_node.get("AllowedIPs", []) if isinstance(self_node, dict) else []
    exit_advertised = None
    if isinstance(allowed, list):
        exit_advertised = "0.0.0.0/0" in allowed or "::/0" in allowed

    relay_port = current_relay_port(redsocks_config_path(distro))
    ports: dict[int, dict[str, str]] = {}
    if proxy_installed:
        _, ports = fetch_port_status()
    port_info = ports.get(relay_port) if relay_port else None
    port_status = port_info.get("status") if port_info else None
    port_online = port_info.get("online") if port_info else None
    public_ip = port_info.get("public_ip") if port_info else None
    city = port_info.get("city") if port_info else None

    logged_in = is_9proxy_logged_in() if proxy_installed else None

    auto_heal_active = systemd_is_active(AUTO_HEAL_TIMER) or systemd_is_active(LEGACY_AUTO_HEAL_TIMER)
    auto_heal_label = state_label(auto_heal_active)
    if systemd_is_active(LEGACY_AUTO_HEAL_TIMER) and not systemd_is_active(AUTO_HEAL_TIMER):
        auto_heal_label = f"{auto_heal_label} (legacy)"

    redsocks_service = redsocks_service_name(distro)
    redsocks_active = systemd_is_active(redsocks_service)
    tcp_redirect_active = systemd_is_active("ts-9proxy-redirect.service")
    udp_tproxy_active = systemd_is_active("ts-9proxy-udp-tproxy.service")
    udp_block_active = systemd_is_active("ts-udp-block.service")
    no_leak_active = systemd_is_active("ts-no-leak.service")

    nonlocal_bind = None
    nonlocal_path = Path("/proc/sys/net/ipv4/ip_nonlocal_bind")
    if nonlocal_path.exists():
        nonlocal_bind = nonlocal_path.read_text().strip() == "1"

    nameservers, resolv_target = read_resolv_conf()
    dns_enabled = tailscale_dns_enabled() if ts_installed else None
    dns_mode = "system"
    stub_ns = any(ns in {"127.0.0.53", "127.0.0.1"} for ns in nameservers)
    stub_target = resolv_target and "stub-resolv.conf" in resolv_target
    if "100.100.100.100" in nameservers:
        dns_mode = "tailscale"
    elif stub_ns or stub_target:
        dns_mode = "tailscale (stub)" if dns_enabled else "systemd stub"
    elif dns_enabled:
        dns_mode = "tailscale (split)"

    if nameservers:
        dns_label = f"{dns_mode} ({', '.join(nameservers[:2])})"
        if len(nameservers) > 2:
            dns_label += " +"
    else:
        dns_label = f"{dns_mode} (none)"
    if resolv_target:
        dns_label = f"{dns_label} -> {Path(resolv_target).name}"

    system_rows = [
        ("Distro", distro),
        ("tailscale", ok_label(ts_installed)),
        ("9proxy", ok_label(proxy_installed)),
        ("redsocks", ok_label(redsocks_installed)),
    ]
    ts_rows = [
        ("State", backend_label(backend_state, ts_installed)),
        ("Host", value_label(host, "unknown")),
        ("DNS", value_label(dns, "unknown")),
        ("Tailnet IP", value_label(ip, "unknown")),
    ]
    if exit_advertised is not None:
        ts_rows.append(("Exit node", state_label(exit_advertised)))

    login_label = value_label(None)
    if logged_in is not None:
        login_label = state_label(logged_in, "yes", "no")

    port_display = str(relay_port) if relay_port else "not set"
    status_display = value_label(None)
    if port_info:
        status_display = f"{port_status_label(port_status)} / {online_label(port_online)}"

    proxy_path_ok = bool(relay_port) and port_is_online(port_info) and redsocks_active and tcp_redirect_active
    proxy_path_label = "[green]ok[/green]" if proxy_path_ok else "[red]needs attention[/red]"

    if udp_tproxy_active:
        udp_label = "[green]tproxy on[/green]"
        if nonlocal_bind is False:
            udp_label = "[yellow]tproxy on (sysctl)[/yellow]"
    elif udp_block_active:
        udp_label = "[yellow]blocked[/yellow]"
    else:
        udp_label = "[red]off[/red]"

    summary_rows = [
        ("Proxy path", proxy_path_label),
        ("Exit node", state_label(exit_advertised) if exit_advertised is not None else "[yellow]unknown[/yellow]"),
        ("DNS mode", dns_label),
        ("Auto-heal", auto_heal_label),
        ("No-leak", state_label(no_leak_active)),
        ("UDP mode", udp_label),
    ]
    if nonlocal_bind is not None:
        summary_rows.append(("ip_nonlocal_bind", state_label(nonlocal_bind, "1", "0")))

    proxy_rows = [
        ("Logged in", login_label),
        ("Relay port", port_display),
        ("Port state", status_display),
        ("Public IP", value_label(public_ip, "unknown")),
        ("City", value_label(city, "unknown")),
    ]

    services_rows = [
        ("Auto-heal", auto_heal_label),
        ("Redsocks", state_label(redsocks_active)),
        ("TCP redirect", state_label(tcp_redirect_active)),
        ("UDP TPROXY", state_label(udp_tproxy_active)),
        ("UDP block", state_label(udp_block_active)),
        ("No-leak", state_label(no_leak_active)),
        ("Local SOCKS", state_label(systemd_is_active(LOCAL_SOCKS_SERVICE))),
        ("Forward", state_label(systemd_is_active(FORWARD_SERVICE))),
        ("HTTP proxy", state_label(systemd_is_active(HTTP_PROXY_SERVICE))),
        ("Allowlist", state_label(systemd_is_active(ALLOWLIST_SERVICE))),
    ]

    notes: list[str] = []
    if not ts_installed:
        notes.append("Tailscale is not installed.")
    if not proxy_installed:
        notes.append("9proxy is not installed.")
    if proxy_installed and relay_port is None:
        notes.append("Relay port is not set.")
    if proxy_installed and relay_port and not port_is_online(port_info):
        notes.append("Proxy port is offline.")
    if not redsocks_active:
        notes.append("Redsocks is not running.")
    if exit_advertised and not tcp_redirect_active:
        notes.append("[bold]TCP redirect is off (exit node will not proxy).[/bold]")
    if udp_tproxy_active and nonlocal_bind is False:
        notes.append("UDP tproxy needs net.ipv4.ip_nonlocal_bind=1.")
    if no_leak_active and not proxy_path_ok:
        notes.append("No-leak is on: traffic will drop until proxy path is ok.")

    # Action hints based on state
    actions: list[str] = []
    if exit_advertised and not tcp_redirect_active:
        actions.append("[yellow]Run option 2 (Quick setup) to enable TCP redirect[/yellow]")
    if not redsocks_active:
        actions.append(f"[yellow]systemctl start {redsocks_service}[/yellow]")

    notes_text = "[green]All checks look good.[/green]" if not notes else "\n".join(f"- {item}" for item in notes)
    if actions:
        notes_text += "\n\n[bold]Suggested:[/bold]\n" + "\n".join(f"  {a}" for a in actions)

    # Build full-screen layout
    term_width = console.width or 120

    header = Panel(
        f"[bold cyan]{APP_TITLE}[/bold cyan]\n[dim]Dashboard[/dim]",
        subtitle=f"Updated {now}",
        border_style="cyan",
    )
    console.print(header)
    console.print(
        Columns(
            [
                Panel(kv_table(summary_rows), title="Summary", border_style="bright_blue"),
                Panel(notes_text, title="Status / Notes", border_style="yellow"),
            ],
            expand=True,
            equal=True,
        )
    )
    console.print(
        Columns(
            [
                Panel(kv_table(system_rows), title="System", border_style="cyan"),
                Panel(kv_table(ts_rows), title="Tailscale", border_style="green"),
                Panel(kv_table(proxy_rows), title="9proxy", border_style="magenta"),
            ],
            expand=True,
            equal=True,
        )
    )
    # Services in 2-column compact layout
    console.print(Panel(kv_table_2col(services_rows), title="Services + Modes", border_style="blue"))


@app.command("dashboard")
def dashboard() -> None:
    show_dashboard()


@app.command()
def status() -> None:
    show_dashboard()


def run_diagnostics(
    save: bool,
    output: Path | None,
    sudo: bool,
) -> None:
    print(Panel("Diagnostics", subtitle="Full setup logs"))
    log_fp: TextIO | None = None
    output_path: Path | None = None

    if save:
        output_path = safe_output_path(diagnostics_path(output))
        log_fp = output_path.open("w", encoding="utf-8")
        log_line(log_fp, f"{APP_TITLE} diagnostics log")
        log_line(log_fp, f"Created: {datetime.now().isoformat(sep=' ', timespec='seconds')}")
        print(f"[dim]Saving log to {output_path}[/dim]")

    try:
        print_section("timestamp", log_fp)
        now = datetime.now().isoformat(sep=" ", timespec="seconds")
        print(now)
        log_line(log_fp, now)

        if cmd_exists("tailscale"):
            print_section("tailscale status json", log_fp)
            run_stream(["tailscale", "status", "--json"], log_fp)

            print_section("tailscale dns status", log_fp)
            run_stream(["tailscale", "dns", "status"], log_fp)

            print_section("tailscale netcheck", log_fp)
            run_stream(["tailscale", "netcheck"], log_fp)

            print_section("tailscale exit/dns flags", log_fp)
            data = tailscale_status_json()
            self_node = data.get("Self", {}) if isinstance(data, dict) else {}
            if not isinstance(self_node, dict):
                self_node = {}
            allowed = self_node.get("AllowedIPs", []) or []
            tailnet = data.get("CurrentTailnet", {}) if isinstance(data, dict) else {}
            lines = [
                f"ExitNode: {self_node.get('ExitNode')}",
                f"ExitNodeOption: {self_node.get('ExitNodeOption')}",
                f"AllowedIPs: {', '.join(allowed) if allowed else '(none)'}",
                f"MagicDNSSuffix: {data.get('MagicDNSSuffix')}",
                f"MagicDNS enabled: {tailnet.get('MagicDNSEnabled')}",
            ]
            for line in lines:
                print(line)
                log_line(log_fp, line)
        else:
            print_section("tailscale", log_fp)
            print("(tailscale not installed)")
            log_line(log_fp, "(tailscale not installed)")

        if cmd_exists("9proxy"):
            print_section("9proxy status", log_fp)
            run_stream(["9proxy", "setting", "--display"], log_fp)
            run_stream(["9proxy", "port", "--status"], log_fp)
        else:
            print_section("9proxy", log_fp)
            print("(9proxy not installed)")
            log_line(log_fp, "(9proxy not installed)")

        print_section("redsocks config", log_fp)
        cfg_path = redsocks_config_path(detect_distro())
        if cfg_path.exists():
            content = cfg_path.read_text()
            sys.stdout.write(content)
            if not content.endswith("\n"):
                sys.stdout.write("\n")
            log_block(log_fp, content)
        else:
            msg = f"(not found: {cfg_path})"
            print(msg)
            log_line(log_fp, msg)

        print_section("systemd units", log_fp)
        run_stream(
            [
                "systemctl",
                "is-active",
                "redsocks2.service",
                "redsocks.service",
                "ts-9proxy-redirect.service",
                "ts-9proxy-udp-tproxy.service",
                "ts-udp-block.service",
                "ts-no-leak.service",
                "9proxyd.service",
                "9proxy.service",
            ],
            log_fp,
        )

        print_section("systemd status redsocks", log_fp)
        run_stream(["systemctl", "status", "--no-pager", "-l", "redsocks2.service"], log_fp)
        run_stream(["systemctl", "status", "--no-pager", "-l", "redsocks.service"], log_fp)

        print_section("systemd status tproxy", log_fp)
        run_stream(["systemctl", "status", "--no-pager", "-l", "ts-9proxy-udp-tproxy.service"], log_fp)

        print_section("systemd status redirect", log_fp)
        run_stream(["systemctl", "status", "--no-pager", "-l", "ts-9proxy-redirect.service"], log_fp)

        print_section("systemd status no-leak", log_fp)
        run_stream(["systemctl", "status", "--no-pager", "-l", "ts-no-leak.service"], log_fp)

        print_section("iptables nat/mangle/filter (tailscale)", log_fp)
        if sudo:
            run_stream(maybe_sudo(["iptables", "-t", "nat", "-S"], sudo), log_fp)
            run_stream(maybe_sudo(["iptables", "-t", "mangle", "-S"], sudo), log_fp)
            run_stream(maybe_sudo(["iptables", "-t", "filter", "-S"], sudo), log_fp)
        else:
            msg = "(skipped: re-run with --sudo for iptables)"
            print(msg)
            log_line(log_fp, msg)

        print_section("ip rules + routes (tproxy)", log_fp)
        if sudo:
            run_stream(maybe_sudo(["ip", "rule", "show"], sudo), log_fp)
            run_stream(maybe_sudo(["ip", "route", "show", "table", "100"], sudo), log_fp)
        else:
            msg = "(skipped: re-run with --sudo for ip rules/routes)"
            print(msg)
            log_line(log_fp, msg)

        print_section("sysctl", log_fp)
        run_stream(["sysctl", "net.ipv4.ip_nonlocal_bind", "net.ipv4.ip_forward"], log_fp)

        print_section("resolv.conf", log_fp)
        resolv = Path("/etc/resolv.conf")
        if resolv.exists():
            content = resolv.read_text()
            sys.stdout.write(content)
            if not content.endswith("\n"):
                sys.stdout.write("\n")
            log_block(log_fp, content)
        else:
            msg = "(not found: /etc/resolv.conf)"
            print(msg)
            log_line(log_fp, msg)

        print_section("last setup log", log_fp)
        base = Path.home() / ".local" / "share" / APP_ID
        legacy = Path.home() / ".local" / "share" / LEGACY_APP_ID
        for path in (base, legacy):
            if path.exists():
                if path.is_dir():
                    print(str(path))
                    log_line(log_fp, str(path))
                    for item in sorted(path.iterdir()):
                        entry = f"- {item.name}"
                        print(entry)
                        log_line(log_fp, entry)
                else:
                    msg = f"{path} (not a directory)"
                    print(msg)
                    log_line(log_fp, msg)
        log_candidate = None
        if base.is_dir():
            candidate = base / "LAST-SETUP.md"
            if candidate.exists():
                log_candidate = candidate
        if log_candidate is None and legacy.is_dir():
            candidate = legacy / "LAST-SETUP.md"
            if candidate.exists():
                log_candidate = candidate
        if log_candidate and log_candidate.exists():
            content = log_candidate.read_text()
            sys.stdout.write(content)
            if not content.endswith("\n"):
                sys.stdout.write("\n")
            log_block(log_fp, content)
        else:
            msg = "(no LAST-SETUP.md found)"
            print(msg)
            log_line(log_fp, msg)
    finally:
        if log_fp:
            log_fp.close()
        if save and output_path:
            print(f"[green]Saved diagnostics to {output_path}[/green]")


def diagnostics_menu() -> None:
    save = Confirm.ask("Save a log file in Downloads?", default=True)
    output: Path | None = None
    if save:
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        output = Path.home() / "Downloads" / f"{APP_ID}-diagnostics-{ts}.txt"
    sudo = Confirm.ask("Include sudo checks (iptables/rules)?", default=True)
    run_diagnostics(save=save, output=output, sudo=sudo)


@app.command()
def diagnostics(
    save: bool = True,
    output: Path | None = None,
    sudo: bool = False,
) -> None:
    run_diagnostics(save=save, output=output, sudo=sudo)


@app.command()
def doctor(
    port: int = 60000,
    country: str = "US",
    no_prompt: bool = False,
    allow_refresh: bool = False,
    allow_switch: bool = False,
) -> None:
    print(Panel(f"{APP_TITLE} doctor", subtitle="No new IP without consent"))
    _, ports = fetch_port_status()
    info = ports.get(port)
    if not info:
        print(f"[red]Port {port} not found in 9proxy status output.[/red]")
        raise typer.Exit(1)

    online = "online" if port_is_online(info) else "offline"
    print(f"Port {port}: {online} (status: {info.get('status', 'unknown')})")

    if port_is_online(info):
        print("[green]Proxy looks healthy.[/green]")
        return

    if no_prompt:
        if restart_9proxy_daemon():
            _, ports = fetch_port_status()
            info = ports.get(port)
            if port_is_online(info):
                print("[green]Port is back online after restart.[/green]")
                return
        print("[yellow]Restart did not bring it online.[/yellow]")
        if allow_switch:
            distro = detect_distro()
            ip = tailscale_ip() or "127.0.0.1"
            new_port = attempt_switch_to_used_port(None, ip, distro, open_ui=False)
            if new_port:
                print(f"[green]Now using port {new_port}.[/green]")
                return
    else:
        if Confirm.ask("Try restarting 9proxy daemon? (no new IP)", default=True):
            if restart_9proxy_daemon():
                _, ports = fetch_port_status()
                info = ports.get(port)
                if port_is_online(info):
                    print("[green]Port is back online after restart.[/green]")
                    return
            print("[yellow]Restart did not bring it online.[/yellow]")
        if Confirm.ask("Switch to another USED port from Today's list?", default=False):
            distro = detect_distro()
            ip = tailscale_ip() or "127.0.0.1"
            new_port = attempt_switch_to_used_port(None, ip, distro, open_ui=True)
            if new_port:
                print(f"[green]Now using port {new_port}.[/green]")
                return

    if not allow_refresh:
        print("[yellow]No refresh performed (allow_refresh is false).[/yellow]")
        return

    if no_prompt or Confirm.ask("Refresh this port now? (consumes a new IP)", default=False):
        res = run_cmd(["9proxy", "proxy", "-c", country, "-p", str(port)], capture=True)
        if res.returncode == 0:
            print("[green]Port refreshed.[/green]")
        else:
            print("[red]Refresh failed.[/red]")
    else:
        print("[yellow]No refresh performed. Proxy will remain offline until it recovers.[/yellow]")


@app.command()
def watch(
    port: int = 60000,
    interval: int = 30,
    country: str = "US",
    no_prompt: bool = False,
    allow_refresh: bool = False,
    allow_switch: bool = False,
) -> None:
    print(Panel(f"Watching port {port}", subtitle=f"interval: {interval}s"))
    last_state: str | None = None

    while True:
        _, ports = fetch_port_status()
        info = ports.get(port)
        if not info:
            print(f"[red]Port {port} not found.[/red]")
            time.sleep(interval)
            continue

        state = "online" if port_is_online(info) else "offline"
        if state != last_state:
            print(f"Port {port}: {state} (status: {info.get('status', 'unknown')})")
            last_state = state

        if state == "offline":
            if no_prompt:
                restart_9proxy_daemon()
                time.sleep(2)
                _, ports = fetch_port_status()
                info = ports.get(port)
                if port_is_online(info):
                    last_state = "online"
                    print("[green]Port back online after restart.[/green]")
                    time.sleep(interval)
                    continue
                if allow_switch:
                    distro = detect_distro()
                    ip = tailscale_ip() or "127.0.0.1"
                    new_port = attempt_switch_to_used_port(None, ip, distro, open_ui=False)
                    if new_port:
                        port = new_port
                        last_state = "online"
                        print(f"[green]Now using port {new_port}.[/green]")
                        time.sleep(interval)
                        continue
            else:
                if Confirm.ask("Try restarting 9proxy daemon? (no new IP)", default=True):
                    restart_9proxy_daemon()
                    time.sleep(2)
                    _, ports = fetch_port_status()
                    info = ports.get(port)
                    if port_is_online(info):
                        last_state = "online"
                        print("[green]Port back online after restart.[/green]")
                        time.sleep(interval)
                        continue
                if Confirm.ask("Switch to another USED port from Today's list?", default=False):
                    distro = detect_distro()
                    ip = tailscale_ip() or "127.0.0.1"
                    new_port = attempt_switch_to_used_port(None, ip, distro, open_ui=True)
                    if new_port:
                        port = new_port
                        last_state = "online"
                        print(f"[green]Now using port {new_port}.[/green]")
                        time.sleep(interval)
                        continue

            if allow_refresh:
                if no_prompt or Confirm.ask("Refresh this port now? (consumes a new IP)", default=False):
                    res = run_cmd(["9proxy", "proxy", "-c", country, "-p", str(port)], capture=True)
                    if res.returncode == 0:
                        print("[green]Port refreshed.[/green]")
                    else:
                        print("[red]Refresh failed.[/red]")

        time.sleep(interval)


@app.command("switch-port")
def switch_port(
    port: int | None = None,
    open_ui: bool = True,
) -> None:
    distro = detect_distro()
    ip = tailscale_ip()
    if not ip:
        print("[red]Tailscale IP not found. Run 'sudo tailscale up' first.[/red]")
        raise typer.Exit(1)

    new_port = attempt_switch_to_used_port(port, ip, distro, open_ui=open_ui)
    if not new_port:
        raise typer.Exit(1)

    print("\n[bold]Share instructions (tailnet-only)[/bold]")
    print(f"Host: {ip}")
    print(f"Port: {new_port}")
    print("Type: SOCKS5 (HTTP also works in some apps)")


@app.command("auto-heal-on")
def enable_auto_heal(
    port: int = 60000,
    interval_minutes: int = 2,
) -> None:
    print(Panel("Enable auto-heal", subtitle="Restart 9proxy only, no new IPs"))
    remove_auto_heal_units(legacy_only=True)
    python_exec = sys.executable
    service = textwrap.dedent(
        f"""
        [Unit]
        Description={APP_TITLE} doctor (no refresh)
        After=network-online.target
        Wants=network-online.target

        [Service]
        Type=oneshot
        ExecStart={shlex.quote(python_exec)} -m proxy_tailscale.cli doctor --port {port} --no-prompt
        """
    ).lstrip()
    timer = textwrap.dedent(
        f"""
        [Unit]
        Description=Run {APP_ID} doctor periodically

        [Timer]
        OnBootSec=1min
        OnUnitActiveSec={interval_minutes}min
        AccuracySec=30s
        Persistent=true

        [Install]
        WantedBy=timers.target
        """
    ).lstrip()

    write_file(Path(f"/etc/systemd/system/{AUTO_HEAL_SERVICE}"), service)
    write_file(Path(f"/etc/systemd/system/{AUTO_HEAL_TIMER}"), timer)
    run_cmd(["systemctl", "daemon-reload"], sudo=True, capture=False)
    run_cmd(["systemctl", "enable", "--now", AUTO_HEAL_TIMER], sudo=True, capture=False)
    print("[green]Auto-heal enabled.[/green]")


def remove_auto_heal_units(legacy_only: bool) -> None:
    targets = [LEGACY_AUTO_HEAL_TIMER, LEGACY_AUTO_HEAL_SERVICE]
    if not legacy_only:
        targets.extend([AUTO_HEAL_TIMER, AUTO_HEAL_SERVICE])
    for unit in targets:
        unit_path = Path("/etc/systemd/system") / unit
        if unit_path.exists():
            run_cmd(["systemctl", "disable", "--now", unit], sudo=True, capture=False)
            run_cmd(["rm", "-f", str(unit_path)], sudo=True, capture=False)


@app.command("auto-heal-off")
def disable_auto_heal() -> None:
    print(Panel("Disable auto-heal"))
    remove_auto_heal_units(legacy_only=False)
    run_cmd(["systemctl", "daemon-reload"], sudo=True, capture=False)
    print("[green]Auto-heal disabled.[/green]")


@app.command("stable-mode")
def stable_mode(
    block_udp: str = "443",
    enable_heal: bool = True,
) -> None:
    print(Panel("Stable mode", subtitle="Fewer drops, less leakage"))
    mode = "all" if block_udp == "all" else "443"

    print("[bold]Step 1:[/bold] Disable UDP/QUIC TPROXY")
    run_cmd(["systemctl", "disable", "--now", "ts-9proxy-udp-tproxy.service"], sudo=True, capture=False)

    print(f"[bold]Step 2:[/bold] Block UDP from tailnet (mode: {mode})")
    write_file(Path("/usr/local/sbin/ts-udp-block.sh"), udp_block_script(), mode=0o755)
    write_file(Path("/etc/systemd/system/ts-udp-block.service"), udp_block_unit(mode))
    run_cmd(["systemctl", "daemon-reload"], sudo=True, capture=False)
    run_cmd(["systemctl", "enable", "--now", "ts-udp-block.service"], sudo=True, capture=False)

    if enable_heal:
        print("[bold]Step 3:[/bold] Enable auto-heal (restart only)")
        enable_auto_heal()
    else:
        print("[bold]Step 3:[/bold] Auto-heal left unchanged")

    print("[green]Stable mode enabled.[/green]")


def install_local_socks_service(
    listen: str,
    upstream: str,
    allow_udp: bool,
    tcp_timeout: int,
    udp_timeout: int,
) -> None:
    cmd = [
        sys.executable,
        "-m",
        "proxy_tailscale.cli",
        "local-socks",
        "--listen",
        listen,
        "--upstream",
        upstream,
        "--tcp-timeout",
        str(tcp_timeout),
        "--udp-timeout",
        str(udp_timeout),
        "--udp" if allow_udp else "--no-udp",
    ]
    service = textwrap.dedent(
        f"""
        [Unit]
        Description=Local SOCKS forwarder ({APP_TITLE})
        After=network-online.target tailscaled.service
        Wants=network-online.target tailscaled.service

        [Service]
        Type=simple
        ExecStart={' '.join(shlex.quote(part) for part in cmd)}
        Restart=on-failure
        RestartSec=2

        [Install]
        WantedBy=multi-user.target
        """
    ).lstrip()
    write_file(Path(f"/etc/systemd/system/{LOCAL_SOCKS_SERVICE}"), service)
    run_cmd(["systemctl", "daemon-reload"], sudo=True, capture=False)
    run_cmd(["systemctl", "enable", "--now", LOCAL_SOCKS_SERVICE], sudo=True, capture=False)
    print("[green]Local SOCKS service enabled.[/green]")


def install_forward_service(
    tcp_rules: list[str],
    udp_rules: list[str],
    tcp_timeout: int,
    udp_timeout: int,
) -> None:
    if not tcp_rules and not udp_rules:
        print("[red]No forwarding rules provided.[/red]")
        return
    cmd = [
        sys.executable,
        "-m",
        "proxy_tailscale.cli",
        "forward",
        "--tcp-timeout",
        str(tcp_timeout),
        "--udp-timeout",
        str(udp_timeout),
    ]
    for rule in tcp_rules:
        cmd.extend(["--tcp", rule])
    for rule in udp_rules:
        cmd.extend(["--udp", rule])
    service = textwrap.dedent(
        f"""
        [Unit]
        Description=Port forwarding ({APP_TITLE})
        After=network-online.target tailscaled.service
        Wants=network-online.target tailscaled.service

        [Service]
        Type=simple
        ExecStart={' '.join(shlex.quote(part) for part in cmd)}
        Restart=on-failure
        RestartSec=2

        [Install]
        WantedBy=multi-user.target
        """
    ).lstrip()
    write_file(Path(f"/etc/systemd/system/{FORWARD_SERVICE}"), service)
    run_cmd(["systemctl", "daemon-reload"], sudo=True, capture=False)
    run_cmd(["systemctl", "enable", "--now", FORWARD_SERVICE], sudo=True, capture=False)
    print("[green]Forwarding service enabled.[/green]")


def run_forwarders(
    tcp_rules: list[str],
    udp_rules: list[str],
    tcp_timeout: int,
    udp_timeout: int,
) -> None:
    mapping = tailscale_host_ip_map()
    dns_map = tailscale_dns_map()
    threads: list[threading.Thread] = []

    for rule in tcp_rules:
        bind, connect, use_tls = parse_tcp_rule(rule)
        thread = threading.Thread(
            target=forward_tcp_server,
            args=(bind, connect, use_tls, tcp_timeout, mapping, dns_map),
            daemon=True,
        )
        thread.start()
        threads.append(thread)

    for rule in udp_rules:
        if "=" not in rule:
            print(f"[red]Invalid UDP rule: {rule}[/red]")
            continue
        bind, connect = rule.split("=", 1)
        thread = threading.Thread(
            target=forward_udp_server,
            args=(bind.strip(), connect.strip(), udp_timeout, mapping),
            daemon=True,
        )
        thread.start()
        threads.append(thread)

    if not threads:
        print("[red]No rules to run.[/red]")
        return

    print("[green]Forwarders running. Press Ctrl+C to stop.[/green]")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass


def install_http_service(listen: str, upstream: str, tcp_timeout: int) -> None:
    cmd = [
        sys.executable,
        "-m",
        "proxy_tailscale.cli",
        "http-proxy",
        "--listen",
        listen,
        "--upstream",
        upstream,
        "--tcp-timeout",
        str(tcp_timeout),
    ]
    service = textwrap.dedent(
        f"""
        [Unit]
        Description=HTTP proxy ({APP_TITLE})
        After=network-online.target tailscaled.service
        Wants=network-online.target tailscaled.service

        [Service]
        Type=simple
        ExecStart={' '.join(shlex.quote(part) for part in cmd)}
        Restart=on-failure
        RestartSec=2

        [Install]
        WantedBy=multi-user.target
        """
    ).lstrip()
    write_file(Path(f"/etc/systemd/system/{HTTP_PROXY_SERVICE}"), service)
    run_cmd(["systemctl", "daemon-reload"], sudo=True, capture=False)
    run_cmd(["systemctl", "enable", "--now", HTTP_PROXY_SERVICE], sudo=True, capture=False)
    print("[green]HTTP proxy service enabled.[/green]")


def pac_content(proxy_host: str, proxy_port: int) -> str:
    return textwrap.dedent(
        f"""
        function FindProxyForURL(url, host) {{
          return "PROXY {proxy_host}:{proxy_port}; DIRECT";
        }}
        """
    ).strip() + "\n"


def generate_pac_file(listen: str) -> Path:
    mapping = tailscale_host_ip_map()
    host, port = resolve_host_port(listen, mapping, default_host="127.0.0.1")
    path = Path.home() / ".local" / "share" / APP_ID / "proxy.pac"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(pac_content(host, port))
    return path


def share_info(ip: str, port: int) -> None:
    print("\n[bold]Share info[/bold]")
    print(f"Host: {ip}")
    print(f"Port: {port}")
    print("Type: SOCKS5 (HTTP proxy also available if enabled)")
    share_text = f"socks5://{ip}:{port}"
    if cmd_exists("qrencode"):
        print("\n[bold]QR[/bold]")
        run_cmd(["qrencode", "-t", "ansiutf8", share_text], capture=False)
    else:
        print(f"Share link: {share_text}")


def allowlist_script() -> str:
    return textwrap.dedent(
        """
        #!/bin/sh
        set -e
        IFACE=tailscale0
        CHAIN=TS_ALLOWLIST
        PORT="${ALLOWLIST_PORT:-60000}"
        IPS="${ALLOWLIST_IPS:-}"
        case "${1:-}" in
          start)
            iptables -t filter -N "$CHAIN" 2>/dev/null || true
            iptables -t filter -F "$CHAIN"
            for ip in $IPS; do
              iptables -t filter -A "$CHAIN" -s "$ip" -p tcp --dport "$PORT" -j ACCEPT
            done
            iptables -t filter -A "$CHAIN" -p tcp --dport "$PORT" -j REJECT
            if ! iptables -t filter -C INPUT -i "$IFACE" -j "$CHAIN" 2>/dev/null; then
              iptables -t filter -I INPUT -i "$IFACE" -j "$CHAIN"
            fi
            ;;
          stop)
            iptables -t filter -D INPUT -i "$IFACE" -j "$CHAIN" 2>/dev/null || true
            iptables -t filter -F "$CHAIN" 2>/dev/null || true
            iptables -t filter -X "$CHAIN" 2>/dev/null || true
            ;;
          *)
            echo "Usage: $0 {start|stop}" >&2
            exit 1
            ;;
        esac
        """
    ).lstrip()


def allowlist_unit(port: int, ips: list[str]) -> str:
    ip_list = " ".join(ips)
    return textwrap.dedent(
        f"""
        [Unit]
        Description=Tailnet allowlist ({APP_TITLE})
        After=network-online.target tailscaled.service
        Wants=network-online.target tailscaled.service

        [Service]
        Type=oneshot
        RemainAfterExit=yes
        Environment=ALLOWLIST_PORT={port}
        Environment=ALLOWLIST_IPS={ip_list}
        ExecStart=/usr/local/sbin/ts-allowlist.sh start
        ExecStop=/usr/local/sbin/ts-allowlist.sh stop

        [Install]
        WantedBy=multi-user.target
        """
    ).lstrip()


def allowlist_on(port: int, ips: list[str]) -> None:
    write_file(Path("/usr/local/sbin/ts-allowlist.sh"), allowlist_script(), mode=0o755)
    write_file(Path(f"/etc/systemd/system/{ALLOWLIST_SERVICE}"), allowlist_unit(port, ips))
    run_cmd(["systemctl", "daemon-reload"], sudo=True, capture=False)
    run_cmd(["systemctl", "enable", "--now", ALLOWLIST_SERVICE], sudo=True, capture=False)
    print("[green]Allowlist enabled.[/green]")


def allowlist_off() -> None:
    run_cmd(["systemctl", "disable", "--now", ALLOWLIST_SERVICE], sudo=True, capture=False)
    run_cmd(["rm", "-f", f"/etc/systemd/system/{ALLOWLIST_SERVICE}"], sudo=True, capture=False)
    run_cmd(["rm", "-f", "/usr/local/sbin/ts-allowlist.sh"], sudo=True, capture=False)
    run_cmd(["systemctl", "daemon-reload"], sudo=True, capture=False)
    print("[green]Allowlist disabled.[/green]")


def pick_online_used_port() -> int | None:
    _, ports = fetch_port_status()
    used = [p for p, info in ports.items() if info["status"].lower() == "used"]
    online = [p for p in used if port_is_online(ports.get(p))]
    if not online:
        return None
    online.sort()
    return online[0]


@app.command("auto-heal-smart-on")
def enable_smart_auto_heal(
    port: int = 60000,
    interval_minutes: int = 2,
) -> None:
    print(Panel("Enable smart auto-heal", subtitle="Restart + switch USED port"))
    remove_auto_heal_units(legacy_only=False)
    python_exec = sys.executable
    service = textwrap.dedent(
        f"""
        [Unit]
        Description={APP_TITLE} smart doctor (no refresh)
        After=network-online.target
        Wants=network-online.target

        [Service]
        Type=oneshot
        ExecStart={shlex.quote(python_exec)} -m proxy_tailscale.cli doctor --port {port} --no-prompt --allow-switch
        """
    ).lstrip()
    timer = textwrap.dedent(
        f"""
        [Unit]
        Description=Run {APP_ID} smart doctor periodically

        [Timer]
        OnBootSec=1min
        OnUnitActiveSec={interval_minutes}min
        AccuracySec=30s
        Persistent=true

        [Install]
        WantedBy=timers.target
        """
    ).lstrip()
    write_file(Path(f"/etc/systemd/system/{AUTO_HEAL_SERVICE}"), service)
    write_file(Path(f"/etc/systemd/system/{AUTO_HEAL_TIMER}"), timer)
    run_cmd(["systemctl", "daemon-reload"], sudo=True, capture=False)
    run_cmd(["systemctl", "enable", "--now", AUTO_HEAL_TIMER], sudo=True, capture=False)
    print("[green]Smart auto-heal enabled.[/green]")


@app.command("share")
def share(
    port: int = 60000,
) -> None:
    ip = tailscale_ip()
    if not ip:
        print("[red]Tailscale IP not found.[/red]")
        raise typer.Exit(1)
    share_info(ip, port)


@app.command("allowlist-on")
def allowlist_on_cmd(
    port: int = 60000,
    ips: list[str] = typer.Option(None, "--ip"),
) -> None:
    if not ips:
        print("[red]Provide at least one --ip.[/red]")
        raise typer.Exit(1)
    allowlist_on(port, ips)


@app.command("allowlist-off")
def allowlist_off_cmd() -> None:
    allowlist_off()


@app.command("http-proxy")
def http_proxy(
    listen: str = "127.0.0.1:8080",
    upstream: str = "127.0.0.1:60000",
    tcp_timeout: int = 1100,
) -> None:
    serve_http_proxy(listen, upstream, tcp_timeout)


@app.command("http-proxy-on")
def http_proxy_on(
    listen: str = "127.0.0.1:8080",
    upstream: str = "127.0.0.1:60000",
    tcp_timeout: int = 1100,
) -> None:
    print(Panel("Enable HTTP proxy", subtitle="Runs in background"))
    install_http_service(listen, upstream, tcp_timeout)


@app.command("http-proxy-off")
def http_proxy_off() -> None:
    print(Panel("Disable HTTP proxy"))
    run_cmd(["systemctl", "disable", "--now", HTTP_PROXY_SERVICE], sudo=True, capture=False)
    run_cmd(["rm", "-f", f"/etc/systemd/system/{HTTP_PROXY_SERVICE}"], sudo=True, capture=False)
    run_cmd(["systemctl", "daemon-reload"], sudo=True, capture=False)
    print("[green]HTTP proxy disabled.[/green]")


@app.command("pac")
def pac(
    listen: str = "127.0.0.1:8080",
) -> None:
    path = generate_pac_file(listen)
    print(f"[green]PAC saved to {path}[/green]")


@app.command("profile-list")
def profile_list() -> None:
    profiles = load_profiles()
    if not profiles:
        print("[yellow]No profiles found.[/yellow]")
        return
    for name in sorted(profiles.keys()):
        print(f"- {name}")


@app.command("profile-apply")
def profile_apply(name: str) -> None:
    profiles = load_profiles()
    if name not in profiles:
        print("[red]Profile not found.[/red]")
        raise typer.Exit(1)
    apply_profile(name, profiles[name])


@app.command("self-test")
def self_test() -> None:
    print(Panel("Self-test", subtitle="Quick health check"))
    ip = tailscale_ip()
    if not ip:
        print("[red]Tailscale IP not found.[/red]")
        return

    relay_port = 60000
    cfg_port = current_relay_port(redsocks_config_path(detect_distro()))
    if cfg_port:
        relay_port = cfg_port

    _, ports = fetch_port_status()
    info = ports.get(relay_port)
    online = "online" if port_is_online(info) else "offline"
    print(f"Proxy port {relay_port}: {online}")

    try:
        sock = socket.create_connection((ip, relay_port), timeout=5)
        sock.sendall(bytes([SOCKS_VERSION, 1, 0]))
        resp = recv_exact(sock, 2)
        print("SOCKS handshake: ok" if resp == bytes([SOCKS_VERSION, 0]) else "SOCKS handshake: failed")
        sock.close()
    except Exception:
        print("SOCKS handshake: failed")

    if cmd_exists("curl"):
        res = run_cmd(
            ["curl", "--socks5-hostname", f"{ip}:{relay_port}", "https://api.ipify.org", "--max-time", "10"],
            capture=True,
        )
        if res.returncode == 0:
            print(f"IP check via proxy: {res.stdout.strip()}")
        else:
            detail = res.stderr.strip() or "failed"
            print(f"IP check via proxy: {detail}")
    else:
        print("IP check via proxy: skipped (curl not found)")


@app.command("local-socks")
def local_socks(
    listen: str = "127.0.0.1:1080",
    upstream: str = "127.0.0.1:60000",
    udp: bool = True,
    tcp_timeout: int = 1100,
    udp_timeout: int = 330,
) -> None:
    serve_local_socks(listen, upstream, udp, tcp_timeout, udp_timeout)


@app.command("local-socks-on")
def local_socks_on(
    listen: str = "127.0.0.1:1080",
    upstream: str = "127.0.0.1:60000",
    udp: bool = True,
    tcp_timeout: int = 1100,
    udp_timeout: int = 330,
) -> None:
    print(Panel("Enable local SOCKS forwarder", subtitle="Runs in background"))
    install_local_socks_service(listen, upstream, udp, tcp_timeout, udp_timeout)


@app.command("local-socks-off")
def local_socks_off() -> None:
    print(Panel("Disable local SOCKS forwarder"))
    run_cmd(["systemctl", "disable", "--now", LOCAL_SOCKS_SERVICE], sudo=True, capture=False)
    run_cmd(["rm", "-f", f"/etc/systemd/system/{LOCAL_SOCKS_SERVICE}"], sudo=True, capture=False)
    run_cmd(["systemctl", "daemon-reload"], sudo=True, capture=False)
    print("[green]Local SOCKS service disabled.[/green]")


@app.command("forward")
def forward(
    tcp: list[str] = typer.Option(None, "--tcp"),
    udp: list[str] = typer.Option(None, "--udp"),
    tcp_timeout: int = 1100,
    udp_timeout: int = 330,
) -> None:
    run_forwarders(tcp or [], udp or [], tcp_timeout, udp_timeout)


@app.command("forward-on")
def forward_on(
    tcp: list[str] = typer.Option(None, "--tcp"),
    udp: list[str] = typer.Option(None, "--udp"),
    tcp_timeout: int = 1100,
    udp_timeout: int = 330,
) -> None:
    print(Panel("Enable port forwarding", subtitle="Runs in background"))
    install_forward_service(tcp or [], udp or [], tcp_timeout, udp_timeout)


@app.command("forward-off")
def forward_off() -> None:
    print(Panel("Disable port forwarding"))
    run_cmd(["systemctl", "disable", "--now", FORWARD_SERVICE], sudo=True, capture=False)
    run_cmd(["rm", "-f", f"/etc/systemd/system/{FORWARD_SERVICE}"], sudo=True, capture=False)
    run_cmd(["systemctl", "daemon-reload"], sudo=True, capture=False)
    print("[green]Forwarding service disabled.[/green]")


def toggle_strict_mode() -> None:
    if systemd_is_active("ts-no-leak.service"):
        if Confirm.ask("Strict mode is ON. Disable it?", default=False):
            strict_mode_off()
        return
    strict_mode()


@app.command("strict-mode")
def strict_mode(enable_heal: bool = True) -> None:
    print(Panel("No-leak strict mode", subtitle="Block non-proxied traffic"))

    print("[bold]Step 1:[/bold] Disable UDP/QUIC TPROXY")
    run_cmd(["systemctl", "disable", "--now", "ts-9proxy-udp-tproxy.service"], sudo=True, capture=False)

    print("[bold]Step 2:[/bold] Enable no-leak firewall (drop tailnet forwarding)")
    write_file(Path("/usr/local/sbin/ts-no-leak.sh"), no_leak_script(), mode=0o755)
    write_file(Path("/etc/systemd/system/ts-no-leak.service"), no_leak_unit())
    run_cmd(["systemctl", "daemon-reload"], sudo=True, capture=False)
    run_cmd(["systemctl", "enable", "--now", "ts-no-leak.service"], sudo=True, capture=False)

    if enable_heal:
        print("[bold]Step 3:[/bold] Enable auto-heal (restart only)")
        enable_auto_heal()
    else:
        print("[bold]Step 3:[/bold] Auto-heal left unchanged")

    print("[green]Strict mode enabled.[/green]")


@app.command("strict-mode-off")
def strict_mode_off() -> None:
    print(Panel("Disable no-leak strict mode"))
    run_cmd(["systemctl", "disable", "--now", "ts-no-leak.service"], sudo=True, capture=False)
    run_cmd(["rm", "-f", "/etc/systemd/system/ts-no-leak.service"], sudo=True, capture=False)
    run_cmd(["rm", "-f", "/usr/local/sbin/ts-no-leak.sh"], sudo=True, capture=False)
    run_cmd(["systemctl", "daemon-reload"], sudo=True, capture=False)
    print("[green]Strict mode disabled.[/green]")


@app.command("enable-redirect")
def enable_redirect(
    enable_udp: bool = typer.Option(False, "--udp", "-u", help="Also enable UDP TPROXY"),
) -> None:
    """Enable TCP redirect for exit-node proxying (fixes missing redirect service)."""
    distro = detect_distro()
    redsocks_bin = "redsocks2" if distro == "arch" else "redsocks"
    svc_name = redsocks_service_name(distro)

    print(Panel("Enable TCP redirect for exit-node", title="TCP Redirect Setup"))

    # Check tailscale is running
    ip = tailscale_ip()
    if not ip:
        print("[red]Tailscale IP not found.[/red] Run 'sudo tailscale up' first.")
        raise typer.Exit(1)

    # Check redsocks
    if not shutil.which(redsocks_bin):
        print(f"[red]{redsocks_bin} not installed.[/red]")
        if not ensure_binary(redsocks_bin, distro, "transparent proxy"):
            raise typer.Exit(1)

    # Get port info
    _, ports = fetch_port_status()
    default_port = 60000
    for p, info in ports.items():
        if info.get("status", "").lower() == "used":
            default_port = p
            break
    port = int(Prompt.ask("Proxy port", default=str(default_port)))

    # Write redsocks config
    cfg_path = redsocks_config_path(distro)
    backup_file(cfg_path)
    write_file(cfg_path, render_redsocks_config(ip, port, udp=enable_udp))
    print(f"[green]Redsocks config written: {cfg_path}[/green]")

    # Start redsocks
    ensure_redsocks_caps_if_needed(distro)
    run_cmd(["systemctl", "enable", "--now", svc_name], sudo=True, capture=False)
    print(f"[green]{svc_name} enabled[/green]")

    # Install TCP redirect
    write_file(Path("/usr/local/sbin/ts-9proxy-redirect.sh"), tcp_redirect_script(), mode=0o755)
    write_file(Path("/etc/systemd/system/ts-9proxy-redirect.service"), tcp_redirect_unit(svc_name))
    run_cmd(["systemctl", "daemon-reload"], sudo=True, capture=False)
    run_cmd(["systemctl", "enable", "--now", "ts-9proxy-redirect.service"], sudo=True, capture=False)
    print("[green]TCP redirect service enabled[/green]")

    # Optional UDP
    if enable_udp:
        write_file(Path("/usr/local/sbin/ts-9proxy-udp-tproxy.sh"), udp_redirect_script(), mode=0o755)
        write_file(Path("/etc/systemd/system/ts-9proxy-udp-tproxy.service"), udp_redirect_unit(svc_name))
        run_cmd(["systemctl", "daemon-reload"], sudo=True, capture=False)
        run_cmd(["systemctl", "enable", "--now", "ts-9proxy-udp-tproxy.service"], sudo=True, capture=False)
        print("[green]UDP TPROXY service enabled[/green]")

    print("\n[bold green]TCP redirect is now active.[/bold green]")
    print("Traffic from tailnet clients will be proxied through 9proxy.")


@app.command()
def undo() -> None:
    print(Panel("Undo redirect services (keeps 9proxy + tailscale)", title="Undo"))
    if not Confirm.ask("Remove redirect and safety services?", default=True):
        raise typer.Exit(0)

    run_cmd(["systemctl", "disable", "--now", "ts-9proxy-udp-tproxy.service"], sudo=True, capture=False)
    run_cmd(["systemctl", "disable", "--now", "ts-9proxy-redirect.service"], sudo=True, capture=False)
    run_cmd(["systemctl", "disable", "--now", "ts-udp-block.service"], sudo=True, capture=False)
    run_cmd(["systemctl", "disable", "--now", "ts-no-leak.service"], sudo=True, capture=False)
    run_cmd(["systemctl", "disable", "--now", LOCAL_SOCKS_SERVICE], sudo=True, capture=False)
    run_cmd(["systemctl", "disable", "--now", FORWARD_SERVICE], sudo=True, capture=False)
    run_cmd(["systemctl", "disable", "--now", HTTP_PROXY_SERVICE], sudo=True, capture=False)
    run_cmd(["systemctl", "disable", "--now", ALLOWLIST_SERVICE], sudo=True, capture=False)
    run_cmd(["rm", "-f", "/etc/systemd/system/ts-9proxy-udp-tproxy.service"], sudo=True, capture=False)
    run_cmd(["rm", "-f", "/etc/systemd/system/ts-9proxy-redirect.service"], sudo=True, capture=False)
    run_cmd(["rm", "-f", "/etc/systemd/system/ts-udp-block.service"], sudo=True, capture=False)
    run_cmd(["rm", "-f", "/etc/systemd/system/ts-no-leak.service"], sudo=True, capture=False)
    run_cmd(["rm", "-f", f"/etc/systemd/system/{LOCAL_SOCKS_SERVICE}"], sudo=True, capture=False)
    run_cmd(["rm", "-f", f"/etc/systemd/system/{FORWARD_SERVICE}"], sudo=True, capture=False)
    run_cmd(["rm", "-f", f"/etc/systemd/system/{HTTP_PROXY_SERVICE}"], sudo=True, capture=False)
    run_cmd(["rm", "-f", f"/etc/systemd/system/{ALLOWLIST_SERVICE}"], sudo=True, capture=False)
    run_cmd(["rm", "-f", "/usr/local/sbin/ts-9proxy-udp-tproxy.sh"], sudo=True, capture=False)
    run_cmd(["rm", "-f", "/usr/local/sbin/ts-9proxy-redirect.sh"], sudo=True, capture=False)
    run_cmd(["rm", "-f", "/usr/local/sbin/ts-udp-block.sh"], sudo=True, capture=False)
    run_cmd(["rm", "-f", "/usr/local/sbin/ts-no-leak.sh"], sudo=True, capture=False)
    run_cmd(["rm", "-f", "/usr/local/sbin/ts-allowlist.sh"], sudo=True, capture=False)
    run_cmd(["systemctl", "daemon-reload"], sudo=True, capture=False)

    print("Done. Your proxy and tailscale remain installed.")


@app.command()
def wizard(save_doc: str | None = None) -> None:
    distro = detect_distro()
    actions: list[str] = []

    print(Panel(f"{APP_TITLE} setup wizard", subtitle="Easy, quick, portable"))

    if not ensure_binary("9proxy", distro, "proxy client"):
        raise typer.Exit(1)
    if not ensure_binary("tailscale", distro, "tailnet VPN"):
        raise typer.Exit(1)

    if not is_9proxy_logged_in():
        print("[yellow]9proxy login required[/yellow]")
        if Confirm.ask("Open 9proxy login UI now?", default=True):
            run_cmd(["9proxy", "auth", "-s"], capture=False)
        print("Run '9proxy setting --display' and confirm User Logged: true.")

    ip = tailscale_ip()
    if not ip:
        print("[red]Tailscale IP not found.[/red] Run 'sudo tailscale up' first.")
        raise typer.Exit(1)

    default_port, ports = pick_default_port()
    used_list = [p for p, info in ports.items() if info["status"].lower() == "used"]
    if used_list:
        used_list.sort()
        display = ", ".join(str(p) for p in used_list)
        print(f"[green]Used ports detected:[/green] {display}")

    port = int(Prompt.ask("Proxy port", default=default_port))
    country = Prompt.ask("Proxy country code", default="US")

    if Confirm.ask("Disable auto refresh to avoid consuming new proxies?", default=True):
        run_cmd(["9proxy", "setting", "--disable-refresh"], capture=True)
        actions.append("Auto refresh disabled")

    if Confirm.ask("Bind 9proxy to your Tailscale IP only? (recommended)", default=True):
        run_cmd(["9proxy", "setting", "--ip", ip], capture=True)
        actions.append(f"Bind 9proxy to tailnet IP: {ip}")

    if Confirm.ask("Use NO proxy auth? (tailnet-only OK)", default=True):
        run_cmd(["9proxy", "setting", "--no_auth"], capture=True)
        actions.append("Proxy auth: disabled (no_auth)")
    else:
        user = Prompt.ask("Proxy username")
        passwd = Prompt.ask("Proxy password", password=True)
        run_cmd(["9proxy", "setting", "--basic_auth", "--proxy_username", user, "--proxy_password", passwd], capture=True)
        actions.append("Proxy auth: enabled (basic_auth)")

    port_info = ports.get(port)
    if port_info and port_info["status"].lower() == "used":
        online = port_info["online"] or "unknown"
        if not port_is_online(port_info):
            print(f"[yellow]Port {port} is USED but OFFLINE.[/yellow]")
            if Confirm.ask("Try restarting 9proxy daemon? (no new IP)", default=True):
                if restart_9proxy_daemon():
                    actions.append("Restarted 9proxy daemon")
                _, ports = fetch_port_status()
                port_info = ports.get(port)
            if not port_is_online(port_info):
                if Confirm.ask("Switch to another USED port from Today's list?", default=False):
                    new_port = attempt_switch_to_used_port(None, ip, distro, open_ui=True)
                    if new_port:
                        port = new_port
                        actions.append(f"Switched to used port {new_port} (today list)")
                        _, ports = fetch_port_status()
                        port_info = ports.get(port)
        if port_is_online(port_info):
            msg = f"Port {port} is in use (online: {port_info['online']}). Reuse without refresh?"
            if Confirm.ask(msg, default=True):
                actions.append(f"Reused existing port {port} (no refresh)")
            else:
                res = run_cmd(["9proxy", "proxy", "-c", country, "-p", str(port)], capture=True)
                if res.returncode == 0:
                    actions.append(f"Refreshed port {port} -> {country}")
        else:
            if Confirm.ask("Refresh this port now? (consumes a new IP)", default=False):
                res = run_cmd(["9proxy", "proxy", "-c", country, "-p", str(port)], capture=True)
                if res.returncode == 0:
                    actions.append(f"Refreshed port {port} -> {country}")
            else:
                actions.append(f"Port {port} offline; no refresh (manual action required)")
    else:
        msg = "This port is free. Create a new proxy on this port now? (consumes a new proxy)"
        if Confirm.ask(msg, default=False):
            res = run_cmd(["9proxy", "proxy", "-c", country, "-p", str(port)], capture=True)
            if res.returncode == 0:
                actions.append(f"9proxy port {port} -> {country}")
        else:
            actions.append(f"Skipped proxy allocation for port {port}")

    mode = Prompt.ask("Mode", choices=["per-app", "exit-node"], default="exit-node")
    enable_udp = False

    if mode == "exit-node":
        skip_exit_node = False
        _, ports = fetch_port_status()
        port_info = ports.get(port)
        if not port_is_online(port_info):
            print("[yellow]Proxy appears offline. Exit-node redirect may break browsing.[/yellow]")
            if not Confirm.ask("Continue exit-node setup anyway?", default=False):
                actions.append("Exit-node setup skipped due to offline proxy")
                skip_exit_node = True
                mode = "per-app"
                print("[green]Continuing in per-app mode.[/green]")

        if skip_exit_node:
            pass
        else:
            run_cmd(["tailscale", "up", "--advertise-exit-node"], sudo=True, capture=False)
            actions.append("Tailscale exit node advertised")

            sysctl_conf = textwrap.dedent(
                """
                net.ipv4.ip_forward = 1
                net.ipv6.conf.all.forwarding = 1
                """
            ).lstrip()
            write_file(Path("/etc/sysctl.d/99-tailscale-exit-node.conf"), sysctl_conf)
            run_cmd(["sysctl", "--system"], sudo=True, capture=False)
            actions.append("IP forwarding enabled")

            redsocks_bin = "redsocks2" if distro == "arch" else "redsocks"
            if not ensure_binary(redsocks_bin, distro, "transparent proxy"):
                raise typer.Exit(1)

            cfg_path = redsocks_config_path(distro)
            svc_name = redsocks_service_name(distro)

            enable_udp = Confirm.ask("Enable UDP/QUIC with redudp + TPROXY?", default=False)
            backup_file(cfg_path)
            write_file(cfg_path, render_redsocks_config(ip, port, udp=enable_udp))
            actions.append(f"Redsocks config written: {cfg_path}")

            ensure_redsocks_caps_if_needed(distro)
            run_cmd(["systemctl", "enable", "--now", svc_name], sudo=True, capture=False)

            write_file(Path("/usr/local/sbin/ts-9proxy-redirect.sh"), tcp_redirect_script(), mode=0o755)
            write_file(Path("/etc/systemd/system/ts-9proxy-redirect.service"), tcp_redirect_unit(svc_name))
            run_cmd(["systemctl", "daemon-reload"], sudo=True, capture=False)
            run_cmd(["systemctl", "enable", "--now", "ts-9proxy-redirect.service"], sudo=True, capture=False)
            actions.append("TCP redirect service enabled")

            if enable_udp:
                write_file(Path("/usr/local/sbin/ts-9proxy-udp-tproxy.sh"), udp_redirect_script(), mode=0o755)
                write_file(Path("/etc/systemd/system/ts-9proxy-udp-tproxy.service"), udp_redirect_unit(svc_name))
                run_cmd(["systemctl", "daemon-reload"], sudo=True, capture=False)
                run_cmd(["systemctl", "enable", "--now", "ts-9proxy-udp-tproxy.service"], sudo=True, capture=False)
                actions.append("UDP redirect service enabled")

    print("\n[bold]Share instructions (tailnet-only)[/bold]")
    print(f"Host: {ip}")
    print(f"Port: {port}")
    print("Type: SOCKS5 (HTTP also works in some apps)")

    log_lines = [
        f"# {APP_TITLE} setup log",
        f"Date: {datetime.now().isoformat(timespec='seconds')}",
        f"Distro: {distro}",
        f"Tailnet IP: {ip}",
        f"Port: {port}",
        f"Mode: {mode}",
        f"UDP enabled: {enable_udp}",
        "",
        "## Actions",
    ] + [f"- {line}" for line in actions]

    output_path = Path(save_doc) if save_doc else None
    saved = write_setup_log(log_lines, output_path)
    print(f"\nSetup log saved to: {saved}")


# =============================================================================
# IP REPUTATION COMMANDS
# =============================================================================


@app.command("ip-check")
def ip_check(
    ip: str = typer.Argument(None, help="IP address to check (uses current proxy IP if not specified)"),
    configure: bool = typer.Option(False, "--configure", "-c", help="Configure API keys"),
) -> None:
    """Check IP reputation across multiple sources."""
    from proxy_tailscale.ip_reputation import check_ip_reputation, configure_api_keys

    if configure:
        configure_api_keys()
        return

    if not ip:
        # Try to get IP from current proxy port
        _, ports = fetch_port_status()
        if ports:
            first_port = sorted(ports.keys())[0]
            info = ports[first_port]
            public_ip = info.get("public_ip", "")
            if public_ip and public_ip != "-":
                ip = public_ip
                print(f"[dim]Using proxy IP from port {first_port}: {ip}[/dim]\n")

    if not ip:
        print("[red]No IP specified and could not detect proxy IP.[/red]")
        print("Usage: tailscale-proxy ip-check <IP>")
        print("       tailscale-proxy ip-check --configure")
        raise typer.Exit(1)

    check_ip_reputation(ip)


if __name__ == "__main__":
    app()
