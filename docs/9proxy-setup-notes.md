# 9proxy + Tailscale on Debian/Ubuntu (easy steps)

This guide is written for Debian/Ubuntu. If you use a different Linux distro, package names may change.

You have two ways to use 9proxy on other devices:
- Option A (simple): set a proxy inside each app
- Option B (advanced): exit node + transparent proxy (system-wide TCP only)

Important:
- Android can only run one VPN. Tailscale uses the VPN slot.
- Exit node + transparent proxy handles TCP only. UDP/QUIC may bypass.
- Do NOT paste credentials in chat or shell history.

## 1) Install 9proxy
```bash
curl -L -o ~/Downloads/9proxy-linux-debian-amd64.deb https://static.9proxy-cdn.net/download/latest/linux/9proxy-linux-debian-amd64.deb
sudo apt install ./~/Downloads/9proxy-linux-debian-amd64.deb
```

## 2) Start 9proxy service
```bash
sudo systemctl enable --now 9proxyd.service
systemctl status 9proxyd.service --no-pager
```

## 3) Install and log into Tailscale
Quick install (recommended):
```bash
curl -fsSL https://tailscale.com/install.sh | sh
```
Then:
```bash
sudo systemctl enable --now tailscaled.service
sudo tailscale up
```
Check your Tailscale IP (you will use it later):
```bash
tailscale ip -4
```

## 4) Log in to 9proxy
UI login (easy):
```bash
9proxy auth -s
```
CLI login (optional):
```bash
sudo 9proxy auth -u "<email>" -p "<password>"
```
If your shell is zsh and password has `!`:
```bash
unsetopt BANG_HIST
sudo 9proxy auth -u "<email>" -p "<password>"
setopt BANG_HIST
```
Verify login:
```bash
sudo 9proxy setting --display
# Look for: User Logged: true
```

## 5) Bind 9proxy to the Tailscale IP
```bash
tailscale ip -4
sudo 9proxy setting --ip <tailscale-ip>
sudo systemctl restart 9proxyd.service
sudo ss -ltnp | rg 9proxy
```
Bind a proxy port (example: US on port 60000):
```bash
sudo 9proxy proxy -c US -p 60000
sudo 9proxy port --status
```

## Option A) Per-app proxy (simple, recommended)
On any device in your tailnet:
- Proxy host: `<tailscale-ip>`
- Proxy port: `60000`
- Proxy type: HTTP or SOCKS5

Test from this Linux box:
```bash
curl -x http://<tailscale-ip>:60000 https://api.ipify.org
curl --socks5-hostname <tailscale-ip>:60000 https://api.ipify.org
```

## Option A2) Public access (fast, NOT recommended without auth)
This exposes your proxy to the public internet. Use strong auth and firewall limits if possible.

Set 9proxy to listen on all interfaces:
```bash
9proxy setting --ip 0.0.0.0
```

Minimal (no auth, risky):
```bash
9proxy setting --no_auth
```

Enable local basic auth (safer, do NOT reuse your 9proxy login):
```bash
9proxy setting --basic_auth --proxy_username "<user>" --proxy_password "<pass>"
```
If your shell is zsh and password has `!`:
```bash
unsetopt BANG_HIST
9proxy setting --basic_auth --proxy_username "<user>" --proxy_password "<pass>"
setopt BANG_HIST
```

Open firewall port 60000/TCP:
```bash
sudo ufw allow 60000/tcp
```

Port-forward your router:
- Forward `60000/TCP` on the router to your PC LAN IP (example: `192.168.0.245:60000`).
- Your public IP is shown by: `curl -s ifconfig.me`

Share with your friend:
- Proxy host: `<public-ip>`
- Proxy port: `60000`
- Proxy type: SOCKS5 (try HTTP if their app does not support SOCKS5)
- Username/password: only if you enabled basic auth

Quick test (from a network outside your LAN):
```bash
curl --socks5-hostname <public-ip>:60000 https://api.ipify.org
```

## Option B) Exit node + transparent proxy (system-wide TCP)
Use this if you want your phone to use Tailscale exit node without setting a proxy in each app.

### B1) Advertise exit node
```bash
sudo tailscale up --advertise-exit-node
```
Then in Tailscale admin console: Machines -> this host -> "Use as exit node" (tick + save).
If the checkbox is greyed out, wait 30-60s and refresh.
You should see "offers exit node" in:
```bash
tailscale status
```

Enable forwarding (persistent):
```bash
cat <<'EOF' | sudo tee /etc/sysctl.d/99-tailscale-exit-node.conf
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
sudo sysctl --system
```

### B2) Install redsocks and configure it
```bash
sudo apt install redsocks
```
Create `/etc/redsocks.conf` (bind must be 0.0.0.0):
```bash
cat <<'EOF' | sudo tee /etc/redsocks.conf
base {
  log_debug = off;
  log_info = on;
  log = "syslog:daemon";
  daemon = on;
  user = redsocks;
  group = redsocks;
  redirector = iptables;
}

redsocks {
  bind = "0.0.0.0:12345";
  relay = "<tailscale-ip>:60000";
  type = socks5;
  autoproxy = 0;
}
EOF
```
Start service:
```bash
sudo systemctl enable --now redsocks.service
```

### B3) Add iptables redirect (systemd-managed)
Create redirect script:
```bash
cat <<'EOF' | sudo tee /usr/local/sbin/ts-9proxy-redirect.sh
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
EOF
sudo chmod +x /usr/local/sbin/ts-9proxy-redirect.sh
```
Create systemd unit:
```bash
cat <<'EOF' | sudo tee /etc/systemd/system/ts-9proxy-redirect.service
[Unit]
Description=Redirect tailnet TCP to 9proxy via redsocks
After=network-online.target tailscaled.service redsocks.service 9proxyd.service
Wants=network-online.target tailscaled.service redsocks.service 9proxyd.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/ts-9proxy-redirect.sh start
ExecStop=/usr/local/sbin/ts-9proxy-redirect.sh stop

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now ts-9proxy-redirect.service
```

### B4) Phone setup (exit node)
On the phone Tailscale app:
- Settings -> Exit node -> select this Linux host

## Optional) Security + workable options
Security notes:
- Keep 9proxy bound to the Tailscale IP only; verify `ss -ltnp | rg 9proxy` does not show `0.0.0.0:60000`.
- Restrict access with Tailscale ACLs (tag this host and allow only your devices).
- If you use a local firewall, allow only `tailscale0` (or `100.64.0.0/10`) to reach the proxy port.
- Avoid shell history leaks: use `9proxy auth -s` or `read -s` before the CLI auth command.

Workable options (quick choice):
- Option A (per-app proxy) is simplest and most compatible.
- Option B (exit node + transparent proxy) is hands-free but TCP only.
- If an app fails with Option B, switch only that app to Option A.
- Option C (redudp + TPROXY) can capture UDP from exit node clients if 9proxy supports SOCKS5 UDP.

### Option C) UDP via redudp + TPROXY (experimental)
Use this only if 9proxy SOCKS5 UDP works for you. Keep Option B for TCP; this is for UDP/QUIC.
Prereq: exit node advertised and IP forwarding enabled (see B1).

Add a `redudp` block to `/etc/redsocks.conf` (on Arch/Manjaro, use `/etc/redsocks2.conf`). Match the same `bind/relay` style already used above; if your config uses `local_ip/local_port`, map `bind` -> `local_ip/local_port` and `relay` -> `ip/port`:
```bash
cat <<'EOF' | sudo tee -a /etc/redsocks.conf

redudp {
  bind = "0.0.0.0:12346";
  relay = "<tailscale-ip>:60000";
  type = socks5;
  udp_timeout = 30;
  udp_timeout_stream = 180;
}
EOF
sudo systemctl restart redsocks.service
```

If redsocks2 fails with `Can not make socket transparent`, add capabilities (Arch/Manjaro):
```bash
sudo mkdir -p /etc/systemd/system/redsocks2.service.d
cat <<'EOF' | sudo tee /etc/systemd/system/redsocks2.service.d/override.conf
[Service]
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
EOF
sudo systemctl daemon-reload
sudo systemctl restart redsocks2.service
```

Add a UDP TPROXY redirect script:
```bash
cat <<'EOF' | sudo tee /usr/local/sbin/ts-9proxy-udp-tproxy.sh
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
EOF
sudo chmod +x /usr/local/sbin/ts-9proxy-udp-tproxy.sh
```

Create a systemd unit:
```bash
cat <<'EOF' | sudo tee /etc/systemd/system/ts-9proxy-udp-tproxy.service
[Unit]
Description=Redirect tailnet UDP to 9proxy via redudp (TPROXY)
After=network-online.target tailscaled.service redsocks.service 9proxyd.service
Wants=network-online.target tailscaled.service redsocks.service 9proxyd.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/ts-9proxy-udp-tproxy.sh start
ExecStop=/usr/local/sbin/ts-9proxy-udp-tproxy.sh stop

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now ts-9proxy-udp-tproxy.service
```

UDP quick test from a tailnet client (optional):
- `dig @1.1.1.1 example.com` should return an answer if redudp is working.

Test in browser:
- `https://api.ipify.org` should show your 9proxy public IP

## Troubleshooting (quick)
- Exit node tick greyed out: wait 30-60s, refresh admin console, confirm "offers exit node" in `tailscale status`.
- Connection refused: ensure redsocks binds to `0.0.0.0:12345` and is running.
- If tailnet account changes, update IP:
```bash
tailscale ip -4
sudo 9proxy setting --ip <new-tailscale-ip>
sudo sed -i 's/relay = "[^"]*";/relay = "<new-tailscale-ip>:60000";/' /etc/redsocks.conf
sudo systemctl restart 9proxyd.service redsocks.service ts-9proxy-redirect.service
```

## Undo (exit node + transparent proxy)
```bash
sudo systemctl disable --now ts-9proxy-redirect.service
sudo systemctl disable --now redsocks.service
sudo tailscale set --advertise-exit-node=false
sudo rm -f /etc/systemd/system/ts-9proxy-redirect.service
sudo rm -f /usr/local/sbin/ts-9proxy-redirect.sh
sudo rm -f /etc/redsocks.conf
sudo rm -f /etc/sysctl.d/99-tailscale-exit-node.conf
sudo sysctl --system
sudo apt remove redsocks
```

## Undo (UDP TPROXY)
```bash
sudo systemctl disable --now ts-9proxy-udp-tproxy.service
sudo rm -f /etc/systemd/system/ts-9proxy-udp-tproxy.service
sudo rm -f /usr/local/sbin/ts-9proxy-udp-tproxy.sh
sudo systemctl daemon-reload
```

## Useful checks
```bash
sudo 9proxy setting --display
sudo 9proxy port --status
systemctl status 9proxyd.service --no-pager
systemctl status redsocks.service --no-pager
systemctl status ts-9proxy-udp-tproxy.service --no-pager
```


---

# Appendix: Arch/Manjaro differences

Use this if you are on Arch/Manjaro instead of Debian/Ubuntu.

## Install 9proxy (via debtap)
```bash
curl -L -o ~/Downloads/9proxy-linux-debian-amd64.deb https://static.9proxy-cdn.net/download/latest/linux/9proxy-linux-debian-amd64.deb
pamac build debtap
sudo pacman -S --needed pacman-contrib
sudo debtap -u
```
If `debtap -u` fails with TLS errors:
```bash
sudo curl -L --retry 5 --retry-delay 2 https://aur.archlinux.org/packages.gz -o /var/cache/debtap/aur-packages.gz
sudo gzip -df /var/cache/debtap/aur-packages.gz
sudo debtap -u
```
Convert + install:
```bash
debtap ~/Downloads/9proxy-linux-debian-amd64.deb
sudo pacman -U ~/Downloads/9proxy-*.pkg.tar.zst
```
Fix broken profile script (if it appears):
```bash
sudo rm -f /etc/profile.d/9proxy.sh
```

## Install Tailscale
```bash
sudo pacman -S tailscale
sudo systemctl enable --now tailscaled.service
sudo tailscale up
```

## Redsocks for transparent proxy (Option B)
Arch uses `redsocks2` (AUR) instead of `redsocks`:
```bash
pamac build redsocks2
```
Config file and service names:
- Config: `/etc/redsocks2.conf`
- Service: `redsocks2.service`

Use the same config as in Option B, but write it to `/etc/redsocks2.conf` and start it with:
```bash
sudo systemctl enable --now redsocks2.service
```

Undo for Arch (Option B):
```bash
pamac remove redsocks2
```