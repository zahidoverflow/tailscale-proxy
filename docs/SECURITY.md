# Security and safety notes

Recommended safe default:
- Bind 9proxy to your Tailscale IP only (tailnet-only)
- Share access using Tailscale share links
- Avoid public open proxy unless you fully understand the risk

## TCP redirect (exit node)
Script for TCP redirect (iptables):
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

Systemd unit:
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

## UDP/QUIC redirect (advanced)
This is experimental and may break some apps.

1) Add redudp block to redsocks config:
```bash
redudp {
  bind = "0.0.0.0:12346";
  relay = "<tailscale-ip>:60000";
  type = socks5;
  udp_timeout = 30;
  udp_timeout_stream = 180;
}
```

2) TPROXY script:
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

Systemd unit:
```bash
cat <<'EOF' | sudo tee /etc/systemd/system/ts-9proxy-udp-tproxy.service
[Unit]
Description=Redirect tailnet UDP to 9proxy via redudp (TPROXY)
After=network-online.target tailscaled.service redsocks2.service
Wants=network-online.target tailscaled.service redsocks2.service

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

## No-leak strict mode (killswitch)
This blocks any forwarding from `tailscale0` so nothing leaks if the proxy goes down.
It will also block LAN access from tailnet clients.

Script:
```bash
cat <<'EOF' | sudo tee /usr/local/sbin/ts-no-leak.sh
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
EOF
sudo chmod +x /usr/local/sbin/ts-no-leak.sh
```

Systemd unit:
```bash
cat <<'EOF' | sudo tee /etc/systemd/system/ts-no-leak.service
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
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now ts-no-leak.service
```

Disable:
```bash
sudo systemctl disable --now ts-no-leak.service
```

## Local SOCKS forwarder
- Keep the listen address on `127.0.0.1` unless you truly want a public SOCKS proxy.
- If you bind to `0.0.0.0`, anyone on your LAN can use it.

## HTTP proxy + PAC
- Keep the HTTP proxy on `127.0.0.1` unless you want LAN access.
- PAC files can leak proxy usage to the browser; use with trusted devices.

## Allowlist
- Use allowlist to restrict access to your proxy port by tailnet IP (TCP).
- Combine allowlist with strict mode for best safety.

## Port forwarding
- Prefer binding to your Tailscale IP for tailnet-only access.
- Avoid exposing public ports unless you understand the risk.

## Capability fix for redsocks2 (Arch/Manjaro)
If you see: "Can not make socket transparent", apply this override:
```bash
sudo mkdir -p /etc/systemd/system/redsocks2.service.d
cat <<'EOF' | sudo tee /etc/systemd/system/redsocks2.service.d/override.conf
[Service]
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
EOF
sudo systemctl daemon-reload
sudo systemctl restart redsocks2
```
