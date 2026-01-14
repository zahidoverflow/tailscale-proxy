# Manual setup (easy, step-by-step)

This is the noob-friendly manual path if you do not want to use the wizard.

## A) Install 9proxy
- Download the Linux package from 9proxy.
- Install it for your distro.
- Confirm the CLI works:
```bash
9proxy -h
```

## B) Install + log in to Tailscale
Debian/Ubuntu:
```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo systemctl enable --now tailscaled
sudo tailscale up
```

Arch/Manjaro:
```bash
sudo pacman -S tailscale
sudo systemctl enable --now tailscaled
sudo tailscale up
```

Get your tailnet IP:
```bash
tailscale ip -4
```

## C) Log in to 9proxy
Open the login UI:
```bash
9proxy auth -s
```

Check login:
```bash
9proxy setting --display
# Look for: User Logged: true
```

## D) Bind 9proxy to Tailscale IP (recommended)
```bash
9proxy setting --ip <tailscale-ip>
```

Bind a port and country (example US on 60000):
```bash
9proxy proxy -c US -p 60000
9proxy port --status
```

## E) Share with friends (tailnet only)
1) In Tailscale admin console, share your device to your friend.
2) Friend logs in to Tailscale and accepts.
3) Friend uses:
- Host: <tailscale-ip>
- Port: 60000
- Type: SOCKS5 (or HTTP)

## F) Exit node + transparent proxy (optional, TCP only)
This makes your phone work without per-app proxy settings.

1) Advertise exit node:
```bash
sudo tailscale up --advertise-exit-node
```
Then approve it in the admin console.

2) Enable forwarding:
```bash
cat <<'EOF' | sudo tee /etc/sysctl.d/99-tailscale-exit-node.conf
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
sudo sysctl --system
```

3) Install redsocks:
- Debian/Ubuntu: `sudo apt install redsocks`
- Arch/Manjaro: `pamac build redsocks2`

4) Configure redsocks (example):
- Debian/Ubuntu: `/etc/redsocks.conf`
- Arch/Manjaro: `/etc/redsocks2.conf`

```bash
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
```

Start:
- Debian/Ubuntu: `sudo systemctl enable --now redsocks`
- Arch/Manjaro: `sudo systemctl enable --now redsocks2`

5) Add iptables redirect:
Create `/usr/local/sbin/ts-9proxy-redirect.sh` and systemd unit as shown in `docs/SECURITY.md`.

## G) UDP/QUIC (advanced)
UDP needs redudp + TPROXY. This is advanced and may break some apps.
See `docs/SECURITY.md` for the full script and systemd unit.

## H) No-leak strict mode (optional)
This is a "killswitch" that blocks any forwarding from `tailscale0`.
It prevents leaks if the proxy goes offline, but it also blocks LAN access.

Use the script and systemd unit in `docs/SECURITY.md`, then enable it:
```bash
sudo systemctl enable --now ts-no-leak.service
```

## I) Local SOCKS forwarder (desktop per-app)
Run a local SOCKS5 proxy that forwards to your tailnet proxy:
```bash
tailscale-proxy local-socks --listen 127.0.0.1:1080 --upstream <tailscale-ip>:60000
```

Run it in the background:
```bash
tailscale-proxy local-socks-on --listen 127.0.0.1:1080 --upstream <tailscale-ip>:60000
```

## J) Port forwarding (TCP/UDP)
TCP forward example:
```bash
tailscale-proxy forward --tcp "0.0.0.0:8080=127.0.0.1:8080"
```

UDP forward example:
```bash
tailscale-proxy forward --udp "0.0.0.0:5353=<tailscale-ip>:5353"
```

## K) HTTP proxy + PAC
```bash
tailscale-proxy http-proxy --listen 127.0.0.1:8080 --upstream <tailscale-ip>:60000
tailscale-proxy pac --listen 127.0.0.1:8080
```

## L) Allowlist (tailnet IPs)
Restrict access to specific tailnet IPs:
```bash
tailscale-proxy allowlist-on --port 60000 --ip <tailnet-ip-1> --ip <tailnet-ip-2>
```

## M) Share (QR + info)
```bash
tailscale-proxy share --port 60000
```

## N) Profiles + Self-test
```bash
tailscale-proxy profile-list
tailscale-proxy profile-apply phone_stable
tailscale-proxy self-test
```

## Undo
Disable the redirect services, remove the scripts, and stop redsocks. The wizard can do this for you.
