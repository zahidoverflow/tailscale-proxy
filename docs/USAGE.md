# Simple usage

You only need **one command**:

```bash
tailscale-proxy
```

Then choose from the menu:
- Dashboard (refresh)
- Quick setup
- Fix offline (no new IP)
- Switch to another USED port (Today list)
- Stable mode (recommended for phone)
- No-leak strict mode (toggle)
- Local SOCKS forwarder (desktop)
- Port forwarding (TCP/UDP)
- HTTP proxy + PAC
- Share (QR + info)
- Allowlist (tailnet IPs)
- Profiles
- Self-test
- Enable/Disable auto-heal
- Undo redirect services

## If websites stop loading
1) Run `tailscale-proxy`
2) Choose **Fix offline**
3) If still offline, choose **Switch to another USED port**

This never uses a new proxy unless you approve it.

## Smart auto-heal (no new IP)
Automatically restarts 9proxy and switches to another USED port when needed:
```bash
tailscale-proxy auto-heal-smart-on
```

## No-leak strict mode
Use this if you want a hard "no leaks" rule. It blocks all forwarding
from the tailnet unless the traffic is redirected through the proxy.
If the proxy goes offline, the exit node will stop working (by design).

## Local SOCKS forwarder (desktop per-app)
Run a local SOCKS5 proxy that forwards to your tailnet 9proxy endpoint.
This is great for desktop apps that support SOCKS directly.

Example:
```bash
tailscale-proxy local-socks --listen 127.0.0.1:1080 --upstream <tailscale-ip>:60000
```

## Port forwarding (TCP/UDP)
Forward TCP/UDP ports between any local or tailnet addresses.

Example TCP with TLS (Tailscale cert):
```bash
tailscale-proxy forward --tcp ":8443=TLS=127.0.0.1:8443"
```

Example UDP:
```bash
tailscale-proxy forward --udp "0.0.0.0:5353=<tailscale-ip>:5353"
```

## HTTP proxy + PAC
Run a local HTTP proxy that forwards via SOCKS, and generate a PAC file:
```bash
tailscale-proxy http-proxy --listen 127.0.0.1:8080 --upstream <tailscale-ip>:60000
tailscale-proxy pac --listen 127.0.0.1:8080
```

## Allowlist
Limit who can use your proxy (tailnet IPs only):
```bash
tailscale-proxy allowlist-on --port 60000 --ip <tailnet-ip-1> --ip <tailnet-ip-2>
```

## Share (QR + info)
```bash
tailscale-proxy share --port 60000
```

## Profiles
```bash
tailscale-proxy profile-list
tailscale-proxy profile-apply phone_stable
```

## Self-test
```bash
tailscale-proxy self-test
```
