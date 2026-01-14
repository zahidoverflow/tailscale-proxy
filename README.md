# tailscale-proxy

A friendly, interactive wizard to set up 9proxy + Tailscale for easy sharing across devices.

## What it does
- Guides you through 9proxy + Tailscale setup with clear prompts
- Supports safe tailnet-only sharing (recommended)
- Optional exit node + transparent proxy (TCP)
- Optional UDP/QUIC routing via redudp + TPROXY (advanced)
- Optional no-leak strict mode (killswitch for leaks)
- Local SOCKS forwarder (desktop per-app)
- TCP/UDP port forwarding helper (with optional TLS)
- `.tshost` hostname support for tailnet devices
- HTTP proxy + PAC generator
- Tailnet allowlist (limit who can connect)
- Share QR (easy onboarding)
- Built-in profiles and self-test
- Writes a noob-friendly setup log you can keep for later

## Install (pipx)
From this folder:
```bash
pipx install -e .
```

Run (opens a friendly menu):
```bash
tailscale-proxy
```

Save the setup log into this repo:
```bash
tailscale-proxy wizard --save-doc docs/LAST-SETUP.md
```

## Quick usage
- Just run `tailscale-proxy` and choose from the menu.
- It will not consume new IPs unless you explicitly confirm it.

Advanced (optional) commands:
- `tailscale-proxy status` : show current status
- `tailscale-proxy doctor` : fix offline ports without consuming new IPs
- `tailscale-proxy watch` : monitor port health (will ask before refreshing)
- `tailscale-proxy switch-port` : switch to another USED port from Today's list
- `tailscale-proxy auto-heal-on` : enable background auto-heal timer
- `tailscale-proxy auto-heal-smart-on` : auto-heal + switch USED port (no new IPs)
- `tailscale-proxy auto-heal-off` : disable background auto-heal timer
- `tailscale-proxy stable-mode` : block QUIC/UDP leaks for phone stability
- `tailscale-proxy strict-mode` : block all non-proxied forwarding (no leaks)
- `tailscale-proxy strict-mode-off` : disable strict mode
- `tailscale-proxy local-socks` : run a local SOCKS forwarder
- `tailscale-proxy local-socks-on` : run local SOCKS in background
- `tailscale-proxy local-socks-off` : stop local SOCKS service
- `tailscale-proxy forward` : TCP/UDP port forwarding
- `tailscale-proxy forward-on` : run forwarding in background
- `tailscale-proxy forward-off` : stop forwarding service
- `tailscale-proxy http-proxy` : run local HTTP proxy
- `tailscale-proxy http-proxy-on` : run HTTP proxy in background
- `tailscale-proxy http-proxy-off` : stop HTTP proxy service
- `tailscale-proxy pac` : generate PAC file for the HTTP proxy
- `tailscale-proxy share` : show share info + QR
- `tailscale-proxy allowlist-on` : restrict access to tailnet IPs
- `tailscale-proxy allowlist-off` : remove allowlist rules
- `tailscale-proxy profile-list` : list profiles
- `tailscale-proxy profile-apply` : apply a profile
- `tailscale-proxy self-test` : quick health check
- `tailscale-proxy undo` : remove redirect services

The wizard will detect any **already used** 9proxy ports and reuse them by default,
so you don't consume extra proxies unless you choose to refresh.

Safe auto-recovery (no new IP):
```bash
tailscale-proxy doctor --port 60000 --no-prompt
```

TCP forward with optional TLS (Tailscale cert):
```bash
tailscale-proxy forward --tcp ":8443=TLS=127.0.0.1:8443"
```

## Docs
- `docs/MANUAL-SETUP.md` for manual steps
- `docs/FRIEND-QUICKSTART.md` for sharing with friends
- `docs/SECURITY.md` for safe defaults

## Notes
- The tool never stores your 9proxy login.
- For best safety, keep the proxy bound to your Tailscale IP (tailnet-only).
- Strict mode blocks forwarding from tailnet; if the proxy is offline, the exit node will stop working (no leaks).
- Legacy alias: `proxy-tailscale` still works.
