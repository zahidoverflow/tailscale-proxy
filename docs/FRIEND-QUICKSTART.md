# Friend quick-start (tailnet share)

This is the easiest and safest way for non-tech users.

## Steps
1) Install Tailscale
- Android/iOS: install from app store
- Windows/macOS/Linux: https://tailscale.com/download

2) Accept the share link
- You will be asked to log in to Tailscale
- Accept the shared device

3) Choose how to use the proxy
Option A (no settings):
- Open Tailscale app
- Exit node -> select the shared PC
- Done

Option B (per-app proxy):
- Proxy host: <tailscale-ip>
- Proxy port: 60000
- Proxy type: SOCKS5 (or HTTP)

Option C (QR share):
- Run `tailscale-proxy share --port 60000` on the host
- Scan the QR to auto-fill the proxy in supported apps

## Test
Open: https://api.ipify.org
You should see the proxy IP.
