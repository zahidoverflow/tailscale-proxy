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

**Option A - Exit Node (recommended):**
- Open Tailscale app
- Exit node -> select the shared PC
- Done! All traffic goes through the proxy

**Option B - Per-app proxy:**
- Proxy host: `<tailscale-ip>`
- Proxy port: `60000`
- Proxy type: SOCKS5 (or HTTP)

**Option C - QR share:**
- Run `tailscale-proxy share --port 60000` on the host
- Scan the QR to auto-fill the proxy in supported apps

## Test
1. IP Check: https://api.ipify.org - should show residential proxy IP
2. DNS Check: https://dnsleaktest.com - should show ISP's DNS (not Google/Cloudflare)
