# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **Do NOT open a public issue** for security vulnerabilities
2. Email the maintainer directly or use GitHub's private vulnerability reporting
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

## Security Considerations

### Safe Defaults

tailscale-proxy is designed with security in mind:

- **Tailnet-only binding**: By default, 9proxy is bound to your Tailscale IP only, preventing exposure to the public internet
- **No credentials stored**: The tool never stores your 9proxy login credentials
- **Strict mode**: Optional killswitch blocks all non-proxied traffic

### Recommendations

1. **Use tailnet-only mode**: Keep the proxy bound to your Tailscale IP
2. **Enable strict mode** for sensitive use cases (blocks leaks if proxy goes offline)
3. **Use allowlist** to restrict which tailnet devices can use the proxy
4. **Keep dependencies updated**: Regularly update Tailscale, 9proxy, and redsocks

### Known Considerations

- **Root access**: Some operations require `sudo` for iptables and systemd
- **Systemd services**: Services are created in `/etc/systemd/system/`
- **Network rules**: iptables rules are modified for transparent proxying

## Responsible Disclosure

We appreciate responsible disclosure and will:
- Acknowledge receipt within 48 hours
- Provide an estimated timeline for a fix
- Credit reporters in release notes (unless anonymity is requested)
