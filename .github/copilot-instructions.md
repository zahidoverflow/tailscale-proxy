# Copilot Instructions for tailscale-proxy

## Project Overview

A Python CLI wizard for setting up 9proxy + Tailscale transparent proxying. Single-file architecture (`src/proxy_tailscale/cli.py`, ~3200 lines) using Typer + Rich for interactive terminal UX.

## Architecture

### Entry Point & Command Structure
- **Entry**: `proxy_tailscale.cli:app` (Typer app with `invoke_without_command=True` callback)
- **Main flow**: No subcommand → `menu()` → interactive numbered menu → individual commands
- **Commands**: Defined via `@app.command("name")` decorators (30+ commands like `wizard`, `doctor`, `dashboard`)

### Key Patterns

**Command execution wrapper** - Always use `CmdResult` dataclass:
```python
def run_cmd(cmd: str | list[str], sudo: bool = False, capture: bool = True) -> CmdResult
```

**Service constants** follow naming pattern:
```python
APP_ID = "tailscale-proxy"
AUTO_HEAL_SERVICE = f"{APP_ID}-doctor.service"  # systemd unit naming
```

**Host resolution** - `.tshost` suffix enables tailnet hostname lookups:
```python
resolve_tshost(host, mapping)  # Converts "myserver.tshost" → tailnet IP
```

**File writes with sudo fallback**:
```python
write_file(path: Path, content: str, mode: int = 0o644)  # Handles root vs user context
```

## Development Workflow

```bash
# Install editable (use pipx, not pip)
pipx install -e .

# Run main entry
tailscale-proxy

# Test specific command
tailscale-proxy self-test
tailscale-proxy doctor --port 60000 --no-prompt
```

## Code Conventions

1. **No external test framework** - Use `self-test` command for health checks
2. **Rich console output** - Use `console.print()` with Rich markup, not plain `print()`
3. **Systemd integration** - Services created via `write_file()` to `/etc/systemd/system/`
4. **Config rendering** - Use `textwrap.dedent()` for multi-line configs (see `render_redsocks_config`)
5. **Logging to file** - `log_line(log_fp, text)` and `log_block(log_fp, text)` for wizard logs

## External Dependencies

- **System binaries**: `tailscale`, `9proxy`, `redsocks`/`redsocks2` (distro-specific)
- **Python**: `typer>=0.12.3`, `rich>=13.7.1` (minimal deps by design)
- **Distro detection**: `detect_distro()` returns `"arch"`, `"debian"`, or `"unknown"`

## Critical Functions

| Function | Purpose |
|----------|---------|
| `tailscale_ip()` | Get local Tailscale IPv4 |
| `tailscale_status_json()` | Parse `tailscale status --json` |
| `fetch_port_status()` | Get 9proxy port states |
| `restart_9proxy_daemon()` | Restart with systemd or manual fallback |
| `run_stream()` | Execute with real-time stdout + log capture |

## Adding New Commands

1. Add function with `@app.command("command-name")` decorator
2. Use `typer.Option()` for CLI args with defaults
3. Add menu entry in `menu()` function if user-facing
4. Follow existing pattern: check deps → prompt user → execute → report status
