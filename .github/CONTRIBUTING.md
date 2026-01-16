# Contributing to tailscale-proxy

Thank you for your interest in contributing! This document provides guidelines and instructions for contributing.

## Code of Conduct

Please be respectful and constructive in all interactions. We're all here to build something useful together.

## Getting Started

### Development Setup

1. Fork and clone the repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/tailscale-proxy.git
   cd tailscale-proxy
   ```

2. Install in editable mode:
   ```bash
   pipx install -e .
   ```

3. Verify installation:
   ```bash
   tailscale-proxy self-test
   ```

### Project Structure

```
tailscale-proxy/
├── src/proxy_tailscale/
│   ├── cli.py          # Main CLI (~3200 lines, single-file architecture)
│   └── ip_reputation.py # IP reputation checker module
├── docs/               # Documentation
├── assets/             # Demo GIFs, images
└── .github/            # GitHub templates and workflows
```

## How to Contribute

### Reporting Bugs

1. Check [existing issues](https://github.com/zahidoverflow/tailscale-proxy/issues) first
2. Use the bug report template
3. Include `tailscale-proxy diagnostics` output
4. Describe steps to reproduce

### Suggesting Features

1. Open a feature request issue
2. Describe the use case and expected behavior
3. Consider if it fits the project's scope (simplifying proxy setup)

### Submitting Code

1. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes following the code conventions below

3. Test thoroughly:
   ```bash
   tailscale-proxy self-test
   ```

4. Commit with a clear message:
   ```bash
   git commit -m "feat: add XYZ feature"
   ```

5. Push and open a Pull Request

## Code Conventions

### Architecture

- **Single-file CLI**: Most functionality lives in `cli.py`
- **No external test framework**: Use `self-test` command for health checks
- **Minimal dependencies**: Only `typer` and `rich` for Python deps

### Patterns

**Command execution** - Always use `CmdResult`:
```python
def run_cmd(cmd: str | list[str], sudo: bool = False, capture: bool = True) -> CmdResult
```

**Rich console output** - Use Rich markup:
```python
console.print("[green]Success[/green]")
console.print(Panel("Content", title="Title"))
```

**Systemd services** - Follow naming convention:
```python
SERVICE_NAME = f"{APP_ID}-feature.service"
```

**File writes with sudo fallback**:
```python
write_file(path: Path, content: str, mode: int = 0o644)
```

### Adding New Commands

1. Add function with `@app.command("command-name")` decorator
2. Use `typer.Option()` for CLI args with defaults
3. Add menu entry in `menu()` function if user-facing
4. Follow pattern: check deps → prompt user → execute → report status

Example:
```python
@app.command("my-feature")
def my_feature(
    port: int = typer.Option(60000, "--port", "-p", help="Port number"),
    no_prompt: bool = typer.Option(False, "--no-prompt", help="Skip confirmation"),
) -> None:
    """Short description of the command."""
    # Check dependencies
    if not cmd_exists("required_binary"):
        print("[red]Missing required_binary[/red]")
        raise typer.Exit(1)
    
    # Prompt if needed
    if not no_prompt:
        if not Confirm.ask("Proceed?"):
            raise typer.Exit(0)
    
    # Execute
    result = run_cmd(["some", "command"])
    
    # Report
    if result.returncode == 0:
        print("[green]Done![/green]")
    else:
        print(f"[red]Failed: {result.stderr}[/red]")
```

### Style Guidelines

- Use type hints for function parameters and return types
- Use `textwrap.dedent()` for multi-line config strings
- Prefer `Path` objects over string paths
- Use Rich `Panel`, `Table`, and markup for output

## Commit Message Format

Follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `refactor:` - Code refactoring
- `chore:` - Maintenance tasks

Examples:
```
feat: add IP reputation checker module
fix: handle missing redsocks config gracefully
docs: update installation instructions
```

## Testing

Since there's no formal test suite, please:

1. Run `tailscale-proxy self-test`
2. Test on both Debian and Arch if possible
3. Verify affected commands work correctly
4. Check for regressions in related functionality

## Questions?

- Open a [Discussion](https://github.com/zahidoverflow/tailscale-proxy/discussions)
- Check existing [Issues](https://github.com/zahidoverflow/tailscale-proxy/issues)

Thank you for contributing!
