# GEMINI.md

## Project Overview

This project, `tailscale-proxy`, is a Python-based command-line interface (CLI) tool designed to simplify the setup and management of a proxy server using Tailscale and 9proxy. It provides an interactive wizard to guide users through the configuration process, including setting up transparent TCP and UDP proxying, managing Tailscale exit nodes, and handling security features like allowlists and no-leak mode.

The tool is built with the `typer` and `rich` libraries, offering a user-friendly and interactive experience in the terminal. It automates the configuration of system services, iptables rules, and other low-level details, making it accessible even for users with limited networking experience.

## Building and Running

### Prerequisites

- Python 3.9+
- `pipx` for installation
- System dependencies: `tailscale`, `9proxy`, `redsocks`

### Installation

The recommended way to install `tailscale-proxy` is via `pipx`, which installs the package in an isolated environment:

```bash
pipx install git+https://github.com/zahidoverflow/tailscale-proxy.git
```

For development, you can install it in editable mode from the local repository:

```bash
pipx install -e .
```

### Running the Application

Once installed, you can run the application with the following command:

```bash
tailscale-proxy
```

This will open a friendly menu with various options for managing your proxy setup. The application also supports a range of subcommands for more advanced usage, which can be explored via the `--help` flag:

```bash
tailscale-proxy --help
```

### Testing

The project does not appear to have a dedicated test suite in the provided file structure. However, it includes a `self-test` command that can be used to perform a quick health check of the proxy setup:

```bash
tailscale-proxy self-test
```

## Development Conventions

### Code Style

The codebase is written in modern Python, using type hints and dataclasses. It follows the standard PEP 8 style guide for Python code. The use of `rich` for console output indicates a focus on providing clear and readable information to the user.

### Project Structure

The project follows a standard Python project structure, with the main source code located in the `src` directory. The `pyproject.toml` file is used for managing project metadata and dependencies, which is a modern standard for Python packaging.

### Entry Point

The application's entry point is defined in the `pyproject.toml` file under the `[project.scripts]` section. It maps the `tailscale-proxy` command to the `app` object in the `proxy_tailscale.cli` module.

### Modularity

The `cli.py` file is well-structured, with a clear separation of concerns. It includes functions for:

- Running shell commands
- Detecting the operating system and distribution
- Interacting with the Tailscale and 9proxy CLIs
- Managing systemd services
- Handling network connections and protocols (SOCKS, HTTP, TCP, UDP)
- Generating configuration files and scripts

This modular design makes the code easier to understand, maintain, and extend.
