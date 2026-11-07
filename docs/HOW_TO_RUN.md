# How to run Vulnscan

This guide covers prerequisites, commands for each supported host platform, optional integrations, and which repository files are required. Run commands from the repository root (the directory containing `pyproject.toml` and `vulnscan/`). Vulnscan is a command-line program, not a continuously running service: each `audit` or `scan` command runs a check and exits.

## Prerequisites

- **Every platform:** Python 3.9 or newer. Vulnscan has no third-party Python runtime dependencies; a source checkout can be run directly with `python -m vulnscan`.
- **Online advisory lookups:** Internet access to the data sources listed in the main README. Without it, use `--offline` only when you already have cache data; an empty cache means packages may remain unchecked.
- **Optional Python inventory:** `pip` must be available in the Python interpreter being audited for the installed-Python-package check.
- **Optional npm inventory:** Install Node.js/npm if you want the globally installed npm package check. Project `package-lock.json` files can be read without npm.
- **Optional Docker inventory:** Install Docker Engine (Linux) or Docker Desktop (Windows/macOS), ensure the `docker` CLI is on `PATH`, and ensure your account can run containers. Only needed with `--docker IMAGE`.
- **Tests only:** Install the development extra with `python -m pip install -e ".[dev]"`; then run `python -m pytest`. This is not required to run Vulnscan.

## Platform support and commands

| Host platform | Required to run | Native OS package inventory | Optional tools |
| --- | --- | --- | --- |
| Windows | Python 3.9+, PowerShell, `py` (or `python` on PATH) | Not supported natively | `pip`, npm, Docker Desktop; WSL for Linux scripts and Linux package inventory |
| Linux | Python 3.9+ | Debian/Ubuntu: `dpkg-query`; Alpine: `apk`; AlmaLinux/Rocky: `rpm` | `pip`, npm, Docker Engine |
| macOS | Python 3.9+, Terminal | Not supported natively | `pip`, npm, Docker Desktop |
| WSL | Python 3.9+ inside WSL, Linux shell | Supported Linux distro only; audits WSL, not Windows | npm, Docker integration if configured |

Missing optional inventory tools can reduce coverage. Check `doctor` and the report's **Coverage and skipped checks** section. Windows and macOS can still audit Python/npm packages, supported project manifests and Docker images, and can run network scans.

### Windows PowerShell

```powershell
py --version
py -m vulnscan --version
py -m vulnscan doctor
py -m vulnscan audit
```

If the Python launcher is not installed but `python` is on `PATH`, replace `py` with `python`. Examples:

```powershell
py -m vulnscan audit --project .\my-app
py -m vulnscan audit --docker nginx:1.18
py -m vulnscan scan 192.168.56.101 -p top
```

### Linux

```bash
python3 --version
python3 -m vulnscan --version
python3 -m vulnscan doctor
python3 -m vulnscan audit
```

Examples:

```bash
python3 -m vulnscan audit --project ./my-app
python3 -m vulnscan audit --docker nginx:1.18
python3 -m vulnscan scan 192.168.56.101 -p top
```

The Linux package inventory supports Debian, Ubuntu, Alpine, AlmaLinux, and Rocky Linux when the corresponding package query utility is installed. Other Linux distributions may run Vulnscan but can have no native package inventory or OSV advisory coverage. For derivatives such as Kali or Mint, `--ecosystem` may be needed; see the main README.

### macOS Terminal

```bash
python3 --version
python3 -m vulnscan --version
python3 -m vulnscan doctor
python3 -m vulnscan audit
```

Examples:

```bash
python3 -m vulnscan audit --project ./my-app
python3 -m vulnscan audit --docker nginx:1.18
python3 -m vulnscan scan 192.168.56.101 -p top
```

macOS package-manager inventory is not implemented. The audit can still check available Python/npm packages, project manifests and Docker images.

### WSL

Run Linux commands from the WSL terminal. Vulnscan inventories the WSL distribution and its software, not the Windows host. To audit Windows, run the Windows Python command in PowerShell. Bash automation scripts can run in Linux, macOS, or WSL.

## What each command does

- `doctor` checks advisory-source connectivity, optional tools, and OSV coverage for the detected Linux release.
- `audit` checks installed software and the machine's localhost services. Its default output is the HTML and Markdown report; review coverage and skipped checks before interpreting a zero-finding result.
- `audit --project PATH` reads `requirements*.txt`, `package-lock.json`, and `Pipfile.lock` under a project directory. It does not install the project.
- `audit --docker IMAGE` briefly runs a container to read its package database. Distroless images without the expected shell/package tools may not be auditable.
- `scan TARGET` checks selected TCP ports and performs limited unauthenticated service/web checks from the machine running Vulnscan. It accepts authorized IPs, hostnames, CIDR ranges, or a file of targets. Publicly routable targets require `--allow-public` and written authorization.
- `update` refreshes OWASP, CISA KEV, and CWE enrichment data.

Example for a public target you are explicitly authorized to test:

```bash
python3 -m vulnscan scan <authorized-public-host> --allow-public
```

Replace the placeholder with a target you have written permission to test. The flag is not permission by itself.

## Output files and Git ignore rules

By default, each `audit` or `scan` run writes only the actual report formats to `reports/<timestamp>/`:

- `report.html` — primary interactive report.
- `report.md` — Markdown version of the report.

The project does **not** add HeyClicky branding or HeyClicky-specific files to report output. The previous `results.json` and `findings.tsv` files were Vulnscan machine-readable sidecars, not HeyClicky files. Use `--include-data` when you explicitly need those sidecars for scripts, archiving, or later report regeneration:

```powershell
py -m vulnscan audit --include-data
```

```bash
python3 -m vulnscan audit --include-data
```

`--no-report` is the opposite mode: it writes only `results.json` and `findings.tsv`. The `scripts/assess.sh` automation requests the data sidecars because its digest and comparison steps depend on them.

The repository's `.gitignore` excludes generated `reports/`, Python bytecode/cache, build artifacts, virtual environments, and package build metadata. These are not source files needed to run Vulnscan. Required source files—including `pyproject.toml`, the `vulnscan/` package, and the bundled `vulnscan/data/owasp_2021.json` / `owasp_2025.json` snapshots—are tracked by Git. The report cache is stored outside the repository under the platform cache directory (`~/.cache/vulnscan`, or `%LOCALAPPDATA%\vulnscan` on Windows); deleting it clears cached data but does not remove source code.

## Reviewing an audit

Open `report.html` in a browser and check **Coverage and skipped checks**. An unavailable data source, unsupported operating system package feed, or skipped inventory can make an otherwise empty findings list incomplete. A localhost connection finding proves only what the scanner reached from that machine; it does not establish LAN or public reachability.
