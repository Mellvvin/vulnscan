# What Vulnscan is

Vulnscan is a command-line security tool that helps people check two practical questions:

1. **Are any of the software packages I use affected by known security advisories?**
2. **Which selected network services can this scanner reach from where it is running?**

It gathers those checks into readable HTML and Markdown reports, with evidence and notes about what was and was not checked.

## The problem it addresses

A package list alone does not tell you whether installed versions have known vulnerabilities. An open-port list alone does not explain what risk an exposed service may represent. And an empty finding list can be misleading if a data source was unavailable or a check could not run.

Vulnscan connects supported software inventory to public vulnerability advisories, checks selected network exposure, and shows coverage and skipped checks alongside the results. This makes it easier to identify likely issues, understand why they were reported, and decide what to investigate or fix first.

## What it can check

### Software and dependencies (`audit`)

- Supported Linux operating-system packages: Debian, Ubuntu, Alpine, AlmaLinux, and Rocky Linux, when their package tools and advisory coverage are available.
- Python packages installed in the Python interpreter running Vulnscan, when `pip` is available.
- Globally installed npm packages, when `npm` is available.
- Project dependency manifests: `requirements*.txt`, `package-lock.json`, and `Pipfile.lock`.
- Compatible Docker images, when Docker is installed and permitted to run containers.

Vulnscan matches discovered package names and versions to public advisory data, then adds available context such as CVE/CWE/CVSS details, known-exploitation status, EPSS, OWASP Top 10 mapping, and remediation guidance. It reads project dependency files; it does not install the project's packages.

### Network exposure (`scan`)

The scanner tests selected TCP ports on authorized IP addresses, hostnames, CIDR ranges, or a target file. It can make limited unauthenticated service, TLS, and web checks. Results classify the tested destination as localhost, LAN, public, or special-use, and include connection evidence.

A normal `audit` only checks listening services on `127.0.0.1`. Use `scan` from an authorized machine on the relevant network to check a server or VM. A result describes what was reachable from that scanner's vantage point; it does not prove reachability from all networks or identify every service with certainty.

## How to use it

Run it from the repository root with Python 3.9 or newer:

```powershell
# Windows PowerShell
py -m vulnscan doctor
py -m vulnscan audit
py -m vulnscan audit --project .\my-app
```

```bash
# Linux or macOS
python3 -m vulnscan doctor
python3 -m vulnscan audit
python3 -m vulnscan audit --project ./my-app
```

The default output is `report.html` and `report.md` under `reports/<timestamp>/`. Review the report's **Coverage and skipped checks** section before treating no findings as a clean bill of health. Add `--include-data` if you also need the JSON and TSV data files for scripts or later report regeneration.

## What it does not do

Vulnscan is a triage aid, not a guarantee that a system is secure. It is not a general source-code or mobile-binary scanner, does not run authenticated application tests, and does not inspect cloud accounts, IAM, managed-cloud settings, or SaaS tenant internals. Native Windows and macOS operating-system package inventories are not implemented. For all network scans, use only systems you own or have explicit written permission to test.

## In short

Vulnscan brings supported software inventory, known-vulnerability data, and limited network exposure checks into one report. Its useful distinction is that it shows both the findings and the limits of the scan, so people can make informed follow-up decisions rather than overstate what a scan proves.
