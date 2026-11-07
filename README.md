# vulnscan

Finds **known vulnerabilities in the software that is actually installed** on a machine, a container image or a project, finds **risky exposure on the network**, and explains every finding in **OWASP Top 10** terms in a single report you can hand to someone.

Python standard library only: nothing to `pip install`. Runs on Linux, macOS and Windows. See [how to run Vulnscan](docs/HOW_TO_RUN.md) for platform-specific setup and ignored/generated files, and the [project overview](docs/PROJECT_OVERVIEW.md) for a plain-language explanation of its purpose and use cases.

```text
          ┌── this machine (apt / apk / rpm, pip, npm)
 audit ───┼── Docker images  (--docker nginx:1.18)
          └── project files  (--project .  : requirements.txt, package-lock.json, Pipfile.lock)
                  │
                  ▼
   what is installed ──► OSV.dev ──► known vulnerabilities (CVE / GHSA / distro advisories)
                                        │
        CVE.org ── CWE + CVSS           ├─ CISA KEV ── "exploited in the wild right now"
        MITRE ──── CWE hierarchy        ├─ FIRST EPSS ── likelihood of exploitation
        OWASP ──── CWE → Top 10 map     └─ fix version + the exact upgrade command
                                        ▼
                         report.html / report.md (default; JSON/TSV with --include-data)

 scan ──► open ports, banners, TLS, headers, cookies, CORS, exposed files, error pages ──► same report
```

## Install and run by platform

### What you need

- **All platforms:** Python 3.9 or newer. No third-party Python runtime packages are required when running from this source checkout; Vulnscan uses the Python standard library. Run commands from the repository root (the folder containing `vulnscan/`). Git is only needed to clone or update the repository.
- **Windows:** Install Python 3.9+ and make the Python launcher (`py`) or `python` available in PowerShell. Native Windows OS-package inventory is not supported. WSL is optional; use it if you want the Linux shell scripts or Linux package auditing.
- **macOS:** Install Python 3.9+ and use Terminal. Native macOS OS-package inventory is not supported.
- **Linux:** Install Python 3.9+. Native OS-package inventory is supported for Debian/Ubuntu (`dpkg-query`), Alpine (`apk`), AlmaLinux/Rocky Linux (`rpm`). Other distributions can still run Vulnscan, but their native OS packages may not be inventoried or have OSV advisory coverage.
- **Optional collectors:** `pip` enables inventory of packages in the running Python interpreter; `npm` enables inventory of globally installed npm packages. Docker Engine/Desktop, its CLI, and permission to run containers are needed only for `--docker`. These tools are not required to start Vulnscan; when an enabled inventory check cannot run, review the report's skipped-check notes.
- **Fresh advisory data:** Internet access to the data sources listed below is needed for current online lookups. `--offline` uses the local cache only; a first offline run may not have cached data.

### Run from source

Open PowerShell on Windows, or a terminal on Linux/macOS, change to the Vulnscan repository root, then use the matching commands:

```powershell
# Windows PowerShell
py -m vulnscan doctor
py -m vulnscan audit
```

```bash
# Linux or macOS
python3 -m vulnscan doctor
python3 -m vulnscan audit
```

If `py` is unavailable on Windows but `python` is on `PATH`, replace `py` with `python`. On Linux/macOS, use the Python 3.9+ interpreter as `python3`. `doctor` checks data-source connectivity, optional inventory tools, and OSV coverage for the detected OS release. `audit` writes `reports/<timestamp>/report.html`; review its **Coverage and skipped checks** section before treating zero findings as clean.

### Common tasks

Use the platform's Python command above (`py -m vulnscan` on Windows, `python3 -m vulnscan` on Linux/macOS):

```text
audit --docker nginx:1.18 --docker httpd:2.4.49   # audit container images
audit --project ./my-app                           # supported dependency manifests
audit --no-host --project . --fail-on high         # CI: fail on High+
scan 192.168.56.101 -p top                         # authorized LAN/VM exposure check
update                                             # refresh advisory enrichment data
audit --offline                                   # use cached data only
```

For example, on Linux/macOS run `python3 -m vulnscan audit --project ./my-app`; on Windows run `py -m vulnscan audit --project .\my-app`. The `--project` option reads `requirements*.txt`, `package-lock.json`, and `Pipfile.lock` manifests; it does not install dependencies. A project may be audited from any of the supported host operating systems.

**Exit codes:** `0` done, `1` bad input, `2` a `--fail-on` threshold was hit, `3` the vulnerability data was **incomplete** (a source was unreachable, or OSV has no data for the OS release). An incomplete result is never presented as clean.

### Your VirtualBox Linux VM

Copy the folder into the VM (shared folder, `scp`, or `git clone`) and run `python3 -m vulnscan audit` **inside** it. That checks the VM's real installed packages. Run `scan <vm-ip>` from your host to see what the VM exposes to the network. Use a host-only or NAT network for the VM.

Derivatives such as Kali or Mint are not in OSV under their own name. Tell the tool which release they track: `--ecosystem Debian:12` or `--ecosystem Ubuntu:22.04:LTS`.

### Docker on Windows

`--docker IMAGE` runs the image briefly (`docker run --rm`) to read its package database, so you can audit images without installing anything inside them. A ready-made lab of intentionally old and vulnerable images is in `lab/docker-compose.yml` (bound to 127.0.0.1 only); `scripts/lab_docker.sh` runs it end to end in WSL or Git Bash, or use the commands in the compose file's header from PowerShell. Distroless images have no package tools and cannot be audited.

## Apps, servers, and cloud

Vulnscan can assess software and network exposure in these specific ways:

- **Application dependencies:** `audit --project PATH` reads supported dependency manifests (`requirements*.txt`, `package-lock.json`, and `Pipfile.lock`) without installing the app. It checks package versions against vulnerability advisories; it is not a source-code, binary, mobile-app, or authenticated application security scanner.
- **Running services:** `scan` accepts authorized IPs, hostnames, CIDR ranges, or a target file. It tests selected TCP ports and performs limited unauthenticated HTTP(S), TLS, and service-banner checks from the machine where Vulnscan runs. This is useful for a server, VM, or app endpoint reachable from that vantage point; results do not prove reachability from other networks.
- **Cloud-hosted servers:** Run `audit` on the server itself (or inside its supported Linux guest) to inventory its local packages, and run `scan` from an authorized network location to test reachability. Vulnscan does not SSH into servers or use cloud-provider APIs.
- **Cloud infrastructure and SaaS:** Vulnscan does not inspect cloud accounts, IAM, cloud configuration, managed-service settings, SaaS tenant settings, or authenticated SaaS workflows. For a SaaS hostname it can only perform the same limited unauthenticated network/web checks, with the owner's explicit authorization; it cannot assess the provider's internals.

Only scan systems you own or have written permission to test. Publicly routable targets require `--allow-public`; this flag does not itself establish authorization.

## How network exposure is reported

`scan` classifies each tested destination address as **localhost** (loopback), **LAN** (private or link-local), **public** (globally routable), or **special-use**. A service finding includes the destination address and a successful TCP-connect observation as evidence. Datastore names are marked **potential** because the scanner infers them from conventional port numbers and does not verify the application protocol. This describes what this scanner could reach; it does not identify the service's bind address or prove reachability from every device in that class, through a firewall, or from the public internet.

The network portion of a normal `audit` deliberately tests `127.0.0.1` only. A MongoDB result there means the local scanner connected to MongoDB on localhost; it is **not** evidence that LAN clients or the internet can connect. To test a LAN-facing path, run `scan` against the host's private IP from another authorized device. Public targets require `--allow-public` and written authorization; even then a successful scan proves reachability only from that scanner's vantage point. Reports list the selected TCP ports and explicitly identify UDP, unselected ports, disabled web checks, and external LAN/public reachability as not covered where applicable.

## How findings are mapped to the OWASP Top 10

- **The mapping is data, not hard-coded.** OWASP publishes which CWE weakness types belong to each category. `vulnscan` downloads those lists from OWASP's own source repository, caches them for a week (`vulnscan update` forces a refresh), and ships an offline snapshot as a fallback. Both **2025** (default) and **2021** are supported: `--owasp-edition 2021`.
- **Each CVE is placed by its weakness (CWE).** A CVE for SQL injection (CWE-89) lands in *Injection*; deserialization (CWE-502) in *Software or Data Integrity Failures*. When a CVE names a specific child weakness, MITRE's CWE hierarchy is walked up to the nearest weakness OWASP lists.
- **Honest fallback.** Weaknesses OWASP does not list (for example memory-safety bugs such as CWE-787) are filed under *Software Supply Chain Failures* (2021: *Vulnerable and Outdated Components*), because the real problem is a known-vulnerable component. Every finding records why it landed where it did.
- **Not everything can be scanned.** *Insecure Design* and *Logging & Alerting Failures* are shown as "not assessable". Zero findings in a category is not proof of safety.

## How findings are prioritised

Severity comes from the **CVSS v3 base score** (computed from the vector; verified against published scores) or the advisory's own rating. Advisories with no score are shown as **Medium, tagged "unrated"**, not hidden. Anything on **CISA's Known Exploited Vulnerabilities** list is raised to at least **High**. The **Fix first** list orders by exploitation evidence, then severity, then EPSS probability.

## Data sources

| Source | Used for | If unreachable |
| --- | --- | --- |
| [OSV.dev](https://osv.dev) | matching installed versions to vulnerabilities (Debian, Ubuntu, Alpine, AlmaLinux, Rocky, PyPI, npm) | audit is flagged **incomplete** (exit 3) |
| OWASP Top 10 source (GitHub) | CWE → category mapping | cached copy, then bundled snapshot |
| CISA KEV | exploited-in-the-wild flag | flag unavailable, stated in report |
| FIRST EPSS | exploit likelihood | omitted, stated in report |
| CVE.org records (GitHub) | CWE and CVSS where OSV lacks them | affected findings fall back to "unrated" / component category |
| MITRE CWE catalog | weakness hierarchy | direct matches only |

Everything is cached in `~/.cache/vulnscan` (Windows: `%LOCALAPPDATA%\vulnscan`; override with `VULNSCAN_CACHE_DIR`). Only package names and versions are sent to OSV; nothing else leaves the machine.

## Bash automation

`scripts/assess.sh audit|scan ...` runs a full cycle: assess, write the digest, **diff against the previous run** (new / resolved findings), and archive the results with a SHA-256 manifest. `scripts/report.sh` is a dependency-free digest and `--fail-on` gate over `findings.tsv`. Needs Linux, macOS or WSL.

## Tested how

`python -m pytest` covers version comparison, CVSS maths, OWASP and CWE parsing, inventory parsers, the audit pipeline with fixtures for OSV / KEV / EPSS / CVE.org, report escaping, exposure classification, unavailable-data behavior, and CLI output. Windows, Linux, and macOS inventory branches have regression tests; those tests simulate platform identity and do not replace running the suite on each OS. The GitHub Actions workflow runs Linux on Python 3.9, 3.12, and 3.13; Windows is informational (`continue-on-error`), and there is no macOS CI job.

Known gaps, stated plainly:

- Confirm live OSV connectivity and release coverage on your network with `vulnscan doctor`.
- Native Windows and macOS operating-system package inventories are not supported; only available Python/npm packages, project files, and Docker images can be audited there. The Windows CI job is informational.
- Docker image collection has not been verified against a live Docker engine.
- `lab/vuln_server.py` is a tiny test target for the *scan* half. It is not evidence for the audit half.

## Limitations

- A finding means a published advisory applies to the **installed version**. It does not prove the flaw is reachable on that system, and distributions sometimes backport fixes without changing version numbers (OSV's distro advisories account for most of this).
- **Native Windows and macOS operating-system package inventory is not covered** (OSV has no supported native feed here). Audit available Python/npm packages, project files, Docker images, or run `vulnscan` inside a supported Linux distribution, WSL, or a VM.
- The built-in host exposure check in `audit` targets localhost only. Use `scan` from an appropriate vantage point to check LAN/public paths. Port scanning is TCP connect only; web checks are unauthenticated and do not crawl. It complements, and does not replace, a penetration test.
- End-of-life OS releases may have no advisory data. The tool detects this with a canary lookup and says so instead of reporting a clean result.

## Legal and ethical use

Only scan systems you own or have **explicit written permission** to test. `scan` refuses publicly routable addresses unless you pass `--allow-public`.

## License

MIT
