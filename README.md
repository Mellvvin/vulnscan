# vulnscan

Finds **known vulnerabilities in the software that is actually installed** on a machine, a container image or a project, finds **risky exposure on the network**, and explains every finding in **OWASP Top 10** terms in a single report you can hand to someone.

Python standard library only: nothing to `pip install`. Runs on Linux, macOS and Windows.

```
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
                         report.html / report.md / results.json / findings.tsv

 scan ──► open ports, banners, TLS, headers, cookies, CORS, exposed files, error pages ──► same report
```

## Run it

You need Python 3.9 or newer.

```bash
# Linux / macOS / WSL                         # Windows (PowerShell)
python3 -m vulnscan doctor                    py -m vulnscan doctor
python3 -m vulnscan audit                     py -m vulnscan audit
```

1. **`doctor` first.** It checks that every data source is reachable and that your OS is recognised, and tells you what is missing. Run it once on each new machine.
2. **`audit`** inventories this machine, matches it against live vulnerability data, and writes `reports/<timestamp>/report.html`. The first run downloads advisory data (a minute or two on a large system); later runs use the cache.
3. Open `report.html`.

```bash
python3 -m vulnscan audit --docker nginx:1.18 --docker httpd:2.4.49   # audit container images
python3 -m vulnscan audit --project ./my-app                          # audit dependency files
python3 -m vulnscan audit --no-host --project . --fail-on high        # CI: fail the build on High+
python3 -m vulnscan scan 192.168.56.101 -p top                        # exposure scan of a host (e.g. a VM)
python3 -m vulnscan update                                            # refresh OWASP, CISA KEV, CWE data now
python3 -m vulnscan audit --offline                                   # cached data only
```

**Exit codes:** `0` done, `1` bad input, `2` a `--fail-on` threshold was hit, `3` the vulnerability data was **incomplete** (a source was unreachable, or OSV has no data for the OS release). An incomplete result is never presented as clean.

### Your VirtualBox Linux VM

Copy the folder into the VM (shared folder, `scp`, or `git clone`) and run `python3 -m vulnscan audit` **inside** it. That checks the VM's real installed packages. Run `scan <vm-ip>` from your host to see what the VM exposes to the network. Use a host-only or NAT network for the VM.

Derivatives such as Kali or Mint are not in OSV under their own name. Tell the tool which release they track: `--ecosystem Debian:12` or `--ecosystem Ubuntu:22.04:LTS`.

### Docker on Windows

`--docker IMAGE` runs the image briefly (`docker run --rm`) to read its package database, so you can audit images without installing anything inside them. A ready-made lab of intentionally old and vulnerable images is in `lab/docker-compose.yml` (bound to 127.0.0.1 only); `scripts/lab_docker.sh` runs it end to end in WSL or Git Bash, or use the commands in the compose file's header from PowerShell. Distroless images have no package tools and cannot be audited.

## How findings are mapped to the OWASP Top 10

- **The mapping is data, not hard-coded.** OWASP publishes which CWE weakness types belong to each category. `vulnscan` downloads those lists from OWASP's own source repository, caches them for a week (`vulnscan update` forces a refresh), and ships an offline snapshot as a fallback. Both **2025** (default) and **2021** are supported: `--owasp-edition 2021`.
- **Each CVE is placed by its weakness (CWE).** A CVE for SQL injection (CWE-89) lands in *Injection*; deserialization (CWE-502) in *Software or Data Integrity Failures*. When a CVE names a specific child weakness, MITRE's CWE hierarchy is walked up to the nearest weakness OWASP lists.
- **Honest fallback.** Weaknesses OWASP does not list (for example memory-safety bugs such as CWE-787) are filed under *Software Supply Chain Failures* (2021: *Vulnerable and Outdated Components*), because the real problem is a known-vulnerable component. Every finding records why it landed where it did.
- **Not everything can be scanned.** *Insecure Design* and *Logging & Alerting Failures* are shown as "not assessable". Zero findings in a category is not proof of safety.

## How findings are prioritised

Severity comes from the **CVSS v3 base score** (computed from the vector; verified against published scores) or the advisory's own rating. Advisories with no score are shown as **Medium, tagged "unrated"**, not hidden. Anything on **CISA's Known Exploited Vulnerabilities** list is raised to at least **High**. The **Fix first** list orders by exploitation evidence, then severity, then EPSS probability.

## Data sources

| Source | Used for | If unreachable |
|---|---|---|
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

`python -m pytest` runs 68 tests: version comparison, CVSS maths, OWASP and CWE parsing, inventory parsers, the full audit pipeline against fixtures that follow the documented OSV / KEV / EPSS / CVE.org response shapes, report output (including escaping of hostile advisory text), the CLI and the Bash scripts. The OWASP, CISA KEV and CVE.org integrations were also exercised against the live services. ShellCheck is clean.

Known gaps, stated plainly:
- The OSV client follows OSV's documented API and is covered by fixtures; confirm it on your network with `vulnscan doctor`, which queries OSV live.
- The Docker image collector and the Windows CI job have not been run by the author yet.
- `lab/vuln_server.py` is a tiny test target for the *scan* half. It is not evidence for the audit half.

## Limitations

- A finding means a published advisory applies to the **installed version**. It does not prove the flaw is reachable on that system, and distributions sometimes backport fixes without changing version numbers (OSV's distro advisories account for most of this).
- Windows application inventory is not covered (OSV has no Windows software feed): audit Python/npm packages, project files, Docker images, and run `vulnscan` inside WSL or VMs.
- Port scanning is TCP connect only; web checks are unauthenticated and do not crawl. It complements, and does not replace, a penetration test.
- End-of-life OS releases may have no advisory data. The tool detects this with a canary lookup and says so instead of reporting a clean result.

## Legal and ethical use

Only scan systems you own or have **explicit written permission** to test. `scan` refuses publicly routable addresses unless you pass `--allow-public`.

## License

MIT
