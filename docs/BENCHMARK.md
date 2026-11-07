# Measuring the time saving

Your resume bullet says the tool reduces manual assessment time by roughly 50%. Before you put a number on it, measure it, so you can defend it in an interview. A measured "~70%" you can explain beats a round "50%" you cannot.

## Method

1. **Pick a fixed workload.** For example: your Linux lab (3-5 VMs, such as Metasploitable, DVWA, a hardened Ubuntu box) and the same port set on each.
2. **Time the manual workflow.** Do the assessment by hand the way you normally would and note the clock time for each step:
   - list installed packages and look each version up against advisories by hand (distro security tracker, NVD, `apt list --upgradable`)
   - port scan with `nmap` and read the output
   - check each web port for headers, cookies, CORS, exposed paths (`curl -I`, browser, a wordlist)
   - check TLS (`openssl s_client`)
   - write up findings with severities and remediation in a document
3. **Time the tool workflow.** `time ./scripts/assess.sh audit` (inside each VM) and `time ./scripts/assess.sh scan <vm-ip>`, plus the time you spend reading the report. Run each once with a warm cache and once with a cold cache (`VULNSCAN_CACHE_DIR=$(mktemp -d)`) and report both.
4. **Repeat 3 times each** and use the median.
5. **Record it** in the table below.

| Run | Manual (min) | vulnscan (min) | Findings (manual) | Findings (tool) |
|---|---:|---:|---:|---:|
| 1 | | | | |
| 2 | | | | |
| 3 | | | | |
| **Median** | | | | |

Saving = `(manual - tool) / manual`.

## Caveats to state honestly

- The tool covers a fixed set of checks; manual testing finds things it cannot. Report coverage, not just speed.
- Report which tool findings were false positives and how many manual-only findings the tool missed. A precision/recall note makes the claim credible.
- State the environment (number of hosts, ports, lab VMs).

## Example resume wording once measured

> Built a Python vulnerability scanner (stdlib-only) and Bash reporting pipeline that cut lab assessment time from ~X min to ~Y min per 5-host environment (~Z% reduction, median of 3 runs).
