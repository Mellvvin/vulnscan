# Engagements: running a small-business security checkup

`vulnscan engage` is a workbench for one client at a time. It keeps the scope, the signed
authorization, the scan and email results, the manual checklist, **your** notes and fix prices, and
produces one report you can hand over and explain.

Everything is plain JSON under `engagements/<client>/` (set `VULNSCAN_ENGAGEMENTS_DIR` or `--dir`
to move it). That folder is git-ignored because it holds client data.

## Workflow

```
vulnscan engage new "Mama Njeri Fashions" --scope mamanjeri.co.ke --contact "Njeri"
vulnscan engage authorize mama-njeri-fashions --signer "Njeri W." --date 2026-11-09 --expires 2026-11-16
vulnscan engage dns  mama-njeri-fashions      # SPF / DKIM / DMARC, public records, no letter needed
vulnscan engage scan mama-njeri-fashions      # ports, TLS, web checks
vulnscan engage findings mama-njeri-fashions  # numbered list
vulnscan engage note mama-njeri-fashions 1 --note "Anyone can email as your shop" --fix "Add DMARC" --price 50
vulnscan engage check mama-njeri-fashions acct-mfa fail --note "No MFA on owner Gmail" --fix "Turn it on" --price 20
vulnscan engage report mama-njeri-fashions    # report.html + report.md
vulnscan engage ui                            # same thing in the browser
```

## More checks (all land in the same findings and report)

| Command | What it does | Needs |
|---|---|---|
| `engage winaudit NAME` | Read-only check of this Windows PC: firewall, antivirus, updates, BitLocker, SMBv1, Remote Desktop, UAC, Guest, Secure Boot, auto-login. Run it in an **Administrator** PowerShell for a full check; anything it cannot read is listed as "not checked", never as a problem. | Windows |
| `engage crawl NAME URL [--login]` | Finds pages, forms and API routes (GET only, never submits forms, never follows logout/delete links) and checks them. With `--login` you paste a test account's cookie (hidden, never saved): the crawl is repeated logged-out to find pages that are only protected in the browser. | site in scope |
| `engage codescan NAME FOLDER` | Looks for leaked secrets (keys, M-Pesa/Daraja credentials, database passwords, `.env` committed to git, secrets in git history) and libraries with known vulnerabilities (npm lock files, pinned `requirements.txt`, `Pipfile.lock`) via OSV.dev. Secrets are shown only as the first characters. | internet for the library lookup |
| `engage nmap NAME HOST` | Names the real software and version behind each open port. | Nmap installed |
| `engage nuclei NAME URL` | Runs community vulnerability templates against a site. | Nuclei installed |

`engage scan` now also confirms what is behind database, Remote Desktop and file-sharing ports by speaking
the protocol (a harmless PING / handshake, no login attempts). A Redis or Memcached that answers without a
password is reported as critical; a port that does not answer like the expected service is reported as low
instead of guessing from the port number.

The checklist tab has **Checked, it's fine** and **Doesn't apply** buttons for one-click answers.

## Authorization guard

Scans of publicly routable addresses are refused unless the target is in the engagement scope and a
signed, unexpired authorization is recorded. Private/loopback targets (a lab, the client's LAN when
you are on site) need no letter. Record the letter only after the client has actually signed it.
The email check reads public DNS only.

## Checklist

21 items. Each is `auto` (a clean scan really means pass), `partial` (scanner finds some problems,
you still look) or `manual` (you ask or inspect). A manual answer always wins over the scanner.
Set one with `engage check <name> <id> pass|fail|na|todo`.

## Report

Sections: fix first, summary, issues (what it means / what I can do about it, with your notes and
prices), checklist, resolved or dismissed, scope and method. Findings you mark `false-positive` or
`fixed` leave the counts but stay listed.

## Web UI

`vulnscan engage ui` serves on 127.0.0.1 only. The URL contains a random token; requests without it,
or with a non-local Host/Origin header, are refused.

## Limits

- The crawler does not run JavaScript, so single-page apps expose fewer pages to it, and it compares one logged-in
  user with anonymous only; it cannot test whether user A can open user B's data.
- Burp Suite and OWASP ZAP are still the right tools for deeper manual web testing; vulnscan does not drive them.
- The Windows check reads settings only. It does not scan for malware or list installed software versions.


DKIM selectors cannot be listed, so only common ones are tried. Scans are TCP connect scans from the
machine you run them on. Automated results are indicators; verify before telling a client something is
broken.
