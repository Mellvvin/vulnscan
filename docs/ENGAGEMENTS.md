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

DKIM selectors cannot be listed, so only common ones are tried. Scans are TCP connect scans from the
machine you run them on. Automated results are indicators; verify before telling a client something is
broken.
