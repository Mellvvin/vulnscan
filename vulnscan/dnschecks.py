"""Email-spoofing checks from public DNS records: SPF, DMARC and (best effort) DKIM.

These read public records only, so they need no authorization.  DNS is queried over HTTPS
(Cloudflare, with Google as fallback) using the project's own HTTP client, which keeps the tool
dependency-free; Python's standard library cannot ask for TXT records itself.

A failed lookup is never reported as "record missing": it is counted as unchecked instead.
"""

from __future__ import annotations

import json
import re
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import quote

from .http import Http, HttpError
from .models import Finding, Severity

DOH_URLS = ["https://cloudflare-dns.com/dns-query?name={name}&type={rtype}",
            "https://dns.google/resolve?name={name}&type={rtype}"]
RTYPES = {"TXT": 16, "MX": 15}
DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "k2", "mail", "dkim", "s1", "s2",
                  "smtp", "mandrill"]
_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')

Lookup = Callable[[str, str], Optional[List[str]]]


def make_lookup(http: Http) -> Lookup:
    """Return lookup(name, type) -> list of record strings, or None when every resolver failed."""
    cache: Dict[Tuple[str, str], Optional[List[str]]] = {}

    def lookup(name: str, rtype: str) -> Optional[List[str]]:
        key = (name.lower(), rtype)
        if key in cache:
            return cache[key]
        result: Optional[List[str]] = None
        for template in DOH_URLS:
            try:
                raw = http.request("GET", template.format(name=quote(name, safe=""), rtype=rtype),
                                   headers={"Accept": "application/dns-json"})
                doc = json.loads(raw)
            except (HttpError, ValueError):
                continue
            status = doc.get("Status")
            if status == 3:  # NXDOMAIN: the name genuinely does not exist
                result = []
                break
            if status != 0:
                continue
            out: List[str] = []
            for ans in doc.get("Answer") or []:
                if ans.get("type") != RTYPES[rtype]:
                    continue
                data = str(ans.get("data", ""))
                parts = _QUOTED.findall(data)
                out.append("".join(parts) if parts else data.strip())
            result = out
            break
        cache[key] = result
        return result

    return lookup


def _tags(record: str) -> Dict[str, str]:
    tags: Dict[str, str] = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def _f(domain: str, cid: str, title: str, sev: Severity, desc: str, fix: str, evidence: str = "") -> Finding:
    return Finding(host=domain, port=None, check_id=cid, title=title, severity=sev, category="misconfig",
                   cwe="CWE-290", description=desc, remediation=fix, evidence=evidence)


def check_domain(domain: str, lookup: Lookup) -> Tuple[List[Finding], bool]:
    """Return (findings, fully_checked)."""
    out: List[Finding] = []
    txt = lookup(domain, "TXT")
    dmarc_txt = lookup("_dmarc." + domain, "TXT")
    mx = lookup(domain, "MX")
    if txt is None or dmarc_txt is None:
        return out, False
    sends_mail = bool(mx)

    spf = [t for t in txt if t.lower().startswith("v=spf1")]
    dmarc = [t for t in dmarc_txt if t.lower().startswith("v=dmarc1")]

    if not spf:
        out.append(_f(domain, "DNS-NO-SPF", f"No SPF record for {domain}",
                      Severity.MEDIUM if sends_mail else Severity.LOW,
                      "Without SPF, receiving mail servers cannot tell which servers may send mail as this "
                      "domain, so forged messages are easier to deliver.",
                      "Publish a TXT record such as 'v=spf1 include:<your mail provider> -all' (or 'v=spf1 -all' "
                      "if the domain sends no mail).",
                      evidence="no TXT record starting v=spf1"))
    elif len(spf) > 1:
        out.append(_f(domain, "DNS-SPF-MULTIPLE", f"Several SPF records for {domain}", Severity.MEDIUM,
                      "More than one SPF record is invalid, and receivers may ignore SPF completely.",
                      "Merge them into a single SPF record.", evidence=" | ".join(spf)[:200]))
    else:
        record = spf[0].lower()
        tokens = record.split()
        all_token = next((t for t in reversed(tokens) if re.fullmatch(r"[+?~-]?all", t)), None)
        if all_token in ("+all", "all", "?all"):
            out.append(_f(domain, "DNS-SPF-PERMISSIVE", f"SPF for {domain} allows any sender", Severity.HIGH,
                          f"The SPF record ends in '{all_token}', which tells receivers any server may send "
                          "mail as this domain.", "End the record with '-all' (or '~all' while testing).",
                          evidence=spf[0][:200]))
        elif all_token is None and not any(t.startswith("redirect=") for t in tokens):
            out.append(_f(domain, "DNS-SPF-NO-ALL", f"SPF for {domain} has no 'all' policy", Severity.LOW,
                          "Without a closing 'all' mechanism receivers do not know what to do with senders "
                          "that are not listed.", "End the record with '-all' or '~all'.", evidence=spf[0][:200]))

    if not dmarc:
        no_protection = not spf
        out.append(_f(domain, "DNS-NO-DMARC", f"No DMARC record for {domain}",
                      Severity.HIGH if no_protection else Severity.MEDIUM,
                      "DMARC tells receivers to reject forged mail and sends you reports about abuse. "
                      + ("With no SPF either, anyone can spoof this domain with little resistance."
                         if no_protection else "SPF alone is not enough to stop display-name and domain spoofing."),
                      "Publish a TXT record at _dmarc." + domain + " such as "
                      "'v=DMARC1; p=quarantine; rua=mailto:<your address>', then tighten to p=reject.",
                      evidence=f"no TXT record starting v=DMARC1 at _dmarc.{domain}"))
    else:
        tags = _tags(dmarc[0])
        if tags.get("p", "").lower() == "none":
            out.append(_f(domain, "DNS-DMARC-MONITOR-ONLY", f"DMARC for {domain} is monitor-only", Severity.LOW,
                          "A policy of p=none reports forged mail but does not stop it.",
                          "Once the reports look clean, move to p=quarantine and then p=reject.",
                          evidence=dmarc[0][:200]))

    if sends_mail:
        found = False
        for selector in DKIM_SELECTORS:
            records = lookup(f"{selector}._domainkey.{domain}", "TXT") or []
            if any("v=dkim1" in r.lower() or "p=" in r.lower() for r in records):
                found = True
                break
        if not found:
            out.append(_f(domain, "DNS-DKIM-NOT-FOUND", f"No DKIM key found for {domain} on common selectors",
                          Severity.INFO,
                          "DKIM selectors cannot be listed from DNS, so only common ones were tried. This may be "
                          "a false alarm if the mail provider uses a custom selector.",
                          "Confirm in the mail provider's admin console that DKIM signing is enabled.",
                          evidence="tried: " + ", ".join(DKIM_SELECTORS)))
    return out, True


def run_dns_checks(domains: List[str], http: Http,
                   log: Callable[[str], None] = lambda m: None) -> Tuple[List[Finding], dict]:
    lookup = make_lookup(http)
    findings: List[Finding] = []
    failed: List[str] = []
    for domain in domains:
        log(f"checking email records for {domain}")
        found, ok = check_domain(domain, lookup)
        findings.extend(found)
        if not ok:
            failed.append(domain)
    coverage = {"status": "completed" if not failed else "incomplete", "domains": list(domains),
                "lookup_failed": failed, "method": "DNS over HTTPS (Cloudflare, Google fallback)",
                "limitations": ["DKIM selectors cannot be enumerated; only common ones are tried.",
                                "Only the names given were checked, not their subdomains."]}
    if failed:
        coverage["skipped_checks"] = [f"DNS lookups failed for {', '.join(failed)}; email records not checked"]
    return findings, coverage
