"""Optional integrations with well-known tools, used only if they are installed on this computer.

* Nmap   - identifies the real software and version behind each open port.
* Nuclei - runs community vulnerability templates against a website.

vulnscan never installs these.  Their output is converted into ordinary findings so it lands in the same
report.  Both tools are active scanners: the engagement's scope and authorization rules apply first.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Callable, Dict, List, Optional, Tuple

from .models import Finding, Severity
from .versions import version_findings

Runner = Callable[[List[str], int], Tuple[int, str]]


def default_runner(cmd: List[str], timeout: int) -> Tuple[int, str]:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")
    return proc.returncode, proc.stdout


def available(tool: str) -> Optional[str]:
    return shutil.which(tool)


# ------------------------------------------------------------------ Nmap

def parse_nmap_xml(xml_text: str) -> List[dict]:
    """Return [{'port', 'name', 'product', 'version', 'extra', 'tunnel'}] for open ports."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []
    out = []
    for port in root.iter("port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        svc = port.find("service")
        s = svc.attrib if svc is not None else {}
        out.append({"port": int(port.get("portid", "0")), "name": s.get("name", ""),
                    "product": s.get("product", ""), "version": s.get("version", ""),
                    "extra": s.get("extrainfo", ""), "tunnel": s.get("tunnel", "")})
    return out


def banner_text(svc: dict) -> str:
    """Rebuild banner-style strings so the built-in version rules (Apache/2.4.x, OpenSSH_8.x) can match."""
    product, version = svc.get("product", ""), svc.get("version", "")
    if not product or not version:
        return ""
    first = product.split()[0]
    forms = [f"{first}/{version}", f"{first}_{version}", f"{first} {version}"]
    if "IIS" in product:
        forms.append(f"Microsoft-IIS/{version}")
    return " ".join(forms)


def nmap_findings(host: str, services: List[dict]) -> List[Finding]:
    findings: List[Finding] = []
    for svc in services:
        text = banner_text(svc)
        if text:
            findings.extend(version_findings(host, svc["port"], text))
    named = [s for s in services if s["product"]]
    if named:
        lines = [f"{s['port']}/{s['name'] or '?'}: {s['product']} {s['version']}".strip() for s in named]
        findings.append(Finding(
            host=host, port=None, check_id="EXT-NMAP-SERVICES", title=f"Nmap identified {len(named)} service(s) "
            "and their versions", severity=Severity.INFO, category="supply_chain", cwe="CWE-200",
            description="Nmap probed each open port and recognised the software behind it. Check the versions "
                        "against the vendors' support pages.",
            remediation="Update anything that is out of date and close services that are not needed.",
            evidence="; ".join(lines)[:600]))
    return findings


def run_nmap(host: str, address: str, ports: str, runner: Runner = default_runner,
             timeout: int = 600) -> Tuple[List[Finding], dict]:
    exe = available("nmap")
    if not exe and runner is default_runner:
        raise RuntimeError("Nmap is not installed (or not on PATH). Get it from https://nmap.org/download")
    cmd = [exe or "nmap", "-sV", "--version-light", "-Pn", "-oX", "-"]
    cmd += ["--top-ports", "1000"] if ports in ("", "top") else ["-p", ports]
    cmd.append(address)
    code, out = runner(cmd, timeout)
    services = parse_nmap_xml(out)
    if code != 0 and not services:
        raise RuntimeError("Nmap did not finish successfully")
    cov = {"status": "completed", "method": "nmap -sV --version-light", "services_identified": len(services),
           "skipped_checks": [], "limitations": ["Nmap's version detection is light; it can miss custom builds "
                                                 "and cannot see distribution back-ported fixes."]}
    return nmap_findings(host, services), cov


# ------------------------------------------------------------------ Nuclei

_SEV = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW,
        "info": Severity.INFO}


def parse_nuclei(lines: str, host: str, port: Optional[int]) -> List[Finding]:
    findings: List[Finding] = []
    seen = set()
    for raw in lines.splitlines():
        raw = raw.strip()
        if not raw.startswith("{"):
            continue
        try:
            rec = json.loads(raw)
        except ValueError:
            continue
        info = rec.get("info") or {}
        tid = str(rec.get("template-id") or "template")
        matched = str(rec.get("matched-at") or rec.get("host") or "")
        if (tid, matched) in seen:
            continue
        seen.add((tid, matched))
        cls = info.get("classification") or {}
        cwe = cls.get("cwe-id") or []
        cwe_text = (cwe[0] if isinstance(cwe, list) and cwe else str(cwe or "")).upper()
        if cwe_text and not cwe_text.startswith("CWE-"):
            cwe_text = "CWE-" + cwe_text
        cves = cls.get("cve-id") or []
        desc = (info.get("description") or info.get("name") or tid).strip()
        if cves:
            desc += " (" + ", ".join(cves if isinstance(cves, list) else [str(cves)]) + ")"
        findings.append(Finding(
            host=host, port=port, check_id="NUCLEI-" + tid, title=str(info.get("name") or tid),
            severity=_SEV.get(str(info.get("severity", "info")).lower(), Severity.INFO),
            category="supply_chain" if cves else "misconfig", cwe=cwe_text or "CWE-200", description=desc,
            remediation=str(info.get("remediation") or "Follow the template's reference links and update or "
                            "reconfigure the affected component.").strip(),
            evidence=f"template {tid} matched at {matched}"[:300]))
    return findings


def run_nuclei(host: str, port: Optional[int], url: str, runner: Runner = default_runner,
               timeout: int = 900) -> Tuple[List[Finding], dict]:
    exe = available("nuclei")
    if not exe and runner is default_runner:
        raise RuntimeError("Nuclei is not installed (or not on PATH). Get it from "
                           "https://github.com/projectdiscovery/nuclei")
    cmd = [exe or "nuclei", "-u", url, "-jsonl", "-silent", "-duc", "-rl", "50", "-timeout", "7",
           "-severity", "low,medium,high,critical"]
    code, out = runner(cmd, timeout)
    findings = parse_nuclei(out, host, port)
    if code != 0 and not findings and not out.strip():
        raise RuntimeError("Nuclei did not finish successfully (are its templates installed? run `nuclei -ut`)")
    cov = {"status": "completed", "method": "nuclei community templates (low to critical)",
           "skipped_checks": [], "limitations": ["Only finds what the installed templates describe.",
                                                  "Template matches are leads: verify before reporting."]}
    return findings, cov
