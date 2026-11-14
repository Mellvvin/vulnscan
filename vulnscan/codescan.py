"""Scan a project folder (your own code) for leaked secrets and vulnerable dependencies.

Secrets are never copied into results in full: only the first characters are kept.  Dependency
versions are looked up on OSV.dev; if the network is down the dependencies are reported as unchecked.
"""

from __future__ import annotations

import json
import math
import os
import re
import subprocess
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from .cache import Cache
from .cvss import severity_label
from .http import Http
from .models import Finding, Severity
from . import osv

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "env", "dist", "build", "__pycache__", ".next", ".nuxt",
             "vendor", "target", ".idea", ".vscode", "coverage", ".pytest_cache", "site-packages", "bower_components"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".pdf", ".zip", ".gz", ".tar", ".woff",
            ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".exe", ".dll", ".so", ".pyc", ".lock", ".map", ".min.js"}
MAX_FILE = 1_000_000
MAX_FILES = 20000

# name, regex, severity, group holding the secret (0 = whole match)
PATTERNS: List[Tuple[str, "re.Pattern[str]", Severity, int]] = [
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), Severity.CRITICAL, 0),
    ("AWS access key", re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), Severity.CRITICAL, 1),
    ("Stripe live key", re.compile(r"\b([sr]k_live_[0-9a-zA-Z]{20,})"), Severity.CRITICAL, 1),
    ("GitHub token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})"), Severity.CRITICAL, 1),
    ("Slack token", re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{20,})"), Severity.HIGH, 1),
    ("Google API key", re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b"), Severity.HIGH, 1),
    ("M-Pesa / Daraja credential",
     re.compile(r"""(?i)(?:mpesa|daraja|consumer[_-]?(?:key|secret)|pass[_-]?key|initiator[_-]?(?:password|name)|"""
                r"""security[_-]?credential)\w*["']?\s*[:=]\s*["']([A-Za-z0-9+/=_\-]{16,})["']"""), Severity.CRITICAL, 1),
    ("Database URL with password",
     re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s/@\"']+:([^@\s\"']{3,})@"),
     Severity.HIGH, 1),
    ("Hard-coded secret",
     re.compile(r"""(?i)\b[\w.-]*(?:api[_-]?key|secret|passw(?:or)?d|passwd|token|auth[_-]?key)[\w.-]*["']?\s*[:=]\s*"""
                r"""["']([^"'\s]{10,})["']"""), Severity.MEDIUM, 1),
]
PLACEHOLDER = re.compile(r"(?i)(your[_-]|example|sample|changeme|change_me|placeholder|xxxx|<.*>|\$\{|\{\{|"
                         r"process\.env|os\.environ|getenv|dummy|test|todo|secret_here|\*{3,}|^\.\.\.)")
ENV_FILE = re.compile(r"^\.env(\..+)?$")
ENV_SAFE = {".env.example", ".env.sample", ".env.template", ".env.dist"}


def redact(value: str) -> str:
    return value[:4] + "…" + f"({len(value)} chars)" if len(value) > 4 else "…"


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def scan_text(text: str, rel: str) -> List[dict]:
    """Return raw hits [{name, severity, line, secret}] for one file's text."""
    hits = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if len(line) > 1000:
            continue
        for name, rx, sev, grp in PATTERNS:
            m = rx.search(line)
            if not m:
                continue
            secret = m.group(grp)
            if name == "Hard-coded secret":
                if PLACEHOLDER.search(secret) or entropy(secret) < 3.0:
                    continue
            elif name != "Private key" and PLACEHOLDER.search(secret):
                continue
            hits.append({"name": name, "severity": sev, "line": lineno, "secret": secret, "file": rel})
            break
    return hits


def _walk(root: Path) -> Iterable[Path]:
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            p = Path(dirpath) / name
            if p.suffix.lower() in SKIP_EXT or name.endswith(".min.js"):
                continue
            count += 1
            if count > MAX_FILES:
                return
            yield p


def _git(root: Path, *args: str, timeout: int = 60) -> Optional[str]:
    try:
        proc = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, timeout=timeout,
                              errors="replace")
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.stdout if proc.returncode == 0 else None


def _finding(label: str, cid: str, title: str, sev: Severity, cwe: str, desc: str, fix: str,
             evidence: str, cat: str = "misconfig") -> Finding:
    return Finding(host=label, port=None, check_id=cid, title=title, severity=sev, category=cat, cwe=cwe,
                   description=desc, remediation=fix, evidence=evidence)


def scan_secrets(root: Path, label: str, history: bool = True) -> Tuple[List[Finding], List[str]]:
    findings: List[Finding] = []
    notes: List[str] = []
    seen_now = set()
    is_git = (root / ".git").exists()
    tracked = set((_git(root, "ls-files") or "").splitlines()) if is_git else set()
    ignored_text = ""
    try:
        ignored_text = (root / ".gitignore").read_text(encoding="utf-8", errors="replace")
    except OSError:
        pass

    for path in _walk(root):
        rel = path.relative_to(root).as_posix()
        if ENV_FILE.match(path.name) and path.name not in ENV_SAFE:
            if rel in tracked:
                findings.append(_finding(label, "CODE-ENV-TRACKED", f"{rel} is committed to git", Severity.HIGH,
                                         "CWE-540", "An environment file normally holds passwords and API keys. "
                                         "Once committed it stays in the git history even if deleted later.",
                                         "Remove it from git (git rm --cached), add it to .gitignore, and change "
                                         "every secret that was inside it.", f"{rel} is tracked by git"))
            elif is_git and ".env" not in ignored_text:
                findings.append(_finding(label, "CODE-ENV-UNIGNORED", f"{rel} is not listed in .gitignore",
                                         Severity.MEDIUM, "CWE-540", "An environment file holds secrets and one "
                                         "careless `git add .` would publish them.", "Add .env to .gitignore.",
                                         f"{rel} exists and .gitignore has no .env rule"))
        try:
            if path.stat().st_size > MAX_FILE:
                continue
            data = path.read_bytes()
        except OSError:
            continue
        if b"\x00" in data[:2048]:
            continue
        for hit in scan_text(data.decode("utf-8", "replace"), rel):
            key = (hit["name"], rel, hit["secret"])
            if key in seen_now:
                continue
            seen_now.add(key)
            findings.append(_finding(
                label, "CODE-SECRET", f"{hit['name']} in {rel}", hit["severity"], "CWE-798",
                "A credential is written into the source code. Anyone who can read the code, including "
                "everyone with access to the repository, can use it.",
                "Rotate (replace) the credential now, then load it from an environment variable or secret "
                "manager instead of the code.", f"{rel}:{hit['line']}  {hit['name']}  {redact(hit['secret'])}"))

    if history and is_git:
        out = _git(root, "log", "--all", "-p", "--no-color", "--max-count=500", timeout=120)
        if out is None:
            notes.append("git history could not be read")
        else:
            commit, current = "", ""
            seen_hist = set()
            for line in out.splitlines():
                if line.startswith("commit "):
                    commit = line[7:15]
                elif line.startswith("+++ b/"):
                    current = line[6:]
                elif line.startswith("+") and not line.startswith("+++"):
                    for hit in scan_text(line[1:], current):
                        if hit["name"] == "Hard-coded secret":
                            continue  # history scan only uses high-confidence patterns
                        key = (hit["name"], hit["secret"])
                        if key in seen_hist or (hit["name"], current, hit["secret"]) in seen_now:
                            continue
                        seen_hist.add(key)
                        findings.append(_finding(
                            label, "CODE-SECRET-HISTORY", f"{hit['name']} in git history ({current})",
                            hit["severity"], "CWE-798",
                            "A credential was committed at some point. Even if the current code no longer "
                            "contains it, it is still in the history and anyone with the repository can read it.",
                            "Treat it as leaked: rotate the credential. Removing it from history is optional and "
                            "does not make it safe again.", f"commit {commit}  {current}  {redact(hit['secret'])}"))
    return findings, notes


# ---------------------------------------------------------------- dependencies

def parse_dependencies(root: Path) -> Tuple[List[Tuple[str, str, str, str]], List[str]]:
    """Return ([(ecosystem, name, version, source file)], notes about what could not be read)."""
    deps: List[Tuple[str, str, str, str]] = []
    notes: List[str] = []
    seen = set()

    def add(eco, name, ver, src):
        if name and ver and (eco, name, ver) not in seen:
            seen.add((eco, name, ver))
            deps.append((eco, name, ver, src))

    for path in _walk(root):
        rel = path.relative_to(root).as_posix()
        name = path.name
        try:
            if name == "package-lock.json":
                doc = json.loads(path.read_text(encoding="utf-8"))
                for key, meta in (doc.get("packages") or {}).items():
                    if key and "node_modules/" in key and isinstance(meta, dict):
                        add("npm", key.rsplit("node_modules/", 1)[1], str(meta.get("version", "")), rel)

                def walk(d):
                    for n, meta in (d or {}).items():
                        add("npm", n, str(meta.get("version", "")), rel)
                        walk(meta.get("dependencies"))
                if "packages" not in doc:
                    walk(doc.get("dependencies"))
            elif name == "Pipfile.lock":
                doc = json.loads(path.read_text(encoding="utf-8"))
                for section in ("default", "develop"):
                    for n, meta in (doc.get(section) or {}).items():
                        add("PyPI", n, str(meta.get("version", "")).lstrip("="), rel)
            elif name.startswith("requirements") and name.endswith(".txt"):
                for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                    line = line.split("#", 1)[0].strip()
                    m = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9_.\-+!]+)$", line)
                    if m:
                        add("PyPI", m.group(1), m.group(2), rel)
                    elif line and not line.startswith(("-", "git+", "http")):
                        notes.append(f"{rel}: '{line}' is not pinned to one version, so it was not checked")
            elif name == "package.json":
                if not (path.parent / "package-lock.json").exists():
                    notes.append(f"{rel}: no package-lock.json next to it, so exact versions are unknown and "
                                 "npm dependencies were not checked (run `npm install` to create it)")
        except (OSError, ValueError, AttributeError):
            notes.append(f"{rel}: could not be read")
    return deps, notes


_SEV = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}


def scan_dependencies(root: Path, label: str, http: Http, cache: Optional[Cache] = None,
                      log: Callable[[str], None] = lambda m: None) -> Tuple[List[Finding], List[str], int]:
    deps, notes = parse_dependencies(root)
    if not deps:
        return [], notes, 0
    keys = [(e, n, v) for e, n, v, _ in deps]
    log(f"looking up {len(keys)} package versions on OSV.dev")
    matches, failed = osv.query_batch(http, keys, log)
    if failed:
        notes.append(f"{len(failed)} package lookups failed (network); those packages are unchecked")
    refs = {}
    for k in keys:
        for v in matches.get(k, []):
            refs[v["id"]] = v.get("modified", "")
    records, bad = osv.fetch_records(http, cache or Cache(), refs, log=log) if refs else ({}, [])
    if bad:
        notes.append(f"{len(bad)} vulnerability records could not be downloaded; severity may be understated")
    source = {(e, n, v): s for e, n, v, s in deps}
    findings: List[Finding] = []
    for key in keys:
        vs = [records[v["id"]] for v in matches.get(key, []) if v["id"] in records and not records[v["id"]].withdrawn]
        if not vs:
            continue
        eco, name, ver = key
        sev = Severity.MEDIUM
        scores = [v.cvss_score for v in vs if v.cvss_score is not None]
        texts = [_SEV[v.severity_text] for v in vs if v.severity_text in _SEV]
        if scores:
            sev = _SEV.get(severity_label(max(scores)) or "", Severity.MEDIUM)
        elif texts:
            sev = max(texts)
        fixes = [f for f in (osv.best_fix(v, name, ver, eco) for v in vs) if f]
        fix_to = max(fixes, key=lambda s: [int(x) if x.isdigit() else 0 for x in re.split(r"\D+", s)]) if fixes else ""
        ids = ", ".join(v.canonical_id for v in vs[:6]) + (" …" if len(vs) > 6 else "")
        findings.append(Finding(
            host=label, port=None, check_id="CODE-DEP-VULN", title=f"{name} {ver} has {len(vs)} known "
            f"vulnerabilit{'y' if len(vs) == 1 else 'ies'}", severity=sev, category="supply_chain",
            cwe="CWE-1104", description=f"The project uses {name} {ver} ({eco}), which matches published "
            f"security advisories: {ids}. {vs[0].summary[:200]}".strip(),
            remediation=(f"Upgrade {name} to {fix_to} or later and re-test." if fix_to else
                         f"Check the advisories for {name}; no fixed version was published yet."),
            evidence=f"{source[key]}: {eco}:{name}@{ver}"))
    return findings, notes, len(keys)


def run_codescan(root: Path, http: Http, cache: Optional[Cache] = None, history: bool = True,
                 log: Callable[[str], None] = lambda m: None) -> Tuple[List[Finding], dict]:
    root = Path(root).resolve()
    if not root.is_dir():
        raise NotADirectoryError(str(root))
    label = root.name
    log(f"scanning {root} for secrets")
    secrets, notes1 = scan_secrets(root, label, history)
    deps, notes2, checked = scan_dependencies(root, label, http, cache, log)
    notes = notes1 + notes2
    coverage = {"status": "completed" if not notes else "incomplete", "folder": str(root),
                "dependencies_checked": checked, "skipped_checks": notes,
                "method": "pattern search over files and recent git history; dependency versions matched "
                          "against OSV.dev",
                "limitations": ["This finds known secret formats and known-vulnerable package versions. It "
                                "does not review your own code logic (pricing, access control).",
                                "Only the latest 500 commits of git history are searched."]}
    return secrets + deps, coverage
