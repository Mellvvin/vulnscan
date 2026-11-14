"""Client engagements: one folder per client holding scope, authorization, scan runs, the checklist
state and your own notes and fix offers.

Everything is plain JSON on disk (``engagements/<slug>/engagement.json`` plus ``runs/<id>/results.json``)
so it can be backed up, diffed and inspected without this tool.  Client data must never be committed:
the default folder is ignored by git.

The authorization guard lives here.  ``scope.py`` refuses public targets unless ``--allow-public`` is
given; an engagement only turns that on when the target is in the recorded scope AND a signed, unexpired
authorization is on file.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import tempfile
import threading
import time
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from . import checklist, explain
from .http import Http
from .models import Finding
from .output import write_json
from .owasp import DEFAULT_EDITION
from .portscan import parse_ports
from .scanner import ScanConfig, scan_host
from .scope import ScopeError, Target, expand_targets

FINDING_STATUSES = ("open", "accepted-risk", "fixed", "false-positive")
COUNTED_STATUSES = ("open", "accepted-risk")
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,59}$")
HOST_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")

_LOCK = threading.RLock()


class EngagementError(Exception):
    pass


def default_root() -> Path:
    return Path(os.environ.get("VULNSCAN_ENGAGEMENTS_DIR") or "engagements")


def slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:60].strip("-")
    if not slug:
        raise EngagementError("the client name must contain letters or digits")
    return slug


def normalize_scope_entry(raw: str) -> str:
    """Reduce a URL, host:port or CIDR to the bare host / network the scanner takes."""
    text = (raw or "").strip().lower()
    if not text:
        raise EngagementError("empty scope entry")
    try:
        return str(ipaddress.ip_network(text, strict=False)) if "/" in text else str(ipaddress.ip_address(text))
    except ValueError:
        pass
    host = urlsplit(text if "://" in text else "//" + text).hostname or ""
    host = host.rstrip(".")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if not HOST_RE.match(host):
        raise EngagementError(f"'{raw}' is not a valid host name, IP address or CIDR range")
    return host


def _is_ip_or_net(entry: str) -> bool:
    try:
        ipaddress.ip_network(entry, strict=False)
        return True
    except ValueError:
        return False


def _parse_day(value: str, what: str) -> date:
    try:
        return date.fromisoformat(value)
    except (TypeError, ValueError):
        raise EngagementError(f"{what} must be a date like 2026-11-08") from None


def parse_price(value) -> Optional[float]:
    if value is None or value == "":
        return None
    try:
        price = float(str(value).replace(",", "").strip())
    except (TypeError, ValueError):
        raise EngagementError(f"'{value}' is not a price") from None
    if price < 0 or price != price or price == float("inf"):
        raise EngagementError("a price cannot be negative")
    return round(price, 2)


def finding_key(f: dict) -> str:
    return f"{f.get('host', '')}|{f.get('port') or ''}|{f.get('check_id', '')}"


def list_engagements(root: Optional[Path] = None) -> List[dict]:
    root = Path(root) if root else default_root()
    out = []
    if root.is_dir():
        for child in sorted(root.iterdir()):
            file = child / "engagement.json"
            if SLUG_RE.match(child.name) and file.is_file():
                try:
                    data = json.loads(file.read_text(encoding="utf-8"))
                    out.append({"slug": child.name, "client": data.get("client", child.name),
                                "created": data.get("created", ""), "scope": data.get("scope", [])})
                except (OSError, ValueError):
                    continue
    return out


class Engagement:
    def __init__(self, directory: Path, data: dict) -> None:
        self.dir = Path(directory)
        self.data = data

    # ------------------------------------------------------------------ create / load / save

    @classmethod
    def create(cls, client: str, scope: Sequence[str], root: Optional[Path] = None, contact: str = "",
               email_domains: Sequence[str] = (), currency: str = "USD") -> "Engagement":
        root = Path(root) if root else default_root()
        client = (client or "").strip()
        if not client:
            raise EngagementError("a client name is required")
        entries: List[str] = []
        for raw in scope:
            norm = normalize_scope_entry(raw)
            if norm not in entries:
                entries.append(norm)
        if not entries:
            raise EngagementError("add at least one target to the scope (a domain, IP address or CIDR range)")
        domains = []
        for raw in email_domains:
            norm = normalize_scope_entry(raw)
            if _is_ip_or_net(norm):
                raise EngagementError(f"'{raw}' is an IP address; email checks need a domain name")
            if norm not in domains:
                domains.append(norm)
        slug = slugify(client)
        directory = root / slug
        if (directory / "engagement.json").exists():
            raise EngagementError(f"an engagement named '{slug}' already exists in {root}")
        data = {"version": 1, "client": client, "slug": slug, "contact": contact.strip(),
                "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "owasp_edition": DEFAULT_EDITION, "currency": (currency or "USD").strip().upper()[:6], "scope": entries, "email_domains": domains,
                "authorization": None, "checklist": checklist.blank_state(), "finding_notes": {},
                "runs": [], "log": []}
        eng = cls(directory, data)
        eng.log("engagement created")
        eng.save()
        return eng

    @classmethod
    def load(cls, slug: str, root: Optional[Path] = None) -> "Engagement":
        root = Path(root) if root else default_root()
        if not SLUG_RE.match(slug or ""):
            raise EngagementError(f"'{slug}' is not a valid engagement name")
        file = root / slug / "engagement.json"
        try:
            data = json.loads(file.read_text(encoding="utf-8"))
        except OSError:
            raise EngagementError(f"no engagement '{slug}' in {root}") from None
        except ValueError as exc:
            raise EngagementError(f"{file} is not valid JSON: {exc}") from None
        state = checklist.blank_state()
        state.update(data.get("checklist") or {})
        data["checklist"] = state
        data.setdefault("finding_notes", {})
        data.setdefault("runs", [])
        data.setdefault("log", [])
        data.setdefault("email_domains", [])
        return cls(root / slug, data)

    def save(self) -> None:
        with _LOCK:
            self.dir.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=str(self.dir), prefix=".engagement-", suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(self.data, fh, indent=2)
                    fh.write("\n")
                os.replace(tmp, self.dir / "engagement.json")
            except BaseException:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise

    def log(self, message: str) -> None:
        self.data["log"].append({"at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                                 "event": message})

    @property
    def slug(self) -> str:
        return self.data["slug"]

    @property
    def client(self) -> str:
        return self.data["client"]

    # ------------------------------------------------------------------ scope and authorization

    def set_authorization(self, signer: str, signed_on: str, reference: str = "",
                          expires: Optional[str] = None) -> None:
        signer = (signer or "").strip()
        if not signer:
            raise EngagementError("who signed the authorization letter?")
        signed = _parse_day(signed_on, "the signing date")
        if signed > date.today():
            raise EngagementError("the signing date is in the future")
        end = _parse_day(expires, "the expiry date") if expires else None
        if end and end < signed:
            raise EngagementError("the expiry date is before the signing date")
        with _LOCK:
            self.data["authorization"] = {"signer": signer, "signed_on": signed.isoformat(),
                                          "reference": (reference or "").strip(),
                                          "expires": end.isoformat() if end else None}
            self.log(f"authorization recorded: signed by {signer} on {signed.isoformat()}")
            self.save()

    def authorization_problem(self, today: Optional[date] = None) -> Optional[str]:
        auth = self.data.get("authorization")
        if not auth:
            return ("no signed authorization is on file for this client. Get the signed letter first, then "
                    "record it with: vulnscan engage authorize " + self.slug + " --signer NAME --date YYYY-MM-DD")
        today = today or date.today()
        if auth.get("expires") and date.fromisoformat(auth["expires"]) < today:
            return f"the authorization expired on {auth['expires']}; get it renewed and record the new letter"
        return None

    def scope_entries(self, subset: Optional[Sequence[str]] = None) -> List[str]:
        entries = list(self.data["scope"])
        if not subset:
            return entries
        chosen = []
        for raw in subset:
            norm = normalize_scope_entry(raw)
            if norm not in entries:
                raise EngagementError(f"'{raw}' is not in this engagement's scope ({', '.join(entries)})")
            chosen.append(norm)
        return chosen

    def plan_scan(self, subset: Optional[Sequence[str]] = None,
                  today: Optional[date] = None) -> Tuple[List[Target], bool]:
        """Resolve scan targets and decide whether public addresses are permitted.

        Private and loopback targets (a lab, the client's LAN from on site) need no letter.  Anything
        publicly routable needs the target to be in scope and an unexpired signed authorization.
        """
        entries = self.scope_entries(subset)
        try:
            targets = expand_targets(entries)
        except (ScopeError, OSError, ValueError) as exc:
            raise EngagementError(str(exc)) from None
        public = [t for t in targets if ipaddress.ip_address(t.address).is_global]
        if public:
            problem = self.authorization_problem(today)
            if problem:
                names = ", ".join(t.label for t in public[:3])
                raise EngagementError(f"refusing to scan {names}: {problem}")
        return targets, bool(public)

    def hostnames(self) -> List[str]:
        return [e for e in self.data["scope"] if not _is_ip_or_net(e)]

    def email_domains(self) -> List[str]:
        return list(self.data.get("email_domains") or self.hostnames())

    # ------------------------------------------------------------------ runs

    def _new_run_dir(self, kind: str, started: datetime) -> Tuple[str, Path]:
        base = started.strftime("%Y%m%d-%H%M%S") + "-" + kind
        run_id, n = base, 1
        while (self.dir / "runs" / run_id).exists():
            n += 1
            run_id = f"{base}-{n}"
        path = self.dir / "runs" / run_id
        path.mkdir(parents=True)
        return run_id, path

    def _record_run(self, kind: str, run_id: str, started: datetime, targets: List[str],
                    findings: List[Finding], duration: float) -> dict:
        counts: Dict[str, int] = {}
        for f in findings:
            counts[f.severity.name] = counts.get(f.severity.name, 0) + 1
        run = {"id": run_id, "kind": kind, "started": started.isoformat(timespec="seconds"),
               "duration_seconds": round(duration, 2), "targets": targets,
               "findings": len(findings), "by_severity": counts}
        with _LOCK:
            self.data["runs"].append(run)
            self.log(f"{kind} run {run_id}: {len(findings)} finding(s)")
            self.save()
        return run

    def run_scan(self, ports: str = "top", timeout: float = 1.0, threads: int = 200, web: bool = True,
                 subset: Optional[Sequence[str]] = None, log: Callable[[str], None] = lambda m: None) -> dict:
        targets, public = self.plan_scan(subset)
        try:
            cfg = ScanConfig(ports=parse_ports(ports), timeout=timeout, threads=threads, web=web)
        except ValueError as exc:
            raise EngagementError(str(exc)) from None
        started = datetime.now(timezone.utc)
        t0 = time.monotonic()
        hosts = []
        for target in targets:
            log(f"scanning {target.label} ({len(cfg.ports)} ports)")
            hosts.append(scan_host(target, cfg, quiet=True))
        findings = [f for h in hosts for f in h.findings]
        run_id, path = self._new_run_dir("scan", started)
        skipped = ["UDP services are not tested", "TCP ports outside the selected port set are not tested"]
        if not web:
            skipped.append("HTTP(S) application checks disabled")
        coverage = {"network": {
            "status": "completed", "scanner_vantage": "this machine", "method": "TCP connect",
            "requested_ports": ports, "selected_tcp_ports_per_host": len(cfg.ports),
            "open_tcp_ports": sum(len(h.ports) for h in hosts),
            "web_checks": "enabled" if web else "disabled", "skipped_checks": skipped,
            "limitations": ["Reachability is confirmed only from this scanner's vantage point.",
                            "A public-routable target does not prove access from every network."]}}
        meta = {"started": started.isoformat(timespec="seconds"),
                "duration_seconds": round(time.monotonic() - t0, 2),
                "targets": [t.label for t in targets], "ports_per_host": len(cfg.ports),
                "hosts_with_open_ports": sum(1 for h in hosts if h.ports), "mode": "scan",
                "engagement": self.slug, "public_targets_authorized": public}
        write_json(str(path / "results.json"), meta, hosts, findings, self.data["owasp_edition"],
                   {"coverage": coverage})
        return self._record_run("scan", run_id, started, [t.label for t in targets], findings,
                                time.monotonic() - t0)

    def run_dns(self, http: Optional[Http] = None, log: Callable[[str], None] = lambda m: None) -> dict:
        from .dnschecks import run_dns_checks
        domains = self.email_domains()
        if not domains:
            raise EngagementError("no domain names to check; add a domain to the scope or use --email-domain")
        started = datetime.now(timezone.utc)
        t0 = time.monotonic()
        findings, coverage = run_dns_checks(domains, http or Http(timeout=15, retries=1), log)
        run_id, path = self._new_run_dir("dns", started)
        meta = {"started": started.isoformat(timespec="seconds"),
                "duration_seconds": round(time.monotonic() - t0, 2), "targets": domains, "mode": "dns",
                "engagement": self.slug}
        write_json(str(path / "results.json"), meta, [], findings, self.data["owasp_edition"],
                   {"coverage": {"dns": coverage}})
        return self._record_run("dns", run_id, started, domains, findings, time.monotonic() - t0)

    def load_docs(self) -> List[dict]:
        """Result documents of every run, newest first (so newer findings win when merged)."""
        docs = []
        for run in reversed(self.data["runs"]):
            file = self.dir / "runs" / run["id"] / "results.json"
            try:
                docs.append(json.loads(file.read_text(encoding="utf-8")))
            except (OSError, ValueError):
                continue
        return docs

    # ------------------------------------------------------------------ findings, notes, checklist

    def findings(self) -> List[dict]:
        """Every distinct finding across runs, each with its ``key`` and your notes attached."""
        seen = set()
        out = []
        for doc in self.load_docs():
            for f in doc.get("findings", []):
                key = finding_key(f)
                if key in seen:
                    continue
                seen.add(key)
                notes = self.data["finding_notes"].get(key) or {}
                item = dict(f)
                item["key"] = key
                item["note"] = notes.get("note", "")
                item["fix"] = notes.get("fix", "")
                item["price"] = notes.get("price")
                item["status"] = notes.get("status", "open")
                item["suggest_note"], item["suggest_fix"] = explain.suggest(f)
                out.append(item)
        return out

    def set_finding(self, key: str, note: Optional[str] = None, fix: Optional[str] = None,
                    price=None, status: Optional[str] = None, price_given: bool = False) -> dict:
        if key not in {finding_key(f) for f in self.findings()}:
            raise EngagementError(f"no finding with key '{key}' in this engagement")
        if status is not None and status not in FINDING_STATUSES:
            raise EngagementError(f"status must be one of: {', '.join(FINDING_STATUSES)}")
        with _LOCK:
            entry = self.data["finding_notes"].setdefault(key, {})
            if note is not None:
                entry["note"] = note.strip()
            if fix is not None:
                entry["fix"] = fix.strip()
            if price_given or price is not None:
                entry["price"] = parse_price(price)
            if status is not None:
                entry["status"] = status
            self.log(f"finding updated: {key}")
            self.save()
            return dict(entry)

    def set_check(self, item_id: str, status: Optional[str] = None, note: Optional[str] = None,
                  fix: Optional[str] = None, price=None, price_given: bool = False) -> dict:
        if item_id not in checklist.BY_ID:
            raise EngagementError(f"unknown checklist item '{item_id}'")
        if status is not None and status not in checklist.STATUSES:
            raise EngagementError(f"status must be one of: {', '.join(checklist.STATUSES)}")
        with _LOCK:
            entry = self.data["checklist"].setdefault(item_id, {"status": "todo", "note": "", "fix": "",
                                                                  "price": None})
            if status is not None:
                entry["status"] = status
            if note is not None:
                entry["note"] = note.strip()
            if fix is not None:
                entry["fix"] = fix.strip()
            if price_given or price is not None:
                entry["price"] = parse_price(price)
            self.log(f"checklist updated: {item_id} -> {entry['status']}")
            self.save()
            return dict(entry)

    def counted_findings(self) -> List[dict]:
        return [f for f in self.findings() if f["status"] in COUNTED_STATUSES]

    def checklist_rows(self) -> List[dict]:
        ran = {r["kind"] for r in self.data["runs"]}
        return checklist.evaluate(self.data["checklist"], [f["check_id"] for f in self.counted_findings()], ran)

    def offer_total(self) -> float:
        total = 0.0
        for f in self.counted_findings():
            total += f["price"] or 0.0
        for row in self.checklist_rows():
            if row["effective"] == "fail":
                total += row["price"] or 0.0
        return round(total, 2)
