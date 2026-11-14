"""Scan orchestration: ports -> fingerprint -> service/TLS/web checks."""

from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable, List, Optional

from . import identify
from .models import HostResult, PortInfo
from .portscan import probe_port, scan_ports, service_findings
from .scope import Target
from .tlschecks import check_tls
from .versions import version_findings
from .webchecks import run_web_checks


@dataclass
class ScanConfig:
    ports: List[int]
    timeout: float = 1.0
    threads: int = 200
    web: bool = True


def _log(msg: str, quiet: bool) -> None:
    if not quiet:
        print(msg, file=sys.stderr, flush=True)


def scan_host(target: Target, cfg: ScanConfig, quiet: bool = False) -> HostResult:
    result = HostResult(host=target.label, address=target.address)
    open_ports = scan_ports(target.address, cfg.ports, cfg.timeout, cfg.threads)
    _log(f"[*] {target.label}: {len(open_ports)} open port(s)", quiet)
    if not open_ports:
        return result

    with ThreadPoolExecutor(max_workers=min(16, len(open_ports))) as pool:
        result.ports = list(pool.map(lambda p: probe_port(target.address, p, cfg.timeout), open_ports))

    https_available = any(p.http and p.tls for p in result.ports)

    for info in result.ports:
        ident = identify.identify(target.address, info.port, max(cfg.timeout, 1.5))
        if ident is not None:
            info.service = ident.name
            info.banner = info.banner or f"{ident.name}: {ident.detail}"
            result.extend(version_findings(target.label, info.port, ident.name + " " + ident.detail))
        result.extend(service_findings(target.label, info, target.address, ident,
                                       probed=info.port in identify.PROBES))
        result.extend(version_findings(target.label, info.port, info.banner))

        if info.tls:
            result.extend(check_tls(target.label, target.address, info.port,
                                    timeout=max(cfg.timeout, 3.0)))
        if cfg.web and info.http:
            _log(f"[*] {target.label}:{info.port}: running web checks", quiet)
            result.extend(run_web_checks(
                target.label, target.address, info.port, info.tls,
                timeout=max(cfg.timeout, 4.0), https_available=https_available))
    return result
