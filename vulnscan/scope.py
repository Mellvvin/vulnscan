"""Target parsing and the authorization guard.

Scanning systems you do not own or have written permission to test is illegal
in most jurisdictions.  By default this tool refuses any target that is not
loopback, private (RFC 1918), or link-local.  Scanning anything else requires
the explicit --allow-public flag.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from dataclasses import dataclass
from typing import Iterable, List

MAX_HOSTS = 1024


class ScopeError(Exception):
    pass


@dataclass(frozen=True)
class Target:
    label: str  # what the user typed / hostname, used in reports
    address: str  # IPv4/IPv6 address we connect to

    @property
    def is_hostname(self) -> bool:
        return self.label != self.address


def classify_exposure(address: str) -> dict:
    """Classify the tested destination address, not the service's bind address.

    A successful connection proves reachability only from this scanner's vantage point.
    It does not prove that a service is reachable by every host in that address class.
    """
    ip = ipaddress.ip_address(address)
    if ip.is_loopback:
        scope, basis = "localhost", f"{ip} is a loopback address"
    elif ip.is_global:
        scope, basis = "public", f"{ip} is globally routable"
    else:
        private_ranges = (ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"),
                          ipaddress.ip_network("192.168.0.0/16"), ipaddress.ip_network("fc00::/7"))
        is_lan = ip.is_link_local or any(ip.version == net.version and ip in net for net in private_ranges)
        if is_lan:
            scope, basis = "lan", f"{ip} is private or link-local"
        else:
            scope, basis = "special", f"{ip} is a special-use/non-global address"
    return {"scope": scope, "address": str(ip), "basis": basis}


def _read_target_file(path: str) -> List[str]:
    specs: List[str] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if line:
                specs.append(line)
    return specs


def expand_targets(specs: Iterable[str], max_hosts: int = MAX_HOSTS) -> List[Target]:
    """Expand IPs, CIDR ranges, hostnames and target files into Targets."""
    flat: List[str] = []
    for spec in specs:
        if os.path.isfile(spec):
            flat.extend(_read_target_file(spec))
        else:
            flat.append(spec)

    targets: List[Target] = []
    seen = set()
    for spec in flat:
        try:
            net = ipaddress.ip_network(spec, strict=False)
        except ValueError:
            try:
                address = socket.gethostbyname(spec)
            except OSError as exc:
                raise ScopeError(f"cannot resolve target '{spec}': {exc}") from exc
            candidates = [Target(spec, address)]
        else:
            # Check the size *before* expanding so a typo like /8 cannot exhaust memory.
            if net.num_addresses > max_hosts + 2:
                raise ScopeError(
                    f"'{spec}' covers {net.num_addresses} addresses; the limit is "
                    f"{max_hosts} hosts per run, so narrow the range"
                )
            hosts = [net.network_address] if net.num_addresses == 1 else list(net.hosts())
            candidates = [Target(str(h), str(h)) for h in hosts]

        for tgt in candidates:
            if tgt.address not in seen:
                seen.add(tgt.address)
                targets.append(tgt)
        if len(targets) > max_hosts:
            raise ScopeError(
                f"target list expands to more than {max_hosts} hosts; narrow the range"
            )
    if not targets:
        raise ScopeError("no targets to scan")
    return targets


def check_authorization(targets: Iterable[Target], allow_public: bool) -> List[Target]:
    """Return targets that are publicly routable (empty list means all in lab scope).

    Raises ScopeError if public targets are present and allow_public is False.
    """
    public = [t for t in targets if ipaddress.ip_address(t.address).is_global]
    if public and not allow_public:
        sample = ", ".join(t.label for t in public[:3])
        more = f" (+{len(public) - 3} more)" if len(public) > 3 else ""
        raise ScopeError(
            f"refusing to scan publicly routable target(s): {sample}{more}.\n"
            "vulnscan is intended for loopback/private lab ranges. If you have "
            "written authorization to test these systems, re-run with --allow-public."
        )
    return public
