"""Confirm what is really listening on a port by speaking the protocol, instead of trusting the port number.

Every probe is read-only and sends the smallest harmless request (a PING, a version query, a handshake).
A probe never logs in, guesses passwords or reads data.
"""

from __future__ import annotations

import re
import socket
import struct
from dataclasses import dataclass
from typing import Callable, Dict, Optional

Exchange = Callable[[str, int, bytes, float], Optional[bytes]]


@dataclass
class Identity:
    name: str                      # e.g. "Redis"
    detail: str = ""               # version or other evidence, safe to show
    auth_required: Optional[bool] = None  # None = could not tell
    open_access: bool = False      # answered a data-store request without any login


def exchange(addr: str, port: int, payload: bytes, timeout: float = 1.5) -> Optional[bytes]:
    """Connect, optionally send payload, return the first reply (or what the server says first)."""
    try:
        with socket.create_connection((addr, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if payload:
                s.sendall(payload)
            return s.recv(4096)
    except OSError:
        return None


def _redis(addr, port, ex, timeout) -> Optional[Identity]:
    data = ex(addr, port, b"PING\r\n", timeout)
    if not data:
        return None
    text = data.decode("latin-1", "replace")
    if text.startswith("+PONG"):
        return Identity("Redis", "answered PING without a password", False, True)
    if text.startswith("-NOAUTH") or "Authentication required" in text:
        return Identity("Redis", "asks for authentication", True)
    if text.startswith("-DENIED") or text.startswith("-ERR") and "redis" in text.lower():
        return Identity("Redis", "refused the request (protected mode)", True)
    return None


def _memcached(addr, port, ex, timeout) -> Optional[Identity]:
    data = ex(addr, port, b"version\r\n", timeout)
    m = re.match(rb"VERSION ([\w.\-]+)", data or b"")
    return Identity("Memcached", f"version {m.group(1).decode()}, no login required", False, True) if m else None


def _mysql(addr, port, ex, timeout) -> Optional[Identity]:
    data = ex(addr, port, b"", timeout)  # MySQL/MariaDB speak first
    if data and len(data) > 6 and data[4] == 10:
        version = data[5:data.find(b"\x00", 5)].decode("latin-1", "replace")
        if re.match(r"^[\w.\-+~]+$", version):
            return Identity("MySQL/MariaDB", f"version {version}", None)
    return None


def _postgres(addr, port, ex, timeout) -> Optional[Identity]:
    data = ex(addr, port, struct.pack("!II", 8, 80877103), timeout)  # SSLRequest
    if data in (b"S", b"N"):
        return Identity("PostgreSQL", "answered the protocol handshake", None)
    return None


def _mongo(addr, port, ex, timeout) -> Optional[Identity]:
    doc = b"\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00"  # {isMaster: 1}
    body = struct.pack("<i", 0) + b"admin.$cmd\x00" + struct.pack("<ii", 0, -1) + doc
    msg = struct.pack("<iiii", 16 + len(body), 1, 0, 2004) + body
    data = ex(addr, port, msg, timeout)
    if data and len(data) >= 16 and struct.unpack("<i", data[12:16])[0] in (1, 2013):
        return Identity("MongoDB", "answered the protocol handshake without a login (reading data may still "
                                   "need a login)", None)
    return None


def _elastic(addr, port, ex, timeout) -> Optional[Identity]:
    data = ex(addr, port, b"GET / HTTP/1.0\r\nHost: x\r\n\r\n", timeout)
    text = (data or b"").decode("latin-1", "replace")
    if "cluster_name" in text or "You Know, for Search" in text:
        m = re.search(r'"number"\s*:\s*"([\d.]+)"', text)
        return Identity("Elasticsearch", (f"version {m.group(1)}, " if m else "") + "answered without a login",
                        False, True)
    if text.startswith("HTTP/") and " 401" in text.split("\r\n", 1)[0] and "elastic" in text.lower():
        return Identity("Elasticsearch", "asks for authentication", True)
    return None


def _rdp(addr, port, ex, timeout) -> Optional[Identity]:
    req = bytes.fromhex("0300000b06e00000000000")  # minimal X.224 connection request
    data = ex(addr, port, req, timeout)
    if data and data[:2] == b"\x03\x00" and len(data) >= 7 and data[5] == 0xD0:
        return Identity("Remote Desktop (RDP)", "answered the RDP handshake", None)
    return None


def _smb(addr, port, ex, timeout) -> Optional[Identity]:
    # SMB2 negotiate is long; a closed or non-SMB service just won't answer with the SMB magic.
    pkt = bytes.fromhex("000000" "2f") + b"\xfeSMB" + b"\x40\x00" + b"\x00" * 6 + b"\x00" * 50
    data = ex(addr, port, pkt, timeout)
    if data and (b"\xfeSMB" in data[:8] or b"\xffSMB" in data[:8]):
        return Identity("SMB (Windows file sharing)", "answered the SMB handshake", None)
    return None


PROBES: Dict[int, Callable] = {6379: _redis, 11211: _memcached, 3306: _mysql, 5432: _postgres,
                               27017: _mongo, 9200: _elastic, 3389: _rdp, 445: _smb}
EXPECTED = {6379: "Redis", 11211: "Memcached", 3306: "MySQL/MariaDB", 5432: "PostgreSQL",
            27017: "MongoDB", 9200: "Elasticsearch", 3389: "Remote Desktop (RDP)",
            445: "SMB (Windows file sharing)"}


def identify(addr: str, port: int, timeout: float = 1.5, ex: Exchange = exchange) -> Optional[Identity]:
    probe = PROBES.get(port)
    return probe(addr, port, ex, timeout) if probe else None
