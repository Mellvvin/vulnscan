"""Threaded TCP connect scanning, service fingerprinting and risky-service checks."""

from __future__ import annotations

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple

from .models import Finding, PortInfo, Severity
from .scope import classify_exposure

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993, 995,
    1433, 1521, 2049, 3000, 3306, 3389, 5000, 5432, 5900, 5985, 6379, 8000, 8008,
    8080, 8443, 8888, 9200, 11211, 27017,
]

COMMON_SERVICES: Dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    443: "https", 445: "smb", 465: "smtps", 587: "submission", 993: "imaps",
    995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5900: "vnc", 5985: "winrm", 6379: "redis",
    9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
    8080: "http-alt", 8443: "https-alt",
}

KNOWN_TLS_PORTS = {443, 465, 993, 995, 8443, 9443}

HTTP_PROBE = b"HEAD / HTTP/1.0\r\nUser-Agent: vulnscan\r\nAccept: */*\r\n\r\n"


def parse_ports(spec: str) -> List[int]:
    """Parse 'top', 'all', or a list/range spec such as '22,80,8000-8100'."""
    spec = spec.strip().lower()
    if spec == "top":
        return list(TOP_PORTS)
    if spec == "all":
        return list(range(1, 65536))
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, hi_s = part.split("-", 1)
            lo, hi = int(lo_s), int(hi_s)
            if lo > hi:
                raise ValueError(f"invalid port range '{part}'")
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part))
    bad = [p for p in ports if not 1 <= p <= 65535]
    if bad or not ports:
        raise ValueError(f"ports must be between 1 and 65535 (got {sorted(bad)[:3] or spec!r})")
    return sorted(ports)


def _is_open(addr: str, port: int, timeout: float) -> bool:
    family = socket.AF_INET6 if ":" in addr else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            return s.connect_ex((addr, port)) == 0
        except OSError:
            return False


def scan_ports(addr: str, ports: List[int], timeout: float = 1.0, threads: int = 200) -> List[int]:
    """TCP connect scan.  Returns the sorted list of open ports."""
    if not ports:
        return []
    workers = max(1, min(threads, len(ports)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda p: _is_open(addr, p, timeout), ports))
    return sorted(p for p, ok in zip(ports, results) if ok)


def _recv(sock: socket.socket, size: int, timeout: float) -> bytes:
    sock.settimeout(timeout)
    try:
        return sock.recv(size)
    except (socket.timeout, OSError):
        return b""


def _tls_probe(addr: str, port: int, timeout: float) -> Tuple[bool, bytes]:
    """Try a TLS handshake plus an HTTP HEAD.  Returns (tls_ok, response_bytes)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((addr, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=None) as tls:
                tls.settimeout(max(timeout, 1.0))
                try:
                    tls.sendall(HTTP_PROBE)
                except OSError:
                    return True, b""
                try:
                    return True, tls.recv(2048)
                except (socket.timeout, OSError):
                    return True, b""
    except (ssl.SSLError, OSError):
        return False, b""


def _first_line(text: str, limit: int = 200) -> str:
    return text.strip().splitlines()[0][:limit] if text.strip() else ""


def _http_banner(text: str) -> str:
    status = _first_line(text)
    for line in text.splitlines()[1:]:
        if line.lower().startswith("server:"):
            return f"{status} | {line.strip()}"[:240]
    return status


def probe_port(addr: str, port: int, timeout: float = 1.0) -> PortInfo:
    """Fingerprint an open port: banner, HTTP(S) detection, TLS detection."""
    info = PortInfo(port=port, service=COMMON_SERVICES.get(port, "unknown"))

    def apply_http(text: str, tls: bool) -> None:
        info.http = True
        info.tls = tls
        info.service = "https" if tls else "http"
        info.banner = _http_banner(text)

    if port in KNOWN_TLS_PORTS:
        ok, data = _tls_probe(addr, port, timeout)
        if ok:
            text = data.decode("latin-1", "replace")
            if text.startswith("HTTP/"):
                apply_http(text, True)
            else:
                info.tls = True
                info.service = COMMON_SERVICES.get(port, "ssl")
            return info

    data = b""
    try:
        with socket.create_connection((addr, port), timeout=timeout) as s:
            data = _recv(s, 512, min(timeout, 0.8))
            if not data:
                try:
                    s.sendall(HTTP_PROBE)
                    data = _recv(s, 2048, min(timeout * 2, 1.5))
                except OSError:
                    pass
    except OSError:
        return info

    text = data.decode("latin-1", "replace")
    if text.startswith("HTTP/"):
        apply_http(text, False)
    elif data:
        info.banner = _first_line(text)
        if text.startswith("SSH-"):
            info.service = "ssh"
        elif text.startswith("220") and "ftp" in text.lower():
            info.service = "ftp"
        elif text.startswith("220"):
            info.service = "smtp"
    else:
        ok, tdata = _tls_probe(addr, port, timeout)
        if ok:
            ttext = tdata.decode("latin-1", "replace")
            if ttext.startswith("HTTP/"):
                apply_http(ttext, True)
            else:
                info.tls = True
                info.service = f"ssl/{info.service}"
    return info


# --- risky service findings --------------------------------------------------

# port -> (check_id, title, severity, category, cwe, description, remediation)
RISKY_SERVICES: Dict[int, Tuple[str, str, Severity, str, str, str, str]] = {
    23: ("PORT-TELNET", "Telnet service exposed", Severity.HIGH, "crypto", "CWE-319",
         "Telnet transmits credentials and session data in cleartext.",
         "Disable telnet and use SSH with key-based authentication."),
    21: ("PORT-FTP", "FTP service exposed (cleartext)", Severity.MEDIUM, "crypto", "CWE-319",
         "FTP sends credentials and data unencrypted and often allows anonymous access.",
         "Replace with SFTP/FTPS and disable anonymous login."),
    445: ("PORT-SMB", "SMB service exposed", Severity.MEDIUM, "misconfig", "CWE-284",
          "SMB has a long history of critical vulnerabilities and should not be broadly reachable.",
          "Restrict SMB to required hosts with a firewall, disable SMBv1, require signing."),
    139: ("PORT-NETBIOS", "NetBIOS session service exposed", Severity.LOW, "misconfig", "CWE-284",
          "Legacy NetBIOS exposure aids host enumeration.",
          "Disable NetBIOS over TCP/IP where it is not required."),
    3389: ("PORT-RDP", "Remote Desktop (RDP) exposed", Severity.MEDIUM, "misconfig", "CWE-284",
           "RDP is a frequent target for credential stuffing and unpatched-vulnerability exploitation.",
           "Place RDP behind a VPN or gateway, enforce NLA and MFA."),
    5900: ("PORT-VNC", "VNC service exposed", Severity.MEDIUM, "crypto", "CWE-319",
           "VNC often uses weak authentication and no transport encryption.",
           "Tunnel VNC over SSH/VPN or replace with an authenticated, encrypted remote-access tool."),
    111: ("PORT-RPCBIND", "rpcbind/portmapper exposed", Severity.LOW, "misconfig", "CWE-284",
          "rpcbind reveals RPC services and has been abused for amplification attacks.",
          "Firewall rpcbind from untrusted networks."),
    2049: ("PORT-NFS", "NFS service exposed", Severity.MEDIUM, "access_control", "CWE-284",
           "Misconfigured NFS exports can expose file systems without authentication.",
           "Restrict exports to specific hosts and review /etc/exports."),
    5985: ("PORT-WINRM", "WinRM (HTTP) exposed", Severity.LOW, "misconfig", "CWE-284",
           "Remote management interface reachable over the network.",
           "Restrict to management networks and require HTTPS."),
}

EXPECTED_SERVICE = {6379: "Redis", 11211: "Memcached", 3306: "MySQL/MariaDB", 5432: "PostgreSQL",
                    27017: "MongoDB", 9200: "Elasticsearch", 3389: "Remote Desktop (RDP)",
                    445: "SMB (Windows file sharing)"}

for _port, _name in [(3306, "MySQL/MariaDB"), (5432, "PostgreSQL"), (1433, "Microsoft SQL Server"),
                     (1521, "Oracle DB"), (6379, "Redis"), (27017, "MongoDB"),
                     (9200, "Elasticsearch"), (11211, "Memcached")]:
    RISKY_SERVICES[_port] = (
        "PORT-DATASTORE", f"Potential {_name} service reachable at target", Severity.HIGH,
        "misconfig", "CWE-284",
        "Data stores are rarely meant to be reachable beyond the application tier, and "
        "several (Redis, Memcached, MongoDB, Elasticsearch) have historically shipped "
        "with no authentication by default.",
        "Bind the service to localhost or a private interface, require authentication, "
        "and restrict access with a firewall.",
    )


def service_findings(host: str, info: PortInfo, address: Optional[str] = None,
                     ident=None, probed: bool = False) -> List[Finding]:
    """``ident`` is what the protocol probe confirmed; ``probed`` says a probe was attempted."""
    rule: Optional[tuple] = RISKY_SERVICES.get(info.port)
    if not rule:
        return []
    if probed and ident is None and info.port in EXPECTED_SERVICE and rule[0] == "PORT-DATASTORE":
        expected = EXPECTED_SERVICE[info.port]
        return [Finding(
            host=host, port=info.port, check_id="PORT-UNVERIFIED",
            title=f"Port {info.port} is open but did not answer like {expected}", severity=Severity.LOW,
            category="misconfig", cwe="CWE-284",
            description=(f"Something accepts connections on port {info.port}, which is normally {expected}, "
                         "but it did not respond to the protocol handshake. It may be a different service, a "
                         "firewall or proxy, or {0} configured to ignore unknown clients.".format(expected)),
            remediation="Find out what owns this port (on Windows: Get-NetTCPConnection -LocalPort "
                        f"{info.port} | Select OwningProcess) and close it if it is not needed.",
            evidence=f"TCP connect to port {info.port} succeeded; protocol check for {expected} got no valid reply")]
    check_id, title, severity, category, cwe, desc, fix = rule
    exposure = classify_exposure(address) if address else {
        "scope": "unknown", "address": "", "basis": "target address was not supplied"}
    scope_name = {"localhost": "localhost", "lan": "private/LAN address",
                  "public": "public-routable address", "special": "special-use address",
                  "unknown": "unclassified address"}[exposure["scope"]]
    if check_id == "PORT-DATASTORE":
        title = title.replace("at target", f"at {scope_name}")
        if ident is not None:
            title = f"{ident.name} service confirmed at {scope_name}"
        else:
            desc += " The service label is inferred from the conventional TCP port; no protocol handshake confirmed it."
    observed = (f"TCP connect from this scanner to {address}:{info.port} succeeded; "
                f"{exposure['basis']}." if address else "TCP connect succeeded; target address was not recorded.")
    if ident is not None:
        desc += f" Confirmed by protocol check: {ident.name} ({ident.detail})."
        observed += f" Protocol check confirmed {ident.name}: {ident.detail}."
        if ident.open_access:
            check_id, severity = "PORT-DATASTORE-OPEN", Severity.CRITICAL
            title = f"{ident.name} answers without a login at {scope_name}"
    elif check_id == "PORT-DATASTORE":
        observed += f" {info.service} is inferred from the port number; protocol not verified."
    return [Finding(
        host=host, port=info.port, check_id=check_id, title=title, severity=severity,
        category=category, cwe=cwe,
        description=(desc + f" Observed from this scanner at {scope_name} scope. This proves reachability "
                     "from this vantage point only; it does not establish reachability from other LAN hosts "
                     "or from the public internet."),
        remediation=fix, evidence=observed,
        extra={"exposure": {**exposure, "observation": "TCP connect succeeded from this scanner"}},
    )]
