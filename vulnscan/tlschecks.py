"""TLS configuration checks using only the standard library."""

from __future__ import annotations

import socket
import ssl
import time
import warnings
from typing import List, Optional

from .models import Finding, Severity

WEAK_CIPHER_MARKERS = ("RC4", "3DES", "DES-CBC", "NULL", "EXPORT", "MD5", "ANON")
with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    LEGACY_PROTOCOLS = [
        ("TLSv1.0", ssl.TLSVersion.TLSv1),
        ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ]


def _unverified_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _legacy_accepted(addr: str, port: int, version: ssl.TLSVersion, timeout: float) -> bool:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
        with warnings.catch_warnings():
            # Probing deprecated protocols is the whole point of this check.
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = version
            ctx.maximum_version = version
    except (ssl.SSLError, ValueError):
        return False  # local OpenSSL cannot even attempt this protocol
    try:
        with socket.create_connection((addr, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw):
                return True
    except (ssl.SSLError, OSError):
        return False


def check_tls(host: str, addr: str, port: int, timeout: float = 3.0) -> List[Finding]:
    findings: List[Finding] = []
    sni: Optional[str] = host if host != addr else None

    # 1. Certificate validation against the system trust store.
    verified_ok = False
    not_after: Optional[str] = None
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((addr, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni or addr) as tls:
                verified_ok = True
                not_after = (tls.getpeercert() or {}).get("notAfter")
    except ssl.SSLCertVerificationError as exc:
        msg = (exc.verify_message or str(exc)).lower()
        if "self-signed" in msg or "self signed" in msg:
            findings.append(Finding(
                host, port, "TLS-SELF-SIGNED", "Self-signed TLS certificate", Severity.MEDIUM,
                "crypto", "CWE-295",
                "The certificate is not signed by a trusted CA, so clients cannot verify "
                "the server's identity and users are trained to click through warnings.",
                "Issue a certificate from a trusted CA (e.g. an internal CA or ACME/Let's Encrypt).",
                evidence=exc.verify_message or "self-signed certificate"))
        elif "expired" in msg:
            findings.append(Finding(
                host, port, "TLS-EXPIRED", "Expired TLS certificate", Severity.HIGH,
                "crypto", "CWE-298",
                "The certificate validity period has ended; clients will reject or warn.",
                "Renew the certificate and automate renewal.",
                evidence=exc.verify_message or "certificate has expired"))
        elif "mismatch" in msg:
            findings.append(Finding(
                host, port, "TLS-HOSTNAME-MISMATCH", "TLS certificate hostname mismatch",
                Severity.LOW, "crypto", "CWE-297",
                "The certificate does not cover the name or address that was scanned.",
                "Issue a certificate whose SAN list covers every name clients use.",
                evidence=exc.verify_message or "hostname mismatch"))
        else:
            findings.append(Finding(
                host, port, "TLS-UNTRUSTED-CERT", "Untrusted TLS certificate chain",
                Severity.MEDIUM, "crypto", "CWE-295",
                "The certificate chain could not be validated against the system trust store.",
                "Serve the full chain from a trusted CA.",
                evidence=exc.verify_message or str(exc)))
    except (ssl.SSLError, OSError):
        pass  # handshake failed for reasons unrelated to certificate validation

    if verified_ok and not_after:
        try:
            days = int((ssl.cert_time_to_seconds(not_after) - time.time()) // 86400)
            if days < 14:
                findings.append(Finding(
                    host, port, "TLS-EXPIRING-SOON", "TLS certificate expires soon",
                    Severity.LOW, "crypto", "CWE-298",
                    f"Certificate expires in {days} day(s).",
                    "Renew the certificate and automate renewal.",
                    evidence=f"notAfter={not_after}"))
        except (ValueError, OverflowError):
            pass

    # 2. Negotiated parameters (unverified connection so we always get data).
    try:
        with socket.create_connection((addr, port), timeout=timeout) as raw:
            with _unverified_context().wrap_socket(raw, server_hostname=None) as tls:
                cipher = tls.cipher()
                if cipher and any(m in cipher[0].upper() for m in WEAK_CIPHER_MARKERS):
                    findings.append(Finding(
                        host, port, "TLS-WEAK-CIPHER", "Weak TLS cipher negotiated",
                        Severity.HIGH, "crypto", "CWE-327",
                        "The server negotiated a cipher suite considered broken or weak.",
                        "Restrict cipher suites to modern AEAD ciphers (AES-GCM, ChaCha20-Poly1305).",
                        evidence=cipher[0]))
    except (ssl.SSLError, OSError):
        return findings

    # 3. Legacy protocol acceptance.
    accepted = [label for label, version in LEGACY_PROTOCOLS
                if _legacy_accepted(addr, port, version, timeout)]
    if accepted:
        findings.append(Finding(
            host, port, "TLS-LEGACY-PROTOCOL",
            f"Deprecated protocol(s) accepted: {', '.join(accepted)}",
            Severity.MEDIUM, "crypto", "CWE-327",
            "TLS 1.0/1.1 are deprecated (RFC 8996) and vulnerable to downgrade and padding attacks.",
            "Disable TLS 1.0/1.1 and require TLS 1.2 or newer.",
            evidence=", ".join(accepted)))
    return findings
