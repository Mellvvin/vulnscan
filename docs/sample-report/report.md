# Security assessment

27 findings, 5 rated Critical or High. 1 is on CISA's list of vulnerabilities exploited in the wild.

- Scanned: 2026-11-03T10:00:00+00:00 UTC
- Standard: OWASP Top 10:2025
- Tool: vulnscan 1.1.0

> Note: SAMPLE REPORT: the package findings come from synthetic test data and the web findings from the bundled lab server. It illustrates the format; it is not an assessment of a real system.

## Severity

| Severity | Findings |
|---|---:|
| Critical | 0 |
| High | 5 |
| Medium | 13 |
| Low | 8 |
| Info | 1 |

## OWASP Top 10:2025

| Category | Findings | High or Critical |
|---|---:|---:|
| A01:2025 Broken Access Control | 1 | 1 |
| A02:2025 Security Misconfiguration | 12 | 2 |
| A03:2025 Software Supply Chain Failures | 3 | 1 |
| A04:2025 Cryptographic Failures | 1 | 1 |
| A05:2025 Injection | 4 | 0 |
| A06:2025 Insecure Design (not assessable by scanning) | 0 | 0 |
| A07:2025 Authentication Failures | 4 | 0 |
| A08:2025 Software or Data Integrity Failures | 1 | 0 |
| A09:2025 Security Logging & Alerting Failures (not assessable by scanning) | 0 | 0 |
| A10:2025 Mishandling of Exceptional Conditions | 1 | 0 |

## Fix first

1. **sudo: CVE-2021-3156** (A03:2025): exploited in the wild (CISA KEV, added 2022-04-06); 97% chance of exploitation in the next 30 days (EPSS); CVSS 7.8; fixed in 1.9.5p2-3
2. **CORS reflects arbitrary origin with credentials** (A01:2025): 127.0.0.1:42693: Any website can make authenticated cross-origin requests and read the responses.
3. **Exposed .env configuration file** (A02:2025): 127.0.0.1:42693: /.env returned content matching a known sensitive-file signature.
4. **Exposed .git repository** (A02:2025): 127.0.0.1:42693: /.git/HEAD returned content matching a known sensitive-file signature.
5. **Login form served over plain HTTP** (A04:2025): 127.0.0.1:42693: Credentials are sent in cleartext and can be captured on the network path.

## All findings

| Severity | Target | Finding | Fixed in | OWASP |
|---|---|---|---|---|
| High | lab-ubuntu | sudo 1.9.5p2-2: CVE-2021-3156 sudo heap overflow | 1.9.5p2-3 | A03:2025 |
| High | 127.0.0.1:42693 | CORS reflects arbitrary origin with credentials |  | A01:2025 |
| High | 127.0.0.1:42693 | Exposed .env configuration file |  | A02:2025 |
| High | 127.0.0.1:42693 | Exposed .git repository |  | A02:2025 |
| High | 127.0.0.1:42693 | Login form served over plain HTTP |  | A04:2025 |
| Medium | lab-ubuntu | baz 2.0-1: CVE-2024-0002 baz parsing bug | 2.0-2 | A05:2025 |
| Medium | lab-ubuntu | jinja2 2.11.2: CVE-2020-28493 Jinja2 ReDoS | 2.11.3 | A05:2025 |
| Medium | lab-ubuntu | foo 1.0-1: CVE-2023-0001 <img src=x onerror=alert(1)> foo flaw |  | A03:2025 |
| Medium | 127.0.0.1:42693 | Outdated Apache httpd (2.4.49) |  | A03:2025 |
| Medium | 127.0.0.1:42693 | Cookie 'PHPSESSID' missing HttpOnly flag |  | A07:2025 |
| Medium | 127.0.0.1:42693 | Directory listing enabled |  | A02:2025 |
| Medium | 127.0.0.1:42693 | phpinfo() page exposed |  | A02:2025 |
| Medium | 127.0.0.1:42693 | Content-Security-Policy header missing |  | A02:2025 |
| Medium | 127.0.0.1:42693 | Unescaped input reflected (possible reflected XSS, verify manually) |  | A05:2025 |
| Medium | 127.0.0.1:42693 | State-changing HTTP methods advertised |  | A02:2025 |
| Medium | 127.0.0.1:42693 | Possible SQL error disclosure (verify manually) |  | A05:2025 |
| Medium | 127.0.0.1:42693 | HTTP TRACE method enabled |  | A02:2025 |
| Medium | 127.0.0.1:42693 | Verbose error output / debug mode |  | A10:2025 |
| Low | 127.0.0.1:42693 | Cookie 'theme' missing HttpOnly flag |  | A07:2025 |
| Low | 127.0.0.1:42693 | Cookie 'PHPSESSID' missing SameSite attribute |  | A07:2025 |
| Low | 127.0.0.1:42693 | Cookie 'theme' missing SameSite attribute |  | A07:2025 |
| Low | 127.0.0.1:42693 | No clickjacking protection |  | A02:2025 |
| Low | 127.0.0.1:42693 | X-Content-Type-Options header missing |  | A02:2025 |
| Low | 127.0.0.1:42693 | Third-party resources loaded without Subresource Integrity |  | A08:2025 |
| Low | 127.0.0.1:42693 | Server header discloses version |  | A02:2025 |
| Low | 127.0.0.1:42693 | X-Powered-By header discloses technology |  | A02:2025 |
| Info | 127.0.0.1:42693 | Referrer-Policy header missing |  | A02:2025 |
