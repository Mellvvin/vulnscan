"""Plain-English starting text for "what it means" and "what I can do about it".

These are suggestions: the workbench pre-fills them and you edit freely.  Lookup is by exact check id,
then by the longest matching prefix, then a generic fallback built from the finding itself.
"""

from __future__ import annotations

from typing import Dict, Tuple

# check id (or prefix ending in "-") -> (what it means, what can be done)
TEXT: Dict[str, Tuple[str, str]] = {
    "PORT-SMB": ("Windows file sharing (SMB) is switched on and listening. It is normal on a Windows PC, but "
                 "it has a long history of serious attacks, so it must never be reachable from the internet "
                 "or from untrusted Wi-Fi.",
                 "Confirm the router does not forward port 445. Turn off SMBv1, set the network profile to "
                 "Private only at home, block inbound 445 in Windows Firewall for Public networks, and turn "
                 "off file sharing if it is not used."),
    "PORT-NETBIOS": ("An old Windows name-sharing service is listening. It can leak computer and user names "
                     "to others on the same network.",
                     "Disable NetBIOS over TCP/IP in the network adapter settings if nothing needs it, and "
                     "block ports 137-139 on the firewall."),
    "PORT-RDP": ("Remote Desktop is reachable. Attackers constantly guess passwords against it, and it is a "
                 "common way ransomware gets in.",
                 "Turn it off if it is not needed. Otherwise require Network Level Authentication, strong "
                 "passwords with MFA, and put it behind a VPN instead of exposing it."),
    "PORT-TELNET": ("Telnet sends passwords and everything else in plain text that anyone on the network can "
                    "read.", "Turn Telnet off and use SSH instead."),
    "PORT-FTP": ("FTP sends logins and files without encryption, so they can be read or changed in transit.",
                 "Replace it with SFTP or FTPS, or turn the service off."),
    "PORT-VNC": ("Remote screen control (VNC) is reachable, usually with a weak or no encryption.",
                 "Turn it off or restrict it to a VPN, and set a strong password."),
    "PORT-RPCBIND": ("A Unix service that lists other services is reachable, which helps an attacker map "
                     "the machine.", "Block it with the firewall unless NFS is in use."),
    "PORT-NFS": ("A network file share (NFS) is reachable and may let other machines read your files.",
                 "Restrict exports to specific trusted addresses, or turn NFS off."),
    "PORT-WINRM": ("Windows remote management is listening. It lets administrators run commands remotely, "
                   "so it is valuable to an attacker.",
                   "Disable it if not used; otherwise limit it to trusted addresses and use HTTPS."),
    "PORT-DATASTORE": ("A database or data store is accepting connections. These often have no password by "
                       "default, so anyone who can reach it may be able to read or delete the data.",
                       "Bind it to localhost only, turn on authentication, and block its port in the firewall "
                       "so only the application can reach it. If it is not used, stop the service."),
    "TLS-EXPIRED": ("The website certificate has expired. Browsers show a scary warning and visitors may "
                    "leave or be tricked into ignoring warnings.", "Renew the certificate now and turn on "
                    "automatic renewal (Let's Encrypt or the host's own)."),
    "TLS-EXPIRING-SOON": ("The certificate expires soon. If nobody renews it the site will start showing "
                          "security errors.", "Renew it and set up automatic renewal."),
    "TLS-SELF-SIGNED": ("The certificate was not issued by a trusted authority, so browsers will warn "
                        "visitors.", "Install a free trusted certificate (Let's Encrypt)."),
    "TLS-UNTRUSTED-CERT": ("Browsers do not trust this certificate, so visitors see warnings and the "
                           "connection is not proven safe.", "Install a certificate from a trusted "
                           "authority with the full chain."),
    "TLS-HOSTNAME-MISMATCH": ("The certificate is for a different name than the one visitors use, so "
                              "browsers warn them.", "Reissue the certificate to include this exact name."),
    "TLS-LEGACY-PROTOCOL": ("The server still accepts old encryption versions that are known to be "
                            "breakable.", "Disable TLS 1.0 and 1.1 in the server or host settings."),
    "TLS-WEAK-CIPHER": ("The server accepts weak encryption settings that can be attacked.",
                        "Use the host's modern TLS profile and disable weak ciphers."),
    "WEB-NO-HSTS": ("The site does not tell browsers to always use HTTPS, so a visitor on public Wi-Fi can "
                    "be downgraded to the unprotected version.", "Add the Strict-Transport-Security header "
                    "once HTTPS works everywhere."),
    "WEB-WEAK-HSTS": ("The HTTPS-only instruction is set but for too short a time to help much.",
                      "Raise max-age to at least six months."),
    "WEB-NO-HTTPS-REDIRECT": ("Visiting the site over plain HTTP does not move people to the secure "
                              "version, so logins and orders can be read on the network.",
                              "Redirect all HTTP traffic to HTTPS."),
    "WEB-NO-CSP": ("There is no Content-Security-Policy, which would limit the damage if someone injects a "
                   "malicious script into a page.", "Add a CSP header, starting in report-only mode."),
    "WEB-NO-CLICKJACK-PROTECTION": ("Another site could load this one invisibly in a frame and trick "
                                    "visitors into clicking buttons.",
                                    "Add X-Frame-Options: DENY or a CSP frame-ancestors rule."),
    "WEB-NO-NOSNIFF": ("Browsers may guess file types and run something that should only be downloaded.",
                       "Add the header X-Content-Type-Options: nosniff."),
    "WEB-NO-REFERRER-POLICY": ("Full page addresses, which can contain private details, may be sent to other "
                               "sites visitors click through to.", "Add Referrer-Policy: "
                               "strict-origin-when-cross-origin."),
    "WEB-NO-SRI": ("Scripts loaded from other sites are not integrity-checked, so if that site is "
                   "compromised your visitors run the attacker's code.",
                   "Add integrity hashes to external scripts or host them yourself."),
    "WEB-SERVER-VERSION": ("The server announces its exact software version, which helps attackers pick "
                           "known exploits.", "Hide version details in the server configuration and keep "
                           "the software updated."),
    "WEB-X-POWERED-BY": ("The site reveals what technology it runs on, which helps attackers choose "
                         "attacks.", "Remove the X-Powered-By header."),
    "WEB-RISKY-METHODS": ("The server allows request types such as PUT or DELETE that can let outsiders "
                          "change or remove content.", "Allow only GET, POST and HEAD."),
    "WEB-TRACE-ENABLED": ("The TRACE method is enabled, which can be abused to steal session details.",
                          "Disable TRACE."),
    "WEB-VERBOSE-ERRORS": ("Error pages show technical details such as file paths or code, which help an "
                           "attacker.", "Turn off debug mode and show a plain error page."),
    "WEB-CORS-": ("The site lets other websites read its responses from a visitor's browser, which can "
                  "expose private data.", "Allow only the specific sites that need access and never "
                  "combine a wildcard with logged-in access."),
    "WEB-COOKIE-": ("Login cookies are missing a protection flag, making them easier to steal or misuse.",
                    "Set Secure, HttpOnly and SameSite on session cookies."),
    "WEB-EXPOSED-": ("A sensitive file or admin page can be opened by anyone on the internet. These often "
                     "contain passwords, source code or customer data.",
                     "Remove it from the public site or block access now, and change any passwords or keys "
                     "that were in it."),
    "WEB-DIR-LISTING": ("The server shows a list of files in a folder, which can reveal backups and private "
                        "files.", "Turn off directory listing."),
    "WEB-LOGIN-OVER-HTTP": ("A login form is served without encryption, so passwords can be read on the "
                            "network.", "Serve all login pages over HTTPS only."),
    "WEB-SQL-ERROR": ("An input caused a database error message. That can mean the form is open to SQL "
                      "injection, where an attacker reads or changes the database.",
                      "Verify by hand, then use parameterised queries and hide database errors."),
    "WEB-REFLECTED-INPUT": ("Text typed into a page is shown back without being cleaned, which can allow "
                            "script injection (XSS).", "Verify by hand, then escape all output."),
    "DNS-NO-SPF": ("Nothing says which servers may send email for this domain, so forged email in your "
                   "name is easier to deliver.", "Publish an SPF record listing your mail provider."),
    "DNS-SPF-MULTIPLE": ("More than one SPF record exists, which is invalid and may disable the protection.",
                         "Merge them into a single record."),
    "DNS-SPF-PERMISSIVE": ("The email rules say anyone may send mail as this domain, so they give no "
                           "protection.", "End the SPF record with -all."),
    "DNS-SPF-NO-ALL": ("The email sender list does not say what to do with unlisted senders.",
                       "End the SPF record with -all or ~all."),
    "DNS-NO-DMARC": ("There is no policy telling receivers to reject forged email, and you get no reports "
                     "about abuse. Scammers can send invoices that look like they come from you.",
                     "Publish a DMARC record, start with p=quarantine and move to p=reject."),
    "DNS-DMARC-MONITOR-ONLY": ("The DMARC policy only watches and does not block forged email.",
                               "Move the policy from none to quarantine, then reject."),
    "DNS-DKIM-NOT-FOUND": ("No email-signing key was found on common names; this may be a false alarm if the "
                           "provider uses a custom one.", "Check in the mail provider's admin that DKIM "
                           "signing is on."),
    "COMP-": ("Software in use has known security holes that attackers already have tools for.",
              "Update to the fixed version shown in the finding."),
}


def suggest(finding: dict) -> Tuple[str, str]:
    cid = finding.get("check_id", "")
    if cid in TEXT:
        return TEXT[cid]
    best = max((k for k in TEXT if k.endswith("-") and cid.startswith(k)), key=len, default=None)
    if best:
        return TEXT[best]
    return (finding.get("description", "").strip(), finding.get("remediation", "").strip())
