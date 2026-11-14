"""Read-only audit of this Windows PC's security settings.

One PowerShell script collects facts as JSON; ``evaluate`` turns facts into findings.  Nothing is
changed.  A fact that could not be read (for example BitLocker needs an administrator) is recorded as
unchecked, never reported as a problem.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import date, datetime
from typing import Callable, Dict, List, Optional, Tuple

from .models import Finding, Severity

PS_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
function T($b){ try { & $b } catch { $null } }
$o = [ordered]@{}
$os = T { Get-CimInstance Win32_OperatingSystem }
$o.os = if ($os) { @{ caption = $os.Caption; version = $os.Version; build = $os.BuildNumber } } else { $null }
$o.firewall = T { @(Get-NetFirewallProfile | ForEach-Object { @{ name = "$($_.Name)"; enabled = ("$($_.Enabled)" -eq 'True') } }) }
$mp = T { Get-MpComputerStatus }
$o.defender = if ($mp) { @{ enabled = [bool]$mp.AntivirusEnabled; realtime = [bool]$mp.RealTimeProtectionEnabled;
   signature_age_days = [int]$mp.AntivirusSignatureAge } } else { $null }
$hf = T { Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1 }
$o.last_update = if ($hf) { $hf.InstalledOn.ToString('yyyy-MM-dd') } else { $null }
$bl = T { @(Get-BitLockerVolume | ForEach-Object { @{ mount = "$($_.MountPoint)"; protected = ("$($_.ProtectionStatus)" -eq 'On') } }) }
$o.bitlocker = $bl
$smb = T { Get-SmbServerConfiguration }
$o.smb1 = if ($smb) { [bool]$smb.EnableSMB1Protocol } else { $null }
$o.smb_signing_required = if ($smb) { [bool]$smb.RequireSecuritySignature } else { $null }
$rdp = T { (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server').fDenyTSConnections }
$o.rdp_enabled = if ($rdp -ne $null) { [bool]($rdp -eq 0) } else { $null }
$nla = T { (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').UserAuthentication }
$o.rdp_nla = if ($nla -ne $null) { [bool]($nla -eq 1) } else { $null }
$uac = T { (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA }
$o.uac = if ($uac -ne $null) { [bool]($uac -eq 1) } else { $null }
$guest = T { Get-LocalUser -Name Guest }
$o.guest_enabled = if ($guest) { [bool]$guest.Enabled } else { $null }
$sb = T { Confirm-SecureBootUEFI }
$o.secure_boot = if ($sb -ne $null) { [bool]$sb } else { $null }
$al = T { (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon').AutoAdminLogon }
$o.auto_login = if ($al -ne $null) { [bool]("$al" -eq '1') } else { $null }
$o.admin = [bool](T { ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) })
$o | ConvertTo-Json -Depth 5 -Compress
"""

Runner = Callable[[List[str]], Tuple[int, str]]


def default_runner(cmd: List[str]) -> Tuple[int, str]:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    return proc.returncode, proc.stdout


def is_windows() -> bool:
    return sys.platform.startswith("win")


def collect(runner: Runner = default_runner) -> Dict:
    """Run the PowerShell script and return the facts (raises RuntimeError if it cannot run)."""
    for exe in ("powershell", "pwsh"):
        try:
            code, out = runner([exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                                "-Command", PS_SCRIPT])
        except (OSError, subprocess.SubprocessError):
            continue
        if code == 0 and out.strip():
            try:
                return json.loads(out[out.index("{"):])
            except ValueError:
                continue
    raise RuntimeError("could not run PowerShell to read this PC's settings")


def _f(host: str, cid: str, title: str, sev: Severity, cwe: str, desc: str, fix: str, evidence: str) -> Finding:
    return Finding(host=host, port=None, check_id=cid, title=title, severity=sev, category="misconfig",
                   cwe=cwe, description=desc, remediation=fix, evidence=evidence)


def _as_list(value):
    """PowerShell turns a one-item list into a bare object; undo that."""
    if value is None:
        return None
    return value if isinstance(value, list) else [value]


def evaluate(facts: Dict, host: str = "this-pc", today: Optional[date] = None) -> Tuple[List[Finding], List[str]]:
    """Return (findings, list of things that could not be checked)."""
    today = today or date.today()
    out: List[Finding] = []
    unchecked: List[str] = []

    def f(*a):
        out.append(_f(host, *a))

    fw = _as_list(facts.get("firewall"))
    if fw is None:
        unchecked.append("Windows Firewall")
    else:
        off = [p["name"] for p in fw if not p.get("enabled")]
        if off:
            f("WIN-FIREWALL-OFF", f"Windows Firewall is off for: {', '.join(off)}",
              Severity.HIGH if "Public" in off else Severity.MEDIUM, "CWE-693",
              "With the firewall off, every service on this PC that listens for connections can be reached by "
              "other devices on the network.",
              "Turn the firewall on for all profiles: Windows Security > Firewall & network protection.",
              "profiles off: " + ", ".join(off))

    d = facts.get("defender")
    if d is None:
        unchecked.append("Microsoft Defender (not readable; another antivirus may be in use)")
    else:
        if not d.get("enabled") or not d.get("realtime"):
            f("WIN-AV-OFF", "Antivirus real-time protection is off", Severity.HIGH, "CWE-693",
              "Without real-time protection malware is not blocked when it arrives.",
              "Turn on real-time protection in Windows Security > Virus & threat protection, or confirm "
              "another antivirus is active.",
              f"enabled={d.get('enabled')}, real-time={d.get('realtime')}")
        age = d.get("signature_age_days")
        if isinstance(age, int) and age > 7:
            f("WIN-AV-STALE", f"Antivirus definitions are {age} days old", Severity.MEDIUM, "CWE-1104",
              "Old definitions miss recent malware.", "Run Windows Update and update the security "
              "intelligence in Windows Security.", f"signature age {age} days")

    last = facts.get("last_update")
    if not last:
        unchecked.append("Windows Update history")
    else:
        try:
            age = (today - datetime.strptime(last, "%Y-%m-%d").date()).days
        except ValueError:
            age = None
        if age is not None and age > 60:
            f("WIN-UPDATES-OLD", f"No Windows update installed for {age} days", Severity.HIGH if age > 120
              else Severity.MEDIUM, "CWE-1104",
              "Windows is patched monthly. Going months without updates leaves known, publicly documented "
              "holes open.", "Open Settings > Windows Update, install everything, restart, and turn on "
              "automatic updates.", f"latest installed update: {last}")

    bl = _as_list(facts.get("bitlocker"))
    if bl is None:
        unchecked.append("BitLocker disk encryption (needs Administrator, or not supported on this edition)")
    else:
        bad = [v["mount"] for v in bl if not v.get("protected")]
        if bad:
            f("WIN-DISK-UNENCRYPTED", f"Disk not encrypted: {', '.join(bad)}", Severity.MEDIUM, "CWE-311",
              "If the laptop or drive is lost or stolen, anyone can read the files by moving the drive.",
              "Turn on BitLocker (or Device encryption) and keep the recovery key somewhere safe, not on "
              "the PC.", "unprotected volumes: " + ", ".join(bad))

    if facts.get("smb1") is True:
        f("WIN-SMB1", "SMBv1 is enabled", Severity.HIGH, "CWE-327",
          "SMBv1 is an obsolete file-sharing version behind the WannaCry and NotPetya outbreaks.",
          "Disable it: Turn Windows features on or off > uncheck SMB 1.0/CIFS, or "
          "Set-SmbServerConfiguration -EnableSMB1Protocol $false.", "EnableSMB1Protocol = True")
    elif facts.get("smb1") is None:
        unchecked.append("SMBv1 setting (needs Administrator)")

    if facts.get("rdp_enabled") is True:
        nla = facts.get("rdp_nla")
        f("WIN-RDP-ON", "Remote Desktop is turned on" + ("" if nla is not False else " without NLA"),
          Severity.HIGH if nla is False else Severity.MEDIUM, "CWE-284",
          "Remote Desktop is a favourite entry point for attackers guessing passwords.",
          "Turn it off in Settings > System > Remote Desktop unless you need it. If you do, require "
          "Network Level Authentication, use a strong password with MFA, and do not forward port 3389 on "
          "the router.", f"RDP enabled, NLA={nla}")

    if facts.get("uac") is False:
        f("WIN-UAC-OFF", "User Account Control is turned off", Severity.HIGH, "CWE-250",
          "UAC stops programs from silently getting administrator rights.",
          "Turn it back on in Control Panel > User Accounts > Change User Account Control settings.",
          "EnableLUA = 0")
    if facts.get("guest_enabled") is True:
        f("WIN-GUEST-ON", "The Guest account is enabled", Severity.MEDIUM, "CWE-1188",
          "A shared guest account lets anyone use the PC without proper accountability.",
          "Disable it: net user Guest /active:no (as Administrator).", "Guest account enabled")
    if facts.get("secure_boot") is False:
        f("WIN-SECUREBOOT-OFF", "Secure Boot is off", Severity.LOW, "CWE-693",
          "Secure Boot blocks tampered boot software and some rootkits.",
          "Turn it on in the PC's UEFI/BIOS settings if the hardware supports it.", "Secure Boot = off")
    if facts.get("auto_login") is True:
        f("WIN-AUTOLOGIN", "Windows signs in automatically without a password", Severity.MEDIUM, "CWE-306",
          "Anyone who turns the PC on gets into the account and its saved sessions.",
          "Require a sign-in: Settings > Accounts > Sign-in options, and turn off automatic sign-in.",
          "AutoAdminLogon = 1")
    if not facts.get("admin"):
        unchecked.append("Some settings need Administrator; run PowerShell as Administrator for a full check")
    return out, unchecked
