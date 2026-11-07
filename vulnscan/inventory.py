"""Software inventory: what is actually installed on a host, in a container image,
or declared by a project.  Each package is expressed in the form OSV.dev expects
(ecosystem + name + version), so the same pipeline audits all of them.

Collectors never raise on a missing tool; they return an empty list plus a note.
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Tuple

Runner = Callable[[List[str], float], Tuple[int, str]]


def default_runner(cmd: List[str], timeout: float = 180.0) -> Tuple[int, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")
        return proc.returncode, proc.stdout
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""


class InventoryError(Exception):
    pass


@dataclass(frozen=True)
class Package:
    name: str
    version: str
    ecosystem: str  # OSV ecosystem string, e.g. "Debian:12", "PyPI", "npm"
    manager: str  # dpkg | rpm | apk | pip | npm
    source: str = ""  # source package name (dpkg/apk) used by OSV
    source_version: str = ""

    @property
    def osv_name(self) -> str:
        return self.source or self.name

    @property
    def osv_version(self) -> str:
        return self.source_version or self.version


@dataclass
class SystemInfo:
    label: str  # shown in reports
    kind: str  # host | docker | project
    os_id: str = ""
    os_version_id: str = ""
    os_pretty: str = ""
    id_like: str = ""
    kernel: str = ""
    arch: str = ""
    platform_name: str = ""
    os_ecosystem: Optional[str] = None
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {"label": self.label, "kind": self.kind, "os": self.os_pretty or self.os_id,
                "os_id": self.os_id, "os_version": self.os_version_id, "kernel": self.kernel,
                "arch": self.arch, "ecosystem": self.os_ecosystem, "notes": self.notes}


# ------------------------------------------------------------------ OS identification

def parse_os_release(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def osv_os_ecosystem(os_id: str, version_id: str) -> Optional[str]:
    """Map /etc/os-release identity to an OSV ecosystem, or None if OSV has no feed."""
    os_id = (os_id or "").lower()
    parts = (version_id or "").split(".")
    major = parts[0]
    if os_id == "debian" and major.isdigit():
        return f"Debian:{major}"
    if os_id == "ubuntu" and len(parts) >= 2 and parts[0].isdigit():
        lts = int(parts[0]) % 2 == 0 and parts[1] == "04"
        return f"Ubuntu:{parts[0]}.{parts[1]}" + (":LTS" if lts else "")
    if os_id == "alpine" and len(parts) >= 2:
        return f"Alpine:v{parts[0]}.{parts[1]}"
    # OSV's own RPM example uses the bare ecosystem name (no major-version suffix).
    if os_id == "almalinux":
        return "AlmaLinux"
    if os_id == "rocky":
        return "Rocky Linux"
    return None


def system_info_from_os_release(label: str, kind: str, text: str,
                                override: Optional[str] = None) -> SystemInfo:
    rel = parse_os_release(text)
    info = SystemInfo(label=label, kind=kind, os_id=rel.get("ID", ""),
                      os_version_id=rel.get("VERSION_ID", ""),
                      os_pretty=rel.get("PRETTY_NAME", rel.get("NAME", "")),
                      id_like=rel.get("ID_LIKE", ""))
    info.os_ecosystem = override or osv_os_ecosystem(info.os_id, info.os_version_id)
    if info.os_ecosystem is None and info.os_id:
        info.notes.append(
            f"OSV.dev has no advisory feed for '{info.os_pretty or info.os_id}'; OS packages were "
            "not audited. If this is a derivative (e.g. Kali, Mint), re-run with --ecosystem "
            "<Debian:12 | Ubuntu:22.04:LTS | ...> naming the release it tracks.")
    return info


def local_system_info(override: Optional[str] = None) -> SystemInfo:
    info = SystemInfo(label=socket.gethostname() or "localhost", kind="host",
                      kernel=platform.release(), arch=platform.machine(),
                      platform_name=platform.system())
    if platform.system() == "Linux":
        for path in ("/etc/os-release", "/usr/lib/os-release"):
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    parsed = system_info_from_os_release(info.label, "host", fh.read(), override)
                parsed.kernel, parsed.arch, parsed.platform_name = info.kernel, info.arch, info.platform_name
                return parsed
            except OSError:
                continue
        info.notes.append("could not read /etc/os-release; OS packages were not audited")
    else:
        info.os_pretty = platform.platform()
        info.notes.append(
            f"{platform.system()} host: operating-system packages are not covered by OSV.dev. "
            "Python/npm packages, project files (--project), Docker images (--docker) and WSL/VM "
            "Linux guests (run vulnscan inside them) are audited instead.")
    return info


# ------------------------------------------------------------------ OS package managers

DPKG_FORMAT = r"${Package}\t${Version}\t${source:Package}\t${source:Version}\t${db:Status-Abbrev}\n"
RPM_FORMAT = r"%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{SOURCERPM}\n"


def parse_dpkg(output: str, ecosystem: str) -> List[Package]:
    pkgs: Dict[Tuple[str, str], Package] = {}
    for line in output.splitlines():
        cols = line.rstrip("\n").split("\t")
        if len(cols) < 5 or not cols[4].startswith("ii"):
            continue
        name, version, src, src_ver = cols[0], cols[1], cols[2], cols[3]
        if not name or not version:
            continue
        pkgs[(name, version)] = Package(name, version, ecosystem, "dpkg",
                                        src or name, src_ver or version)
    return sorted(pkgs.values(), key=lambda p: p.name)


_APK_LINE = re.compile(r"^(?P<full>\S+)\s+\S+\s+\{(?P<origin>[^}]*)\}")
_APK_NAMEVER = re.compile(r"^(?P<name>.+?)-(?P<ver>\d[^-]*-r\d+)$")


def parse_apk(output: str, ecosystem: str) -> List[Package]:
    pkgs: List[Package] = []
    for line in output.splitlines():
        m = _APK_LINE.match(line.strip())
        if not m:
            continue
        nv = _APK_NAMEVER.match(m.group("full"))
        if not nv:
            continue
        pkgs.append(Package(nv.group("name"), nv.group("ver"), ecosystem, "apk",
                            m.group("origin") or nv.group("name"), nv.group("ver")))
    return pkgs


def parse_rpm(output: str, ecosystem: str) -> List[Package]:
    pkgs: List[Package] = []
    for line in output.splitlines():
        cols = line.split("\t")
        if len(cols) < 2 or not cols[0]:
            continue
        version = cols[1]
        if version.startswith("0:"):
            version = version[2:]
        pkgs.append(Package(cols[0], version, ecosystem, "rpm"))
    return pkgs


def collect_os_packages(info: SystemInfo, runner: Runner = default_runner) -> List[Package]:
    eco = info.os_ecosystem
    if not eco:
        return []
    family = eco.split(":", 1)[0]
    if family in ("Debian", "Ubuntu"):
        if not shutil.which("dpkg-query"):
            info.notes.append("dpkg-query not found; cannot list Debian/Ubuntu packages")
            return []
        rc, out = runner(["dpkg-query", "-W", "-f", DPKG_FORMAT], 120)
        if rc != 0:
            info.notes.append("dpkg-query failed; Debian/Ubuntu OS packages were not inventoried")
        return parse_dpkg(out, eco) if rc == 0 else []
    if family == "Alpine":
        if not shutil.which("apk"):
            info.notes.append("apk not found; Alpine OS packages were not inventoried")
            return []
        rc, out = runner(["apk", "list", "-I"], 120)
        if rc != 0:
            info.notes.append("apk query failed; Alpine OS packages were not inventoried")
        return parse_apk(out, eco) if rc == 0 else []
    if family in ("AlmaLinux", "Rocky Linux"):
        if not shutil.which("rpm"):
            info.notes.append("rpm not found; RPM OS packages were not inventoried")
            return []
        rc, out = runner(["rpm", "-qa", "--qf", RPM_FORMAT + "\n"], 120)
        if rc != 0:
            info.notes.append("rpm query failed; RPM OS packages were not inventoried")
        return parse_rpm(out, eco) if rc == 0 else []
    return []


# ------------------------------------------------------------------ language packages

def normalize_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def collect_pip(runner: Runner = default_runner, python: Optional[str] = None) -> List[Package]:
    rc, out = runner([python or sys.executable, "-m", "pip", "list", "--format=json"], 120)
    if rc != 0:
        return []
    try:
        return [Package(normalize_pypi(p["name"]), p["version"], "PyPI", "pip")
                for p in json.loads(out) if p.get("name") and p.get("version")]
    except (ValueError, TypeError, KeyError):
        return []


def collect_npm_global(runner: Runner = default_runner) -> List[Package]:
    npm = shutil.which("npm")
    if not npm:
        return []
    _rc, out = runner([npm, "ls", "-g", "--json", "--depth=0"], 120)  # rc may be 1 for warnings
    try:
        deps = json.loads(out).get("dependencies", {})
        return [Package(n, d["version"], "npm", "npm") for n, d in deps.items() if d.get("version")]
    except (ValueError, TypeError, AttributeError):
        return []


# ------------------------------------------------------------------ project files

_REQ_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9._!+-]*)")
SKIP_DIRS = {"node_modules", ".git", "venv", ".venv", "env", "__pycache__", "site-packages",
             "dist", "build", ".tox", ".mypy_cache"}


def parse_requirements(text: str) -> List[Package]:
    pkgs = []
    for line in text.splitlines():
        line = line.split("#", 1)[0]
        m = _REQ_RE.match(line)
        if m:
            pkgs.append(Package(normalize_pypi(m.group(1)), m.group(2), "PyPI", "pip"))
    return pkgs


def _walk_npm_v1(deps: dict, out: List[Package]) -> None:
    for name, meta in (deps or {}).items():
        if isinstance(meta, dict):
            if meta.get("version") and not str(meta["version"]).startswith(("file:", "git", "http", "link:")):
                out.append(Package(name, meta["version"], "npm", "npm"))
            _walk_npm_v1(meta.get("dependencies", {}), out)


def parse_package_lock(text: str) -> List[Package]:
    data = json.loads(text)
    out: List[Package] = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for path, meta in packages.items():
            if not path or not isinstance(meta, dict) or not meta.get("version") or meta.get("link"):
                continue
            name = meta.get("name") or path.rsplit("node_modules/", 1)[-1]
            out.append(Package(name, meta["version"], "npm", "npm"))
    else:
        _walk_npm_v1(data.get("dependencies", {}), out)
    return out


def parse_pipfile_lock(text: str) -> List[Package]:
    data = json.loads(text)
    out: List[Package] = []
    for section in ("default", "develop"):
        for name, meta in (data.get(section) or {}).items():
            ver = str((meta or {}).get("version", "")).lstrip("=")
            if ver:
                out.append(Package(normalize_pypi(name), ver, "PyPI", "pip"))
    return out


def collect_project(path: str) -> Tuple[List[Package], List[str]]:
    """Find dependency manifests under `path`. Returns (packages, files used)."""
    found: Dict[Tuple[str, str, str], Package] = {}
    used: List[str] = []
    if not os.path.isdir(path):
        raise InventoryError(f"project path not found: {path}")
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for fname in files:
            parser: Optional[Callable[[str], List[Package]]] = None
            if re.fullmatch(r"requirements[\w.-]*\.txt", fname):
                parser = parse_requirements
            elif fname == "package-lock.json":
                parser = parse_package_lock
            elif fname == "Pipfile.lock":
                parser = parse_pipfile_lock
            if not parser:
                continue
            full = os.path.join(root, fname)
            try:
                with open(full, encoding="utf-8", errors="replace") as fh:
                    pkgs = parser(fh.read())
            except (OSError, ValueError):
                continue
            used.append(os.path.relpath(full, path))
            for p in pkgs:
                found[(p.ecosystem, p.name, p.version)] = p
    return sorted(found.values(), key=lambda p: (p.ecosystem, p.name)), used


# ------------------------------------------------------------------ Docker images

def collect_docker_image(image: str, ecosystem_override: Optional[str] = None,
                         runner: Runner = default_runner) -> Tuple[SystemInfo, List[Package]]:
    """Inventory a container image without keeping it running (docker run --rm)."""
    if not shutil.which("docker"):
        raise InventoryError("docker was not found on PATH")

    def run_in(entrypoint: str, *args: str) -> Tuple[int, str]:
        return runner(["docker", "run", "--rm", "--entrypoint", entrypoint, image, *args], 600)

    rc, text = run_in("cat", "/etc/os-release")
    if rc != 0 or not text.strip():
        raise InventoryError(
            f"could not read /etc/os-release from '{image}' (is Docker running, is the image "
            "name right, or is it a distroless/scratch image without a shell toolset?)")
    info = system_info_from_os_release(f"docker:{image}", "docker", text, ecosystem_override)
    pkgs: List[Package] = []
    eco = info.os_ecosystem
    if eco:
        family = eco.split(":", 1)[0]
        if family in ("Debian", "Ubuntu"):
            rc, out = run_in("dpkg-query", "-W", "-f", DPKG_FORMAT)
            pkgs += parse_dpkg(out, eco) if rc == 0 else []
        elif family == "Alpine":
            rc, out = run_in("apk", "list", "-I")
            pkgs += parse_apk(out, eco) if rc == 0 else []
        elif family in ("AlmaLinux", "Rocky Linux"):
            rc, out = run_in("rpm", "-qa", "--qf", RPM_FORMAT + "\n")
            pkgs += parse_rpm(out, eco) if rc == 0 else []
        if not pkgs:
            info.notes.append("package manager query inside the image returned nothing")
    for py in ("python3", "python"):
        rc, out = run_in(py, "-m", "pip", "list", "--format=json")
        if rc == 0:
            try:
                pkgs += [Package(normalize_pypi(p["name"]), p["version"], "PyPI", "pip")
                         for p in json.loads(out)]
            except (ValueError, KeyError, TypeError):
                pass
            break
    return info, pkgs
