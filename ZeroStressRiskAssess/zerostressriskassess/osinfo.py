"""Target operating system detection (first step of every assessment).

Package names, package manager, repositories and default configurations differ between distributions, so
before installing or checking anything the tool must know which family the target belongs to.

How the distribution is recognised, in order of reliability:
  1. /etc/os-release (or /usr/lib/os-release): the systemd standard. ID names the distribution, ID_LIKE the
     families it derives from (Ubuntu: "debian"; Rocky: "rhel centos fedora"; CachyOS: "arch"), so a
     derivative never seen before is still placed in the right family;
  2. legacy release files (/etc/redhat-release, /etc/debian_version, /etc/arch-release...), for very old or
     minimal systems without os-release;
  3. the package managers actually present: a family is supported only if its package manager is there
     (a Debian-like ID without apt-get, for example a stripped container, is not treated as Debian).

Support levels:
  - supported families: Debian/Ubuntu (apt) and RHEL/Rocky/Alma/CentOS Stream/Fedora/Oracle (dnf, or yum on
    old releases). Every check runs;
  - among those, the releases the tool was actually tested on are listed in TESTED; on the others the
    assessment runs, but the report says the release was not tested;
  - other families (Arch, SUSE, Alpine, unknown) are recognised and reported by name, and the assessment
    stops with a clear message: the package-based checks would give wrong answers there. Use --recon-only
    for an external assessment of those machines.
"""
from __future__ import annotations

from dataclasses import dataclass, field


class UnsupportedOS(Exception):
    pass


# Family -> IDs that identify it (in ID or ID_LIKE). The first family whose set matches wins, ID first.
FAMILY_IDS = {
    "debian": {"debian", "ubuntu", "linuxmint", "pop", "kali", "raspbian", "elementary", "zorin", "neon", "devuan"},
    "rhel": {"rhel", "fedora", "centos", "rocky", "almalinux", "ol", "amzn", "scientific", "eurolinux", "circle"},
    "arch": {"arch", "archlinux", "cachyos", "manjaro", "endeavouros", "garuda", "artix"},
    "suse": {"suse", "opensuse", "sles", "sled", "opensuse-leap", "opensuse-tumbleweed"},
    "alpine": {"alpine"},
}
FAMILY_NAMES = {"debian": "Debian/Ubuntu", "rhel": "RHEL/Fedora", "arch": "Arch", "suse": "SUSE",
                "alpine": "Alpine", "unknown": "unknown"}
# Legacy release files, used only when os-release is missing.
RELEASE_FILES = {"/etc/redhat-release": "rhel", "/etc/debian_version": "debian", "/etc/arch-release": "arch",
                 "/etc/SuSE-release": "suse", "/etc/alpine-release": "alpine"}
# Package managers of the supported families, in order of preference.
SUPPORTED = {"debian": ("apt-get",), "rhel": ("dnf", "yum")}
# Releases the tool was run on, end to end (ID, major version). See README, Requirements.
TESTED = {("ubuntu", "22"), ("ubuntu", "24"), ("ubuntu", "26"), ("rocky", "9")}

SCRIPT = r"""
f=/etc/os-release; [ -r "$f" ] || f=/usr/lib/os-release
[ -r "$f" ] && sed 's/^/OSR|/' "$f"
for x in /etc/redhat-release /etc/debian_version /etc/arch-release /etc/SuSE-release /etc/alpine-release; do
  [ -r "$x" ] && printf 'REL|%s|%s\n' "$x" "$(head -n1 "$x" | cut -c1-120)"
done
for m in apt-get dnf yum pacman zypper apk; do command -v "$m" >/dev/null 2>&1 && echo "PM|$m"; done
true
"""


@dataclass
class OSInfo:
    id: str
    version_id: str
    pretty: str
    pkg_mgr: str   # "apt" | "dnf" | "yum"
    kernel: str
    arch: str
    container: bool = False
    family: str = "debian"         # "debian" | "rhel"
    tested: bool = True            # release among TESTED
    notes: list = field(default_factory=list)

    @property
    def family_key(self) -> str:
        """Key for the package tables: 'apt' or 'dnf' (yum uses the same package names)."""
        return "apt" if self.pkg_mgr == "apt" else "dnf"


def parse(text: str) -> dict:
    """Output of SCRIPT -> {"osr": {KEY: value}, "release": {path: first line}, "pkg_mgrs": [..]}. Pure function."""
    d = {"osr": {}, "release": {}, "pkg_mgrs": []}
    for line in text.splitlines():
        tag, _, rest = line.partition("|")
        if tag == "OSR" and "=" in rest:
            k, v = rest.split("=", 1)
            d["osr"][k.strip()] = v.strip().strip('"').strip("'")
        elif tag == "REL":
            path, _, first = rest.partition("|")
            d["release"][path] = first.strip()
        elif tag == "PM" and rest.strip():
            d["pkg_mgrs"].append(rest.strip())
    return d


def classify(d: dict) -> dict:
    """Facts from parse() -> {"family", "id", "version", "pretty", "pkg_mgr", "supported", "tested", "reason"}.
    Pure function: all the decisions about the distribution are here, testable without a target.
    """
    osr = d["osr"]
    did = osr.get("ID", "").lower()
    like = osr.get("ID_LIKE", "").lower().split()
    family = "unknown"
    # ID first: a derivative may list several parents in ID_LIKE, its own ID is the most specific fact.
    for token in [did] + like:
        family = next((f for f, ids in FAMILY_IDS.items() if token in ids), "unknown")
        if family != "unknown":
            break
    pretty = osr.get("PRETTY_NAME") or osr.get("NAME") or ""
    if family == "unknown" and not osr:
        family = next((fam for path, fam in RELEASE_FILES.items() if path in d["release"]), "unknown")
        pretty = pretty or next(iter(d["release"].values()), "")
        did = did or family
    version = osr.get("VERSION_ID", "")
    out = {"family": family, "id": did or "?", "version": version or "?", "pretty": pretty or "unknown system",
           "pkg_mgr": "", "supported": False, "tested": False, "reason": ""}

    if family not in SUPPORTED:
        present = ", ".join(d["pkg_mgrs"]) or "none found"
        out["reason"] = (f"{out['pretty']}: {FAMILY_NAMES[family]} family (package managers: {present}). "
                         "Supported for the full assessment: Debian/Ubuntu (apt) and RHEL, Rocky, Alma, CentOS Stream, "
                         "Fedora (dnf). Use --recon-only for an external assessment without logging in.")
        return out
    mgr = next((m for m in SUPPORTED[family] if m in d["pkg_mgrs"]), "")
    if not mgr:
        out["reason"] = (f"{out['pretty']}: {FAMILY_NAMES[family]} family, but its package manager "
                         f"({' or '.join(SUPPORTED[family])}) is not installed: the package-based checks cannot run. "
                         "Use --recon-only for an external assessment.")
        return out
    out.update(pkg_mgr="apt" if mgr == "apt-get" else mgr, supported=True,
               tested=(did, version.split(".")[0]) in TESTED)
    return out


def detect(rem) -> OSInfo:
    c = classify(parse(rem.run(SCRIPT).out))
    if not c["supported"]:
        raise UnsupportedOS(c["reason"])
    notes = []
    if not c["tested"]:
        notes.append(f"{c['pretty']} is in a supported family ({FAMILY_NAMES[c['family']]}) but this release was not "
                     "tested end to end: every check runs, verify unexpected results by hand.")
    if c["pkg_mgr"] == "yum":
        notes.append("yum instead of dnf: very old RHEL/CentOS release (7 or earlier), end of life.")
    cont = rem.run("[ -f /.dockerenv ] || [ -f /run/.containerenv ] || "
                   "grep -qaE 'container=(docker|podman|lxc)' /proc/1/environ 2>/dev/null", sudo=True).rc == 0
    return OSInfo(
        id=c["id"],
        version_id=c["version"],
        pretty=c["pretty"],
        pkg_mgr=c["pkg_mgr"],
        kernel=rem.run("uname -r").out,
        arch=rem.run("uname -m").out,
        container=cont,
        family=c["family"],
        tested=c["tested"],
        notes=notes,
    )
