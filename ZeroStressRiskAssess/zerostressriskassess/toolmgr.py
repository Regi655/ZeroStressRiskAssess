"""Tool lifecycle on the target: check -> install/upgrade -> remove at the end.

Safe uninstallation
-------------------
Before changing anything, a snapshot of all installed packages is taken. At the end a second
snapshot is taken and ONLY the difference is removed, so a tool already present on the target
is never uninstalled.

Safeguards against a wrong removal:
  1. cleanup runs ONLY if the initial snapshot was actually taken (`_prepared`); otherwise the
     "difference" would be every package on the system;
  2. with apt the removal is SIMULATED first: if it would touch a package we did not install,
     it is aborted;
  3. a maximum number of packages can be removed automatically;
  4. a MANIFEST on the target records the initial snapshot, so `--recover` can clean up later if
     the connection drops midway.
"""
from __future__ import annotations

import json
import shlex
from datetime import datetime

from .osinfo import OSInfo
from .pkgmgr import Apt, Dnf
from .validate import split_pkgs

# Tools installed on the target with apt and removed at the end: ClamAV (antivirus) and chkrootkit (rootkits).
# Lynis is PORTABLE instead (copied and deleted, see portable.py): no package involved.
# binutils provides `strings`, without which chkrootkit stops immediately ("can't find strings"). Normal
# systems already have it (then it is neither installed nor removed); minimal containers do not.
# On the RHEL family ClamAV and chkrootkit live in EPEL; freshclam is a separate package there
# ("clamav-freshclam" on EPEL 8/9/10: the older name "clamav-update" left the signatures unupdated on Rocky 9).
TOOLS = {"clamav": {"apt": ["clamav"], "dnf": ["clamav", "clamav-freshclam"], "bin": "clamscan"},
         "chkrootkit": {"apt": ["chkrootkit", "binutils"], "dnf": ["chkrootkit", "binutils"], "bin": "chkrootkit"},
         "smartmontools": {"apt": ["smartmontools"], "dnf": ["smartmontools"], "bin": "smartctl"}}
# Which check uses which tool: if the check is skipped (--skip) the tool is not installed.
TOOL_SCAN = {"clamav": "clamav", "chkrootkit": "chkrootkit", "smartmontools": "disks"}
# Tools that are useless in a container (the hardware belongs to the host): not installed there.
HOST_ONLY_TOOLS = {"smartmontools"}
# SUPPORT packages (needed by a tool, not the tool itself): installed only if missing and never upgraded.
# Upgrading binutils on a server would be an unnecessary change.
HELPER_PKGS = {"binutils"}
# Tools that are NEVER installed but are used if the target already has them (name -> binary).
# rkhunter: a baseline created now, on a system that may already be compromised, would be worthless.
DETECT_ONLY = {"rkhunter": "rkhunter"}

MANIFEST_DIR = "/var/lib/zerostressriskassess"
MANIFEST = MANIFEST_DIR + "/manifest.json"
MAX_AUTO_REMOVE = 80  # a normal installation of these tools pulls in a few dozen packages


class StaleManifest(RuntimeError):
    pass


def make_pm(rem, osinfo: OSInfo):
    return Apt(rem) if osinfo.pkg_mgr == "apt" else Dnf(rem, osinfo.pkg_mgr)


class ToolManager:
    def __init__(self, rem, osinfo: OSInfo, keep: bool = False, skip=(), portable=None, no_install: bool = False):
        self.rem, self.osinfo, self.keep = rem, osinfo, keep
        self.no_install = no_install   # --no-install: nothing installed, the tools are used only if already there
        self.skip = set(skip)
        self.portable = dict(portable or {})   # tool -> version: copied from the controller, no package
        self.pm = make_pm(rem, osinfo)
        self.log: list[dict] = []        # reported: what was done on the target
        self.available: set[str] = set()  # tools actually usable
        self._before: set[str] = set()
        self._conf_before: set[str] = set()
        self._prepared = False            # True only after a successful snapshot + manifest
        self.installed: list[str] = []    # packages installed by us during this run

    def _note(self, **kw):
        self.log.append(kw)

    # ------------------------------------------------------------------ manifest
    def _write_manifest(self) -> bool:
        data = json.dumps({
            "version": 1,
            "created": datetime.now().isoformat(timespec="seconds"),
            "pkg_mgr": self.osinfo.pkg_mgr,
            "policy_rc_created": getattr(self.pm, "_policy_created", False),
            "before": sorted(self._before),
            "config_only": sorted(self._conf_before),
        })
        # Uploaded first to the SSH user's home directory, then moved into place by root with mode 600
        # (it only contains package names, but nobody else needs it).
        tmp = f"{self.rem.home()}/.riskassess_manifest.tmp"
        self.rem.upload_text(tmp, data)
        r = self.rem.run(f"install -D -m 600 -o root -g root {shlex.quote(tmp)} {MANIFEST} "
                         f"&& rm -f {shlex.quote(tmp)}", sudo=True)
        return r.rc == 0

    def _delete_manifest(self):
        self.rem.run(f"rm -f {MANIFEST}; rmdir {MANIFEST_DIR} 2>/dev/null; true", sudo=True)

    # ------------------------------------------------------------------ preparation
    def prepare(self):
        key = self.osinfo.family_key

        # An existing manifest means a previous run was interrupted. Proceeding would make its packages
        # look "already present before us" and they would never be removed: stop and let the operator
        # decide (--recover).
        if self.rem.run(f"test -e {MANIFEST}", sudo=True).rc == 0:
            raise StaleManifest("A manifest from an interrupted run exists on the target. "
                                "Run again with --recover to clean up, then retry.")

        if self.no_install:
            # No repository refresh, no snapshot, no manifest: the target's package state is not touched at all, so
            # there is nothing to remove at the end (_prepared stays False and cleanup() does nothing).
            self._detect()
            for tool in TOOLS:
                if TOOL_SCAN.get(tool) in self.skip or (tool in HOST_ONLY_TOOLS and self.osinfo.container):
                    continue
                lost = "SMART disk health not checked" if tool == "smartmontools" else "its check is skipped"
                self._note(tool=tool, package="-", action=(
                    "already present on the target: used, not modified (--no-install)" if tool in self.available
                    else f"NOT present and not installed (--no-install): {lost}"))
            return

        r = self.pm.refresh()  # without a fresh index the candidate version would be stale
        if r.rc != 0:
            self._note(tool="*", package="-", action="repository index update FAILED "
                       "(repositories unreachable or archived: candidate versions unreliable)",
                       detail=r.out[-300:])

        self._before = self.pm.snapshot()  # snapshot BEFORE changing anything
        self._conf_before = self.pm.config_only()   # removed earlier, configuration kept: restored as it was
        if not self._before:
            raise RuntimeError("Empty list of installed packages: aborting for safety.")
        self.pm.block_daemons()
        if not self._write_manifest():
            self.pm.allow_daemons()
            raise RuntimeError("Cannot write the manifest on the target: aborting before installing.")
        self._prepared = True

        to_install, to_upgrade, epel_tried = [], [], False
        for tool, spec in TOOLS.items():
            if TOOL_SCAN.get(tool) in self.skip:
                self._note(tool=tool, package="-", action="not needed (check skipped with --skip)")
                continue
            if tool in HOST_ONLY_TOOLS and self.osinfo.container:
                self._note(tool=tool, package="-", action="not needed in a container (the disks belong to the host)")
                continue
            if tool in self.portable:
                self._note(tool=tool, package="-", action=f"portable from the controller (version {self.portable[tool]}): "
                           "no package installed, temporary directory deleted after the scan")
                continue
            for pkg in spec[key]:
                inst, cand, upg = self.pm.status(pkg)
                if pkg in HELPER_PKGS and inst is not None:
                    continue  # already present: left untouched and not recorded

                # On RHEL and derivatives these packages are in EPEL, not in the base repositories. epel-release
                # is installed like any other package: it is in the snapshot difference and removed at the end.
                if inst is None and cand is None and key == "dnf" and not epel_tried:
                    epel_tried = True
                    r = self.pm.install(["epel-release"])
                    self._note(tool="epel-release", package="epel-release",
                               action=f"installed to reach the EPEL repository (rc={r.rc}), removed at the end")
                    self.pm.refresh()
                    inst, cand, upg = self.pm.status(pkg)

                if inst is None and cand is None:
                    self._note(tool=tool, package=pkg, action="NOT available in the repositories of "
                               f"{self.osinfo.pretty}")
                elif inst is None:
                    to_install.append(pkg)
                    self._note(tool=tool, package=pkg, action="to be installed", to=cand)
                elif upg:
                    to_upgrade.append(pkg)
                    self._note(tool=tool, package=pkg, action="already present, to be upgraded",
                               frm=inst, to=cand)
                else:
                    self._note(tool=tool, package=pkg, action="already present and up to date", frm=inst)

        if to_install:
            self.installed = list(to_install)
            r = self.pm.install(to_install)
            self._note(tool="*", package=",".join(to_install),
                       action=f"installation rc={r.rc}", detail=r.out[-400:] if r.rc else "")
        if to_upgrade:
            r = self.pm.upgrade(to_upgrade)
            self._note(tool="*", package=",".join(to_upgrade),
                       action=f"upgrade rc={r.rc}", detail=r.out[-400:] if r.rc else "")

        self._detect()

    def _detect(self):
        # Final check: rely on the binary being present, not on the exit code.
        # sudo=True because some binaries live in /usr/sbin, outside regular users' PATH.
        bins = {t: s["bin"] for t, s in TOOLS.items()}
        bins.update(DETECT_ONLY)  # tools used only if already present
        for tool, binary in bins.items():
            if self.rem.run(f"command -v {binary}", sudo=True).rc == 0:
                self.available.add(tool)
        for tool in DETECT_ONLY:
            if tool in self.available and tool not in TOOLS:
                self._note(tool=tool, package=tool, action="already present on the target: used, not modified")

    # ------------------------------------------------------------------ cleanup
    def cleanup(self):
        """Must ALWAYS be called (finally block), even if a check failed."""
        try:
            if not self._prepared:
                return  # no initial snapshot = NO removal (otherwise "new" would mean everything)
            after = self.pm.snapshot()
            if not after:
                self._note(tool="*", package="-", action="empty final list: nothing removed")
                return
            new_pkgs, bad = split_pkgs(after - self._before)
            if bad:
                self._note(tool="*", package="-", action="anomalous package names ignored",
                           detail=",".join(bad)[:300])
            if self.keep:
                self._note(tool="*", package=",".join(new_pkgs), action="NOT removed (--keep-tools); "
                           "manifest kept: use --recover to clean up")
                return
            if not new_pkgs:
                self._note(tool="*", package="-", action="no packages to remove")
                self._delete_manifest()
                return
            if len(new_pkgs) > MAX_AUTO_REMOVE:
                self._note(tool="*", package="-", action=f"{len(new_pkgs)} new packages: too many for "
                           "automatic removal, NOT removed (manifest kept)")
                return
            if self.pm.can_simulate:
                touched = self.pm.simulate_remove(new_pkgs)
                if touched is None or (touched - set(new_pkgs)):
                    extra = "" if touched is None else ",".join(sorted(touched - set(new_pkgs)))[:300]
                    self._note(tool="*", package=",".join(new_pkgs),
                               action="removal CANCELLED: the simulation cannot be verified or would touch "
                                      "packages not installed by us (manifest kept)", detail=extra)
                    return

            r = self.pm.remove(new_pkgs, keep_config=self._conf_before)
            leftovers = sorted(set(new_pkgs) & self.pm.snapshot())
            self._note(tool="*", package=",".join(new_pkgs), action=f"removal rc={r.rc}",
                       detail=("STILL PRESENT: " + ",".join(leftovers)) if leftovers else "")
            if r.rc == 0 and not leftovers:
                self._delete_manifest()
        finally:
            self.pm.allow_daemons()


# ---------------------------------------------------------------------- recovery
def recover_interrupted(rem, osinfo: OSInfo, confirm, log=print) -> bool:
    """Clean up the target after an interrupted run, using the manifest.

    `confirm(text) -> bool` asks the operator for confirmation: between the interruption and the
    recovery someone may have installed their own packages, which would look "new".
    """
    from .portable import CLEANUP
    rem.run(CLEANUP, sudo=True)   # portable Lynis possibly left behind by an interrupted run
    r = rem.run(f"cat {MANIFEST}", sudo=True)
    if r.rc != 0:
        log("No manifest on the target: nothing to recover.")
        return False
    try:
        data = json.loads(r.out)
        before = set(data["before"])
    except (ValueError, KeyError, TypeError):
        log("Unreadable manifest: nothing removed.")
        return False
    if not before:
        log("Manifest without an initial list: nothing removed.")
        return False

    pm = make_pm(rem, osinfo)
    new, bad = split_pkgs(pm.snapshot() - before)
    if new:
        log(f"Packages installed after the interrupted run ({len(new)}): {', '.join(new)}")
        if pm.can_simulate:
            touched = pm.simulate_remove(new)
            if touched is None or (touched - set(new)):
                log("Cancelled: the removal would touch other packages or cannot be verified.")
                return False
        if not confirm(f"Remove these {len(new)} packages from the target?"):
            log("Cancelled by the user.")
            return False
        rr = pm.remove(new, keep_config=set(data.get("config_only", [])))
        log(f"Removal completed (rc={rr.rc}).")
        if rr.rc != 0:
            return False
    else:
        log("No new packages compared with the manifest.")
    if data.get("policy_rc_created"):
        rem.run("rm -f /usr/sbin/policy-rc.d", sudo=True)
    rem.run(f"rm -f {MANIFEST}; rmdir {MANIFEST_DIR} 2>/dev/null; true", sudo=True)
    log("Manifest rimosso: target ripulito.")
    return True
