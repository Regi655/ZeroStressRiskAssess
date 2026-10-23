"""Package managers: apt (Debian/Ubuntu) and dnf/yum (RHEL family).

Interface:
    refresh()            update the repository index
    status(pkg)          -> (installed_version|None, candidate_version|None, upgradable)
    install(pkgs) / upgrade(pkgs) / remove(pkgs)
    snapshot()           -> set of the names of all installed packages
    config_only()        -> packages removed earlier whose configuration files are still there (apt only)
    block_daemons() / allow_daemons()

The "candidate version" is the version the distribution repository designates as supported for
THAT operating system. Installing the latest upstream release manually could break dependencies
and would not receive the distribution's security updates.
"""
from __future__ import annotations

import re
import shlex


def _q(pkgs) -> str:
    """Each package name becomes ONE shell argument (defence in depth: names coming from the target
    cannot inject ';', '$(...)' and similar).
    """
    return " ".join(shlex.quote(p) for p in pkgs)


class PkgManager:
    name = ""
    can_simulate = False  # True if removal can be simulated without executing it

    def __init__(self, rem):
        self.rem = rem

    def simulate_remove(self, pkgs):
        return set()

    def config_only(self):
        return set()

    def block_daemons(self):
        pass

    def allow_daemons(self):
        pass


# ======================================================================= APT
class Apt(PkgManager):
    name = "apt"
    can_simulate = True
    # Prevents interactive prompts, which would block the SSH session indefinitely.
    ENV = "DEBIAN_FRONTEND=noninteractive "
    # If another apt process is running (typically unattended-upgrades right after boot), apt-get
    # normally fails immediately on the lock; this makes it wait up to 10 minutes
    # (apt >= 1.9.11, Ubuntu 20.04+; older versions ignore the option).
    LOCK = "-o DPkg::Lock::Timeout=600 "
    POLICY = "/usr/sbin/policy-rc.d"

    def __init__(self, rem):
        super().__init__(rem)
        self._policy_created = False

    def block_daemons(self):
        """On Debian/Ubuntu installing a package STARTS its services immediately (e.g. the ClamAV
        freshclam daemon, which would lock the manual signature update). A policy-rc.d file
        returning 101 tells dpkg not to start any service. It is created only if absent.
        """
        if self.rem.run(f"test -e {self.POLICY}").rc != 0:
            self.rem.run(f"printf '#!/bin/sh\\nexit 101\\n' > {self.POLICY} && chmod 755 {self.POLICY}",
                         sudo=True)
            self._policy_created = True

    def allow_daemons(self):
        if self._policy_created:
            self.rem.run(f"rm -f {self.POLICY}", sudo=True)
            self._policy_created = False

    def refresh(self):
        return self.rem.run(self.ENV + "apt-get " + self.LOCK + "update -qq", sudo=True, timeout=900)

    def status(self, pkg):
        r = self.rem.run(f"dpkg-query -W -f='${{db:Status-Status}}|${{Version}}' {pkg} 2>/dev/null")
        installed = None
        if r.rc == 0 and r.out.startswith("installed|"):
            installed = r.out.split("|", 1)[1]
        c = self.rem.run(f"apt-cache policy {pkg} | awk '/Candidate:/{{print $2}}'")
        candidate = c.out.strip() or None
        if candidate == "(none)":
            candidate = None
        upgradable = False
        if installed and candidate:
            # Versions must not be compared as strings ("10" < "9"):
            # dpkg's own comparison algorithm is used instead.
            upgradable = self.rem.run(
                f"dpkg --compare-versions {shlex.quote(installed)} lt {shlex.quote(candidate)}").rc == 0
        return installed, candidate, upgradable

    def install(self, pkgs):
        # --no-install-recommends: avoids pulling in unrelated packages (e.g. a mail server).
        return self.rem.run(
            self.ENV + "apt-get " + self.LOCK + "install -y --no-install-recommends "
            "-o Dpkg::Options::=--force-confold " + _q(pkgs),
            sudo=True, timeout=1800)

    def upgrade(self, pkgs):
        # --only-upgrade: upgrades ONLY if already installed, never installs anything else.
        return self.rem.run(
            self.ENV + "apt-get " + self.LOCK + "install -y --only-upgrade --no-install-recommends "
            "-o Dpkg::Options::=--force-confold " + _q(pkgs),
            sudo=True, timeout=1800)

    def _states(self):
        r = self.rem.run("dpkg-query -W -f='${db:Status-Status} ${Package}\\n'")
        return [line.split() for line in r.out.splitlines() if len(line.split()) == 2]

    def snapshot(self):
        # INSTALLED packages only. dpkg-query -W also lists packages removed without purge (state config-files,
        # "rc" in dpkg -l): counted as present, a tool removed earlier by the user looked "already there", was
        # reinstalled by us and then never removed (seen with smartmontools on the development sandbox).
        return {p for state, p in self._states() if state == "installed"}

    def config_only(self):
        return {p for state, p in self._states() if state == "config-files"}

    def simulate_remove(self, pkgs):
        """`apt-get -s` (simulate) lists, as "Purg name" (or "Remv") lines, EVERYTHING that would be
        removed, including reverse dependencies (packages depending on ours).
        If the list contains anything we did not install, the removal is aborted.
        """
        r = self.rem.run(self.ENV + "apt-get -s purge " + _q(pkgs), sudo=True, timeout=300)
        if r.rc != 0:
            return None  # simulation failed: NOT verifiable
        # With "purge" apt prints "Purg name [version]" (with "remove" it would be "Remv").
        return {l.split()[1] for l in r.out.splitlines()
                if l.startswith(("Purg ", "Remv ")) and len(l.split()) > 1}

    def remove(self, pkgs, keep_config=()):
        # purge also removes configuration files and data (e.g. the ClamAV signature database).
        # keep_config: packages whose configuration files were ALREADY there before us (removed earlier without
        # purge): plain remove, so the target goes back to exactly that state and the owner's files stay.
        keep = [p for p in pkgs if p in set(keep_config)]
        purge = [p for p in pkgs if p not in set(keep_config)]
        r = None
        if purge:
            r = self.rem.run(self.ENV + "apt-get " + self.LOCK + "purge -y " + _q(purge), sudo=True, timeout=900)
        if keep:
            rk = self.rem.run(self.ENV + "apt-get " + self.LOCK + "remove -y " + _q(keep), sudo=True, timeout=900)
            r = rk if r is None or rk.rc != 0 else r
        self.rem.run("apt-get clean", sudo=True)  # frees the cache of downloaded .deb files
        return r


# ======================================================================= DNF / YUM
class Dnf(PkgManager):
    """RHEL, Rocky, Alma, CentOS Stream, Fedora, Oracle Linux (dnf; yum on releases 7 and earlier)."""
    name = "dnf"
    can_simulate = True
    # By default dnf, when removing a package, also removes its dependencies left unused
    # (clean_requirements_on_remove). It could then take away a package that was ALREADY there before us, if it
    # was orphaned and our tools "adopted" it. The exact list computed from the snapshot difference is removed
    # instead (it already contains the dependencies we installed).
    NO_AUTOREMOVE = "--setopt=clean_requirements_on_remove=False "

    def __init__(self, rem, binary="dnf"):
        super().__init__(rem)
        self.bin = binary

    def refresh(self):
        return self.rem.run(f"{self.bin} -q makecache", sudo=True, timeout=900)

    def status(self, pkg):
        r = self.rem.run(f"rpm -q --qf '%{{VERSION}}-%{{RELEASE}}' {shlex.quote(pkg)}")
        installed = r.out if r.rc == 0 else None
        # check-update exit code: 100 = updates exist, 0 = none.
        c = self.rem.run(f"{self.bin} -q check-update {shlex.quote(pkg)}", sudo=True, timeout=600)
        candidate, upgradable = None, False
        if c.rc == 100:
            for line in c.out.splitlines():
                t = line.split()
                if len(t) >= 3 and t[0].startswith(pkg):
                    candidate, upgradable = t[1], bool(installed)
                    break
        elif installed:
            candidate = installed
        if installed is None and candidate is None:
            a = self.rem.run(f"{self.bin} -q list --available {shlex.quote(pkg)}", sudo=True)
            if a.rc == 0 and a.out.strip():
                t = a.out.splitlines()[-1].split()
                candidate = t[1] if len(t) > 1 else "?"
        return installed, candidate, upgradable

    def install(self, pkgs):
        return self.rem.run(f"{self.bin} install -y " + _q(pkgs), sudo=True, timeout=1800)

    def upgrade(self, pkgs):
        return self.rem.run(f"{self.bin} upgrade -y " + _q(pkgs), sudo=True, timeout=1800)

    def snapshot(self):
        r = self.rem.run("rpm -qa --qf '%{NAME}\\n'")
        return set(r.out.split())

    def simulate_remove(self, pkgs):
        """`rpm -e --test`: tries to remove EXACTLY these packages without doing it. If another installed package
        needs one of them, rpm answers "X is needed by (installed) Y" with rc=1: Y is not ours, so it is returned
        and the tool aborts the removal (as with the apt simulation)."""
        r = self.rem.run("rpm -e --test " + _q(pkgs), sudo=True, timeout=300)
        if r.rc == 0:
            return set(pkgs)
        needed_by = set(re.findall(r"needed by \(installed\) (\S+)", r.out))
        return (set(pkgs) | needed_by) if needed_by else None   # any other error: NOT verifiable

    def remove(self, pkgs, keep_config=()):
        r = self.rem.run(f"{self.bin} remove -y " + self.NO_AUTOREMOVE + _q(pkgs), sudo=True, timeout=900)
        self.rem.run(f"{self.bin} clean all", sudo=True)
        return r
