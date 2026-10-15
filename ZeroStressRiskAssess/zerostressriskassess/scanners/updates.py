"""Pending updates (security updates in particular).

The most common cause of compromise is a vulnerability that is ALREADY known and ALREADY fixed by the
vendor, but whose fix has not been installed. Counting pending updates and isolating the security ones
is the check with the best cost/benefit ratio. Nothing is installed: `apt-get -s` (simulation) only
lists what would be done. The package index is refreshed during tool preparation (ClamAV); with
--skip clamav the lists already present on the target are used.
"""
from __future__ import annotations

import re
import shlex

from ..models import ScanResult
from ..validate import split_pkgs

INST_RE = re.compile(r"^Inst (\S+) (?:\[([^\]]*)\] )?\(([^)]*)\)")
# Packages whose unfixed vulnerabilities weigh more: remote access, privileges, system core.
CORE_RE = re.compile(r"^(openssh-.*|libssh.*|openssl|libssl.*|sudo|linux-image.*|linux-generic.*|libc6|libc-bin|"
                     r"policykit-1|polkitd|pkexec|systemd|glibc.*|kernel.*|bash|apache2.*|nginx.*|bind9.*|samba.*)$")


def parse_apt_sim(text: str):
    """From `apt-get -s ...` derive (updates, security, held back, new_from_security). Pure function.

    "new_from_security": packages NOT installed that the upgrade would pull in as dependencies from
    the -security pocket. apt-check counts them as security updates, but they are not on the system
    today: they are not an existing flaw and are only explained in the report.
    """
    allp, sec, new_sec = [], [], []
    for line in text.splitlines():
        m = INST_RE.match(line)
        if not m:
            continue
        name, old, origin = m.groups()
        is_sec = "-security" in origin or "esm" in origin.lower()
        if old is None:
            if is_sec:
                new_sec.append(name)
            continue  # new package: not an update of something already installed
        allp.append(name)
        if is_sec:
            sec.append(name)
    held = []
    m = re.search(r"kept back:\n((?:\s+.*\n?)+)", text)
    if m:
        held = m.group(1).split()
    return allp, sec, held, new_sec


# A package is "security" if a newer version than the installed one EXISTS in the -security pocket,
# even when the version apt would install (the candidate) comes from -updates.
# Typical case: 1.0 installed, security fix 1.1 in -security, then 1.2 in -updates.
# `apt-get -s` only shows the origin of 1.2 and the flaw would look "non-security".
# Same criterion as Ubuntu's apt-check (also used by Lynis).
SEC_SCRIPT = r"""
for p in @PKGS@; do
  inst=$(dpkg-query -W -f='${Version}' "$p" 2>/dev/null) || continue
  apt-cache madison "$p" 2>/dev/null | awk -F'|' '$3 ~ /-security|esm/ {gsub(/ /,"",$2); print $2}' |
  while read -r v; do
    if dpkg --compare-versions "$v" gt "$inst"; then echo "SEC|$p"; break; fi
  done
done
"""


def _security_by_pocket(rem, pkgs):
    if not pkgs:
        return set()
    out = rem.run(SEC_SCRIPT.replace("@PKGS@", " ".join(shlex.quote(p) for p in pkgs)),
                  sudo=True, timeout=300).out
    return {l[4:] for l in out.splitlines() if l.startswith("SEC|")} & set(pkgs)


def run(ctx) -> ScanResult:
    res, rem = ScanResult("updates"), ctx.rem
    # `upgrade` holds back packages that require installing/removing others ("kept back");
    # `dist-upgrade` includes them. A held-back package can carry a security fix (e.g. netplan.io):
    # counting vulnerabilities requires the full list, as apt-check does.
    _, _, held, _ = parse_apt_sim(rem.run("apt-get -s upgrade 2>&1", sudo=True, timeout=300).out)
    allp, sec, _, new_sec = parse_apt_sim(rem.run("apt-get -s dist-upgrade 2>&1", sudo=True, timeout=300).out)
    allp, _ = split_pkgs(allp)  # names end up in a command: valid names only
    sec = sorted(set(sec) | _security_by_pocket(rem, allp))
    # Cross-check with Ubuntu's apt-check (if present): prints "total;security".
    ac = rem.run("/usr/lib/update-notifier/apt-check 2>&1").out.strip()
    if re.fullmatch(r"\d+;\d+", ac):
        res.data["apt_check"] = ac
    unatt = rem.run("dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null").out
    per = rem.run("apt-config dump 2>/dev/null | grep -i 'APT::Periodic::Unattended-Upgrade'").out
    auto = "install ok installed" in unatt and '"1"' in per

    allp, bad = split_pkgs(allp)
    sec = [p for p in sec if p in allp]
    # If apt-check (Ubuntu) counts more, its number prevails: overestimating a flaw is preferable
    # to reporting "no security updates" when the official tool says otherwise.
    n_sec, n_all = len(sec), len(allp)
    new_sec, _ = split_pkgs(new_sec)
    if new_sec:
        res.add("info", f"{len(new_sec)} new packages would be installed from the security pocket",
                ", ".join(new_sec[:15]) + ". They are dependencies of other updates and are NOT installed today: "
                "not an existing vulnerability (apt-check, however, counts them as security updates).")
    if "apt_check" in res.data:
        # apt-check's first number also includes NEW packages (dependencies): it is not the number of
        # updates for what is installed, so it is kept for comparison only.
        ac_sec = int(res.data["apt_check"].split(";")[1])
        unexplained = ac_sec - n_sec - len(new_sec)
        if unexplained > 0:
            res.add("info", f"apt-check counts {ac_sec} security updates: {unexplained} not identified by the tool",
                    "They are included in the severity as a precaution. Verify with: apt-get -s dist-upgrade | grep '^Inst' | grep -- -security")
            n_sec += unexplained
    res.data.update({"upgradable": n_all, "security": n_sec, "security_named": sec, "new_from_security": new_sec,
                     "held_back": len(held), "automatic_updates": auto})

    core = [p for p in sec if CORE_RE.match(p)]
    # A "security" title lists ONLY security packages: a mixed list would make non-vulnerable
    # packages look vulnerable.
    sec_detail = ", ".join(sec[:20]) if sec else "packages not identified by the tool (see the apt-check line)"
    sample = ", ".join([p for p in allp if p not in sec][:20])
    if n_sec and (core or n_sec >= 20):
        res.add("high", f"{n_sec} security updates not installed"
                + (f" (including critical components: {', '.join(core[:8])})" if core else ""), sec_detail)
    elif n_sec:
        res.add("medium", f"{n_sec} security updates not installed", sec_detail)
    elif allp:
        res.add("low", f"{n_all} non-security updates to install", sample)
    else:
        res.add("info", "No pending updates")
    if allp and n_sec:
        res.add("info", f"Upgradable packages: {n_all}, of which security: {n_sec}")
    if held:
        res.add("low", f"{len(held)} packages held back (kept back): they require a 'full' upgrade",
                ", ".join(held[:15]))

    if not auto:
        res.add("low", "Automatic security updates not enabled",
                "Recommended: unattended-upgrades (sudo apt install unattended-upgrades).")

    rb = rem.run("test -e /var/run/reboot-required && cat /var/run/reboot-required.pkgs 2>/dev/null; "
                 "test -e /var/run/reboot-required").rc == 0
    if rb:
        res.add("medium", "Reboot required to apply updates already installed (e.g. kernel)")
    return res
