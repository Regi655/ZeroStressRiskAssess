"""Account and UID checks.

On Unix systems privileges depend on the numeric UID, not on the name: a user called "backup" with
UID 0 is root in every respect. A second UID 0 account or an account without a password is a classic
backdoor. Password hashes are NEVER included in the report: knowing whether they are empty or weak
is sufficient.
"""
from __future__ import annotations

import re

from ..models import ScanResult

# Shells that do NOT allow an interactive session.
NOLOGIN = {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false",
           "/bin/sync", "/sbin/halt", "/sbin/shutdown", "/sbin/nologin "}
SHADOW_AWK = r"""awk -F: '($2==""){print $1"|empty"} ($2 ~ /^[$]1[$]/){print $1"|md5"} ($2 !~ /^[$!*]/ && $2!=""){print $1"|des"}' /etc/shadow"""
SHADOW_LINE = re.compile(r"[A-Za-z0-9._$-]+\|(empty|md5|des)")


# Accounts that RHEL, Rocky, Alma and Fedora create by default with GID 0, each with its own special
# shell. If the shell differs from the default one, the account has been modified and remains
# a "medium" finding.

RHEL_GID0 = {"sync": {"/bin/sync"}, "shutdown": {"/sbin/shutdown", "/usr/sbin/shutdown"},
             "halt": {"/sbin/halt", "/usr/sbin/halt"}, "operator": {"/sbin/nologin", "/usr/sbin/nologin"}}

def get_users(ctx):
    """Read /etc/passwd once and cache it for the other checks."""
    if "users" in ctx.cache:
        return ctx.cache["users"]
    rem = ctx.rem
    uid_min = 1000  # threshold between system accounts and regular users
    r = rem.run("awk '/^UID_MIN/{print $2}' /etc/login.defs").out.strip()
    if r.isdigit():
        uid_min = int(r)
    users = []
    for line in rem.run("cat /etc/passwd").out.splitlines():
        p = line.split(":")
        if len(p) < 7 or not p[2].isdigit():
            users.append({"bad": True, "raw": line})
            continue
        users.append({"bad": False, "name": p[0], "pw": p[1], "uid": int(p[2]), "gid": p[3],
                      "home": p[5], "shell": p[6] or "/bin/sh"})
    ctx.cache["users"] = (users, uid_min)
    return ctx.cache["users"]


def run(ctx) -> ScanResult:
    res, rem = ScanResult("accounts"), ctx.rem
    users, uid_min = get_users(ctx)
    by_uid, by_name, interactive, rhel_gid0 = {}, {}, [], []

    for u in users:
        if u["bad"]:
            res.add("medium", "Malformed line in /etc/passwd", u["raw"][:100])
            continue
        n, uid = u["name"], u["uid"]
        by_uid.setdefault(uid, []).append(n)
        by_name[n] = by_name.get(n, 0) + 1

        extra_root = uid == 0 and n != "root"
        if extra_root:
            # ONE finding per account: UID 0, GID 0 and a login shell are the same problem seen from three
            # angles, and three lines for the same account would only add noise.
            facts = ["UID 0 shared with root"]
            if u["gid"] == "0":
                facts.append("GID 0 (gruppo root)")
            if u["shell"] not in NOLOGIN:
                facts.append(f"login shell {u['shell']}")
            res.add("critical", f"Account '{n}' with UID 0: equivalent to root", "Possible backdoor. " + "; ".join(facts) + ".")
        elif u["gid"] == "0" and n != "root":
            if n in RHEL_GID0 and u["shell"] in RHEL_GID0[n]:
                rhel_gid0.append(n)   # present like this on every RHEL/Rocky/Fedora installation
            else:
                res.add("medium", f"Account '{n}' with GID 0 (root group)")
        if u["pw"] == "":
            res.add("critical", f"Account '{n}' without password (empty field in /etc/passwd)")
        elif u["pw"] != "x":
            res.add("high", f"Account '{n}': password hash stored in /etc/passwd",
                    "Readable by every user: it belongs in /etc/shadow.")

        can_login = u["shell"] not in NOLOGIN
        if can_login and uid < uid_min and n != "root" and not extra_root:
            res.add("medium", f"System account '{n}' with a login shell", f"uid={uid} shell={u['shell']}")
        if can_login and uid >= uid_min:
            interactive.append(n)

    for uid, names in by_uid.items():
        if len(names) > 1 and uid != 0:  # UID 0 is already covered by the per-account finding above
            res.add("medium", f"UID {uid} shared by several accounts", ", ".join(names))
    for n, c in by_name.items():
        if c > 1:
            res.add("medium", f"User name '{n}' duplicated in /etc/passwd")
    res.data["interactive_users"] = interactive
    if rhel_gid0:
        res.add("info", f"Standard RHEL system accounts with GID 0: {', '.join(rhel_gid0)}",
                "Created this way by the installer (sync, shutdown, halt, operator) with their default shells.")
    res.add("info", f"Users with interactive login: {', '.join(interactive) or 'none'}")

    # /etc/shadow: only "name|problem type" is printed, never the hash.
    sh = rem.run(SHADOW_AWK, sudo=True)
    if sh.rc != 0:
        res.add("info", "Cannot read /etc/shadow: password check not performed")
    for line in sh.out.splitlines():
        if not SHADOW_LINE.fullmatch(line):
            continue
        name, kind = line.split("|")
        if kind == "empty":
            res.add("critical", f"Account '{name}' with an empty password in /etc/shadow", "Login without a password.")
        elif kind == "md5":
            res.add("medium", f"Account '{name}': MD5 hash ($1$), obsolete algorithm")
        else:
            res.add("high", f"Account '{name}': traditional DES hash, easily cracked")

    recent = rem.run("find /etc/passwd /etc/shadow /etc/group /etc/gshadow -mtime -7 2>/dev/null", sudo=True).out
    if recent.strip():
        res.add("low", "Account files modified in the last 7 days", recent.replace("\n", ", "))
    return res
