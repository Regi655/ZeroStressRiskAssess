"""MySQL and MariaDB: accounts, configuration, network exposure.

A database holds the data that matters (customers, credentials, payments). Typical weaknesses are
configuration errors rather than software bugs:
  - accounts WITHOUT a password, ANONYMOUS accounts (empty user), root usable from other hosts;
  - application accounts with administrative privileges, in particular FILE, which allows reading
    and writing operating-system files (SELECT ... INTO OUTFILE, LOAD_FILE());
  - database reachable from the network without TLS: passwords and data travel in clear text.

Method:
  1) INSIDE: is it running? (`ps`, which also works in containers where `ss -p` does not show other
     users' processes). The server is then queried as root through the local socket (on recent
     Debian/Ubuntu/RHEL root authenticates this way without a password, as intended by the
     installation). Accounts and variables are read from the system tables.
  2) OUTSIDE, from the controller (mysqlprobe.py): only the server greeting, which contains the
     version, is read. NO login is attempted: empty passwords are already visible in the tables,
     without trying credentials against the client's server.

Verified with MariaDB 10.11 (Ubuntu 24.04) and MySQL 8.0 (see tests/test_mysql.py).
"""
from __future__ import annotations

import re
import shlex

from .. import mysqlprobe
from ..models import ScanResult

DAEMONS = ("mysqld", "mariadbd")
# System accounts created by the installation: local, managed by the package.
SYSTEM_ACCOUNTS = {"root", "mysql", "mariadb.sys", "mysql.sys", "mysql.session", "mysql.infoschema",
                   "debian-sys-maint"}
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
SOCKET_PLUGINS = {"unix_socket", "auth_socket"}   # authentication through the operating system user
VARS = ("version", "version_comment", "bind_address", "skip_networking", "local_infile", "secure_file_priv",
        "require_secure_transport", "have_ssl", "port", "datadir")

Q_VARS = "SHOW GLOBAL VARIABLES WHERE Variable_name IN (%s)" % ",".join(f"'{v}'" for v in VARS)
# TLS: have_ssl exists in MariaDB and MySQL <= 8.3 but was REMOVED in MySQL 8.4 (on 8.4.11 it yields
# "have_ssl=?" and a false "no TLS"). Since MySQL 8.0.16 the actual state of the main channel is in
# performance_schema.tls_channel_status (verified on 8.0.46: Enabled=Yes/No).
Q_TLS = ("SELECT VALUE FROM performance_schema.tls_channel_status "
         "WHERE CHANNEL='mysql_main' AND PROPERTY='Enabled'")
Q_PRIVS = "SELECT user, host, Super_priv, File_priv FROM mysql.user"
Q_DBS = "SHOW DATABASES LIKE 'test'"
# Authentication: in MariaDB >= 10.4 the source of truth is mysql.global_priv (JSON); in MySQL mysql.user.
# "account_locked" matters: mariadb.sys has an empty password but is LOCKED (verified on 10.11).
Q_AUTH_MARIADB = ("SELECT User, Host, IFNULL(JSON_VALUE(Priv,'$.plugin'),''), "
                  "IF(IFNULL(JSON_VALUE(Priv,'$.authentication_string'),'')='',1,0), "
                  "IF(IFNULL(JSON_VALUE(Priv,'$.account_locked'),'') IN ('1','true'),1,0) FROM mysql.global_priv")
Q_AUTH_MYSQL = ("SELECT user, host, plugin, IF(authentication_string='',1,0), IF(account_locked='Y',1,0) "
                "FROM mysql.user")

FILES_SCRIPT = r"""
for f in /root/.my.cnf /home/*/.my.cnf /etc/mysql/debian.cnf; do
  [ -f "$f" ] || continue
  pw=nopw; grep -qiE '^[[:space:]]*password[[:space:]]*=[[:space:]]*[^[:space:]]' "$f" && pw=pw
  echo "F|$(stat -c '%a|%U' "$f")|$pw|$f"
done
"""


# ---------------------------------------------------------------------------- pure functions
def parse_tsv(out: str, cols: int) -> list:
    rows = []
    for line in out.splitlines():
        p = line.split("\t")
        if len(p) == cols:
            rows.append(p)
    return rows


def accounts(auth_rows, priv_rows) -> list:
    """Merge authentication and privileges per (user, host)."""
    privs = {(u, h): (s == "Y", f == "Y") for u, h, s, f in priv_rows}
    out = []
    for u, h, plugin, empty, locked in auth_rows:
        sup, fil = privs.get((u, h), (False, False))
        out.append({"user": u, "host": h, "plugin": plugin, "empty": empty == "1", "locked": locked == "1",
                    "super": sup, "file": fil})
    return out


def _who(a) -> str:
    return f"'{a['user']}'@'{a['host']}'"


def check_accounts(res, accs: list, exposed: bool, secure_file_priv: str, db: str = "MySQL"):
    for a in accs:
        if a["locked"]:
            continue
        remote = a["host"] not in LOCAL_HOSTS
        no_pw = a["empty"] and a["plugin"] not in SOCKET_PLUGINS
        admin = a["user"] in SYSTEM_ACCOUNTS   # root and similar: all privileges by definition
        if a["user"] == "":
            sev = "critical" if (remote and exposed and no_pw) else "high"
            res.add(sev, f"{db}: ANONYMOUS account {_who(a)}",
                    "Anyone can connect with any user name" + (" and without a password" if no_pw else "")
                    + ". It must be removed (DROP USER).")
            continue
        if no_pw:
            res.add("critical" if remote else "high", f"{db}: account {_who(a)} WITHOUT password",
                    "From any computer" if a["host"] == "%" else f"Access from {a['host']}")
        if a["user"] == "root" and remote:
            res.add("high", f"{db}: root usable from other computers ({_who(a)})",
                    "The database administrator should only log in locally.")
        elif a["host"] == "%" and not admin and not no_pw:   # no password: already reported above
            res.add("medium", f"{db}: account {_who(a)} usable from ANY host",
                    "Restrict the host to the application servers' addresses.")
        if a["file"] and not admin:
            res.add("high", f"{db}: account {_who(a)} with the FILE privilege",
                    "It reads and writes server files (LOAD_FILE, SELECT ... INTO OUTFILE): combined with an SQL injection "
                    "in the application it becomes system file disclosure."
                    + (" secure_file_priv is empty: no directory is excluded." if secure_file_priv == "" else ""))
        elif a["super"] and not admin:
            res.add("medium", f"{db}: account {_who(a)} with the SUPER privilege (administration)",
                    "An application account should not be able to change the server configuration.")


def tls_state(have_ssl, channel, greeting: dict):
    """(True/False/None, source). Pure function. Order: have_ssl, TLS channel table, CLIENT_SSL bit of the
    greeting read from the controller; None = unknown (no "without TLS" finding).
    """
    if have_ssl in ("YES", "DISABLED", "NO"):
        return have_ssl == "YES", f"have_ssl={have_ssl}"
    ch = (channel or "").strip()
    if ch in ("Yes", "No"):
        return ch == "Yes", f"tls_channel_status Enabled={ch}"
    if "ssl" in (greeting or {}):
        return greeting["ssl"], "server greeting (CLIENT_SSL bit)"
    return None, ""


def check_vars(res, v: dict, exposed: bool, db: str = "MySQL", tls=None):
    if v.get("local_infile") == "ON":
        res.add("low", f"{db}: local_infile enabled (LOAD DATA LOCAL)",
                "Default on MariaDB; the CIS benchmark recommends local_infile=0.")
    if v.get("secure_file_priv", None) == "":
        res.add("low", f"{db}: secure_file_priv empty (no directory excluded for file import/export)",
                "Relevant only for accounts with the FILE privilege. A dedicated directory or NULL is recommended.")
    if exposed:
        ok, src = tls if tls is not None else tls_state(v.get("have_ssl"), None, None)
        if ok is None:
            res.add("info", f"{db}: TLS support cannot be verified",
                    "Neither have_ssl (removed in MySQL 8.4) nor performance_schema.tls_channel_status is available.")
        elif not ok:
            res.add("medium", f"{db} listening on the network without TLS",
                    f"{src}: passwords and data travel in clear text over the network.")
        elif v.get("require_secure_transport") != "ON":
            res.add("low", f"{db}: TLS available but not mandatory (require_secure_transport=OFF)")


def clean_version(ver: str) -> str:
    return re.sub(r"^5\.5\.5-", "", ver or "")   # compatibility prefix MariaDB adds to the greeting


# ---------------------------------------------------------------------------- check
def _sql(rem, query: str):
    """Run a query as root through the local socket; if that fails, try Debian's maintenance
    credentials. Returns the output or None.
    """
    q = shlex.quote(query)
    for extra in ("", "--defaults-file=/etc/mysql/debian.cnf "):
        r = rem.run(f"mysql {extra}--protocol=socket -N -B -e {q}", sudo=True, timeout=60)
        if r.rc == 0:
            return r.out
    return None


def run(ctx) -> ScanResult:
    res, rem = ScanResult("mysql"), ctx.rem
    procs = [l.split(None, 2) for l in rem.run("ps -eo pid=,user=,comm=", sudo=True).out.splitlines()]
    procs = [p for p in procs if len(p) == 3 and p[2].strip() in DAEMONS and p[0].isdigit()]
    if not procs:
        return res.skip("No MySQL/MariaDB server running")
    pid = procs[0][0]
    cmd = rem.run(f"tr '\\0' ' ' < /proc/{int(pid)}/cmdline", sudo=True).out
    if "skip-grant-tables" in cmd or "skip_grant_tables" in cmd:
        res.add("critical", "MySQL started with --skip-grant-tables: NO password checks",
                "Anyone who can connect logs in as administrator. The option is meant only for recovering "
                "the root password, never for production.")

    raw_vars = _sql(rem, Q_VARS)
    if raw_vars is None:
        res.add("info", "MySQL/MariaDB: SQL access as root failed: accounts and variables not checked",
                "Neither the local socket nor /etc/mysql/debian.cnf allowed access.")
        v = {}
    else:
        v = {k: val for k, val in parse_tsv(raw_vars, 2)}
    flavor = "MariaDB" if "mariadb" in (v.get("version", "") + v.get("version_comment", "")).lower() else "MySQL"
    bind = v.get("bind_address", "")
    exposed = bool(v) and v.get("skip_networking") != "ON" and bind not in LOCAL_HOSTS and bind != ""
    if not v:   # without SQL: inferred from the listening sockets
        ss = rem.run("ss -Hltn", sudo=True).out
        exposed = any(re.search(r"\s(?!127\.)(?!\[::1\])\S+:3306\s", " " + l + " ") for l in ss.splitlines())
    res.data.update({"flavor": flavor, "version": v.get("version"), "bind_address": bind, "exposed": exposed})
    res.add("info", f"{flavor} {v.get('version', '?')} running, " +
            ("listening on the network (bind-address " + (bind or "?") + ")" if exposed else "local only"))

    g, port = None, int(v.get("port", 3306)) if str(v.get("port", "3306")).isdigit() else 3306
    local = bool(getattr(ctx.opts, "local", False))
    if (exposed or "3306" in str(ctx.cache.get("nmap_open", ""))) and not local:
        # With --local the "controller" IS the machine: a probe from here goes through no firewall and proves nothing.
        g = mysqlprobe.probe(ctx.rem.host, port)
        res.data["probe"] = g
    if local and exposed:
        res.add("medium", f"{flavor} listening on all interfaces (bind-address {bind or '?'}): exposure not verified "
                "(local mode)", "Whether it is reachable from the network depends on the firewall: verify it from another "
                "machine (zsra --recon-only), or set bind-address = 127.0.0.1 if only local programs use it.")

    if v:
        auth = parse_tsv(_sql(rem, Q_AUTH_MARIADB if flavor == "MariaDB" else Q_AUTH_MYSQL) or "", 5)
        privs = parse_tsv(_sql(rem, Q_PRIVS) or "", 4)
        accs = accounts(auth, privs)
        res.data["accounts"] = [f"{a['user']}@{a['host']}" for a in accs]
        check_accounts(res, accs, exposed, v.get("secure_file_priv", "?"), flavor)
        tls = tls_state(v.get("have_ssl"), None if "have_ssl" in v else _sql(rem, Q_TLS), g)
        res.data["tls"] = tls[1] or "?"
        check_vars(res, v, exposed, flavor, tls)
        if (_sql(rem, Q_DBS) or "").strip():
            res.add("low", f"{flavor}: the 'test' database exists", "Test database often accessible to everyone: it should be removed.")

    for line in rem.run(FILES_SCRIPT, sudo=True).out.splitlines():
        p = line.split("|", 4)
        if len(p) == 5 and p[0] == "F" and p[1].isdigit() and p[3] == "pw" and int(p[1], 8) & 0o077:
            res.add("high", f"{flavor} password file readable by others: {p[4]}", f"mode={p[1]} owner={p[2]}")

    if g is not None:
        if g.get("kind") == "greeting":
            res.add("medium", f"{flavor} reachable from the controller (port {port})",
                    f"The server answers with version {clean_version(g['version'])}. A database should be "
                    "reachable only from the application servers: firewall or bind-address on an internal address."
                    + (f" Cause in the configuration: bind-address {bind}." if bind else ""))
        elif g.get("kind") == "error":
            res.add("low", f"{flavor}: port {port} reachable, but the controller address is not authorised",
                    g.get("message", "")[:200])
        elif exposed:
            res.add("info", f"{flavor} listening on the network but NOT reachable from the controller",
                    "Probably a firewall in between: exposure cannot be confirmed from here.")
    return res
