"""MySQL / MariaDB with REAL output.

The mariadb_* and mysql8_* fixtures are the real answers to the check's queries, recorded on MariaDB
10.11.14 and MySQL 8.0.46 (Ubuntu 24.04), each in two states:
  - default: freshly installed;
  - lab: with a deliberately wrong configuration (ISP lab used during development, not part of this repository).
The greeting .bin files are the first bytes each server sends to a connecting client.
"""
import socketserver
import threading
import unittest
from pathlib import Path
from unittest import mock

from zerostressriskassess import mysqlprobe
from zerostressriskassess.scanners import mysql
from tests.fakes import FIXTURES, FakeRemote, fixture, make_ctx


def scan(kind: str, state: str, extra=(), probe=None, ps="1 mysql mariadbd\n", cmdline="mariadbd --user=mysql"):
    auth_key = "global_priv" if kind == "mariadb" else "IF(account_locked"
    rem = FakeRemote(host="172.28.7.50", rules=list(extra) + [
        ("ps -eo pid=,user=,comm=", ps, 0),
        ("cmdline", cmdline, 0),
        ("SHOW GLOBAL VARIABLES", fixture(f"{kind}_{state}_vars.tsv"), 0),
        (auth_key, fixture(f"{kind}_{state}_auth.tsv"), 0),
        ("Super_priv, File_priv", fixture(f"{kind}_{state}_privs.tsv"), 0),
        ("SHOW DATABASES", "test\n" if state == "lab" else "", 0),
    ])
    with mock.patch.object(mysqlprobe, "probe", return_value=probe or {"reachable": False}) as p:
        res = mysql.run(make_ctx(rem))
    return res, {(f.severity, f.title) for f in res.findings}, p


GREET = {"reachable": True, "kind": "greeting", "version": "5.5.5-10.11.14-MariaDB"}


class MariaDBTest(unittest.TestCase):
    def test_lab(self):
        res, got, _ = scan("mariadb", "lab", probe=GREET)
        self.assertEqual(sorted(t for s, t in got if s != "info"), sorted([
            "MariaDB: ANONYMOUS account ''@'%'",
            "MariaDB: account 'radius'@'%' WITHOUT password",
            "MariaDB: account 'app'@'%' usable from ANY host",
            "MariaDB: account 'app'@'%' with the FILE privilege",
            "MariaDB: root usable from other computers ('root'@'%')",
            "MariaDB: local_infile enabled (LOAD DATA LOCAL)",
            "MariaDB: secure_file_priv empty (no directory excluded for file import/export)",
            "MariaDB listening on the network without TLS",
            "MariaDB: the 'test' database exists",
            "MariaDB reachable from the controller (port 3306)"]))
        self.assertIn(("critical", "MariaDB: ANONYMOUS account ''@'%'"), got)  # anonymous + no password + exposed
        greet = [f for f in res.findings if "reachable from the controller" in f.title][0]
        self.assertIn("version 10.11.14-MariaDB.", greet.detail)          # without the 5.5.5- prefix
        self.assertIn("bind-address 0.0.0.0", greet.detail)

    def test_default_no_false_positive(self):
        # mariadb.sys has an EMPTY password but is locked; root and mysql log in via unix_socket.
        _, got, p = scan("mariadb", "default")
        self.assertEqual({s for s, _ in got} - {"info"}, {"low"})   # only the two CIS recommendations
        self.assertEqual(len([1 for s, _ in got if s == "low"]), 2)
        p.assert_not_called()   # local only: no network probe


class MySQL8Test(unittest.TestCase):
    def test_lab(self):
        _, got, _ = scan("mysql8", "lab", ps="1 mysql mysqld\n", cmdline="mysqld --user=mysql",
                         probe={"reachable": True, "kind": "greeting", "version": "8.0.46-0ubuntu0.24.04.4"})
        self.assertIn(("critical", "MySQL: account 'radius'@'%' WITHOUT password"), got)
        self.assertIn(("high", "MySQL: account 'app'@'%' with the FILE privilege"), got)
        # MySQL 8 generates its own TLS certificates: "not mandatory", not "without TLS".
        self.assertIn(("low", "MySQL: TLS available but not mandatory (require_secure_transport=OFF)"), got)
        self.assertNotIn(("medium", "MySQL listening on the network without TLS"), got)

    def test_default_clean(self):
        _, got, _ = scan("mysql8", "default", ps="1 mysql mysqld\n", cmdline="mysqld --user=mysql")
        self.assertEqual({s for s, _ in got}, {"info"})   # root with auth_socket: it is not "without password"


class SpecialCasesTest(unittest.TestCase):
    def test_skip_grant_tables(self):
        _, got, _ = scan("mariadb", "default", cmdline="mariadbd --user=mysql --skip-grant-tables")
        self.assertIn(("critical", "MySQL started with --skip-grant-tables: NO password checks"), got)

    def test_sql_access_denied(self):
        rem = FakeRemote(rules=[("ps -eo pid=,user=,comm=", "1 mysql mysqld\n", 0), ("mysql ", "ERROR 1698", 1)])
        with mock.patch.object(mysqlprobe, "probe", return_value={"reachable": False}):
            res = mysql.run(make_ctx(rem))
        self.assertTrue([f for f in res.findings if "SQL access as root failed" in f.title])

    def test_readable_my_cnf(self):
        _, got, _ = scan("mariadb", "default", extra=[("/root/.my.cnf", "F|644|admin|pw|/home/admin/.my.cnf\n", 0)])
        self.assertIn(("high", "MariaDB password file readable by others: /home/admin/.my.cnf"), got)

    def test_not_running(self):
        self.assertEqual(mysql.run(make_ctx(FakeRemote())).status, "skipped")


class Mysql84Test(unittest.TestCase):
    """MySQL 8.4 no longer has have_ssl: on the laptop (8.4.11) it gave a false "without TLS" with have_ssl=?.
    Variables = the real 8.0 lab ones without the have_ssl line and with version 8.4.11."""

    def vars84(self):
        lines = [l for l in fixture("mysql8_lab_vars.tsv").splitlines() if not l.startswith("have_ssl")]
        return "\n".join(l.replace("8.0.46-0ubuntu0.24.04.4", "8.4.11-0ubuntu0.26.04.1") for l in lines) + "\n"

    def run84(self, channel, probe=None):
        extra = [("SHOW GLOBAL VARIABLES", self.vars84(), 0), ("tls_channel_status", channel, 0 if channel else 1)]
        return scan("mysql8", "lab", extra=extra, probe=probe, ps="1 mysql mysqld\n", cmdline="mysqld")

    def test_tls_on_from_tls_channel_status(self):
        res, got, _ = self.run84("Yes\n")
        self.assertFalse([t for s, t in got if "without TLS" in t])
        self.assertEqual(res.data["tls"], "tls_channel_status Enabled=Yes")

    def test_tls_off_from_tls_channel_status(self):
        _, got, _ = self.run84("No\n")
        self.assertIn(("medium", "MySQL listening on the network without TLS"), got)

    def test_no_sources_but_greeting_with_bit(self):
        g = {"reachable": True, "kind": "greeting", "version": "8.4.11", "ssl": True}
        res, got, _ = self.run84("", probe=g)
        self.assertFalse([t for s, t in got if "without TLS" in t])
        self.assertEqual(res.data["tls"], "server greeting (CLIENT_SSL bit)")

    def test_no_source_info_not_false_positive(self):
        _, got, _ = self.run84("")
        self.assertIn(("info", "MySQL: TLS support cannot be verified"), got)
        self.assertFalse([t for s, t in got if "without TLS" in t])


# ---------------------------------------------------------------------------- server greeting
class _Greeter(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(self.server.payload)


class GreetingTest(unittest.TestCase):
    def test_real_greetings(self):
        for name, ver in (("mysql_greeting_mariadb.bin", "5.5.5-10.11.14-MariaDB-0ubuntu0.24.04.1"),
                          ("mysql_greeting_mysql8.bin", "8.0.46-0ubuntu0.24.04.4")):
            g = mysqlprobe.parse_greeting(Path(FIXTURES, name).read_bytes())
            self.assertEqual((g["kind"], g["version"]), ("greeting", ver))

    def test_greeting_tls_bit(self):
        # Real: MySQL 8.0 with TLS (certificates generated at installation) and with an empty tls_version;
        # Ubuntu's MariaDB without certificates (have_ssl=DISABLED).
        for name, ssl in (("mysql_greeting_mysql8.bin", True), ("mysql_greeting_mysql8_notls.bin", False),
                          ("mysql_greeting_mariadb.bin", False)):
            self.assertIs(mysqlprobe.parse_greeting(Path(FIXTURES, name).read_bytes())["ssl"], ssl, name)

    def test_host_not_allowed_error(self):
        # Synthetic, in the protocol format: 0xff + code 1130 + message.
        msg = b"Host '172.28.7.1' is not allowed to connect to this MariaDB server"
        payload = b"\xff" + (1130).to_bytes(2, "little") + msg
        g = mysqlprobe.parse_greeting(len(payload).to_bytes(3, "little") + b"\x00" + payload)
        self.assertEqual((g["kind"], g["code"]), ("error", 1130))
        self.assertIn("not allowed", g["message"])

    def test_real_network(self):
        srv = socketserver.TCPServer(("127.0.0.1", 0), _Greeter)
        srv.payload = Path(FIXTURES, "mysql_greeting_mysql8.bin").read_bytes()
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            g = mysqlprobe.probe("127.0.0.1", srv.server_address[1])
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertEqual((g["reachable"], g["version"]), (True, "8.0.46-0ubuntu0.24.04.4"))
        with socketserver.TCPServer(("127.0.0.1", 0), _Greeter) as s:
            free = s.server_address[1]
        self.assertEqual(mysqlprobe.probe("127.0.0.1", free, timeout=0.5), {"reachable": False})


if __name__ == "__main__":
    unittest.main()
