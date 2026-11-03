"""Real cases from the Docker lab (Ubuntu 22.04 in a container, report of 2026-10-12).

Every test reproduces a defect seen in that report: it failed before the fix.
"""
import re
import unittest

from zerostressriskassess.redact import mask
from zerostressriskassess.scanners import clamav_scan, permissions, rootkit
from tests.fakes import FakeRemote, fixture, make_ctx

PASSWD = ("root:x:0:0:root:/root:/bin/bash\n"
          "guest:x:1000:1000::/home/guest:/bin/bash\n"
          "dev:x:1001:1001::/home/dev:/bin/bash\n"
          "dev2:x:1001:1001::/home/dev2:/bin/bash\n")


class ContainerPermissionsTest(unittest.TestCase):
    def setUp(self):
        self.rem = FakeRemote(default_rc=1, rules=[
            ("cat /etc/passwd", PASSWD, 0),
            # numeric stat of the homes: /home/dev2 belongs to UID 1001, which is ALSO dev2's UID
            (re.compile(r"%u.* /home/dev2 "), "777|1001|1001|/home/dev2\n", 0),
            (re.compile(r"%u.* /home/dev "), "755|1001|1001|/home/dev\n644|1001|1001|/home/dev/.ssh/id_ed25519\n", 0),
            ("-type d -perm -0002", "/opt/app\n/srv/ftp/pub\n/srv/ftp/upload\n", 0),
            ("find -H /etc /usr", "/opt/app/db.env\n", 0),
            ("-perm -4000", "4755|root|/usr/bin/su\n4755|root|/usr/bin/passwd\n", 0),
        ])
        self.res = permissions.run(make_ctx(self.rem))
        self.titles = [f.title for f in self.res.findings]

    def test_root_always_searched(self):
        # In a container "/" is overlay: without "echo /" the search did not start (0 SUID, 0 777 directories).
        cmds = [c for c in self.rem.calls if "-perm -0002" in c or "-perm -4000" in c]
        self.assertTrue(cmds)
        self.assertTrue(all("echo /;" in c for c in cmds if "findmnt" in c))
        self.assertEqual(self.res.data["suid_sgid_total"], 2)

    def test_777_directories_found(self):
        dirs = [f.detail for f in self.res.findings if "without sticky bit" in f.title]
        self.assertEqual(dirs, ["/opt/app", "/srv/ftp/pub", "/srv/ftp/upload"])

    def test_shared_uid_is_not_a_wrong_owner(self):
        self.assertFalse([t for t in self.titles if "belongs to" in t])
        self.assertIn("Home directory of 'dev2' writable by everyone", self.titles)

    def test_db_env_recognised_as_credentials(self):
        f = [f for f in self.res.findings if f.detail == "/opt/app/db.env"]
        self.assertEqual([x.title for x in f], ["Credentials file writable by everyone"])

    def test_owner_really_different(self):
        rem = FakeRemote(default_rc=1, rules=[
            ("cat /etc/passwd", PASSWD, 0),
            (re.compile(r"%u.* /home/dev "), "755|1000|1000|/home/dev\n", 0),
        ])
        res = permissions.run(make_ctx(rem))
        self.assertTrue([f for f in res.findings if "belongs to UID 1000" in f.title])


class ChkrootkitNotRunTest(unittest.TestCase):
    def test_strings_missing(self):
        # Minimal container without binutils: chkrootkit stops at once. The check is "error" (not performed),
        # and the finding is info: a check that did not run is not a weakness of the target.
        rem = FakeRemote(rules=[("chkrootkit -q", "chkrootkit: can't find `strings'.", 0)])
        res = rootkit.run_chkrootkit(make_ctx(rem, tools_ok={"chkrootkit"}))
        self.assertEqual(res.status, "error")
        self.assertEqual([(f.severity, f.title) for f in res.findings],
                         [("info", "chkrootkit NOT run: programs missing on the target (strings)")])

    def test_parse(self):
        d = rootkit.parse_chkrootkit("chkrootkit: can't find `strings'.\n")
        self.assertEqual(d["missing"], ["strings"])
        self.assertEqual(d["other"], [])


class ChkrootkitContainerTest(unittest.TestCase):
    """REAL output of chkrootkit 0.58b in the lab containers (overlayfs): chkdirs prints "Possible LKM Trojan
    installed" followed by its own notice that it cannot work on BTRFS-like file systems."""

    def test_chkdirs_on_overlay_is_info(self):
        rem = FakeRemote(default_rc=1, rules=[("chkrootkit -q", fixture("chkrootkit_container_overlay.txt"), 0)])
        res = rootkit.run_chkrootkit(make_ctx(rem, tools_ok={"chkrootkit"}))
        self.assertEqual({f.severity for f in res.findings}, {"info"})
        self.assertTrue([f for f in res.findings if "chkdirs" in f.title and "not reliable" in f.title])

    def test_chkdirs_without_the_notice_stays_an_alert(self):
        out = "WARNING: chkdirs: Possible LKM Trojan installed:\nYou have 1 process hidden for readdir command\n"
        rem = FakeRemote(default_rc=1, rules=[("chkrootkit -q", out, 0)])
        res = rootkit.run_chkrootkit(make_ctx(rem, tools_ok={"chkrootkit"}))
        self.assertEqual([(f.severity, f.title) for f in res.findings],
                         [("high", "chkrootkit: chkdirs: Possible LKM Trojan installed")])


class ClamavCoverageTest(unittest.TestCase):
    def test_quick_mode_says_home_not_scanned(self):
        rem = FakeRemote(rules=[("clamscan", "Scanned files: 209\nInfected files: 0\n", 0)])
        ctx = make_ctx(rem, tools_ok={"clamav"})
        ctx.opts.clamav_quick = True
        res = clamav_scan.run(ctx)
        self.assertIn("ClamAV in quick mode: /home NOT scanned", [f.title for f in res.findings])


class MaskingTest(unittest.TestCase):
    def test_file_list_not_masked(self):  # F007 of the report: "/etc/passwd, [MASKED], ..."
        for t in ("/etc/passwd, /etc/shadow, /etc/group, /etc/gshadow",
                  "/etc/passwd: permissions too wide (666, expected at most 644)",
                  "passwd: files systemd"):
            self.assertEqual(mask(t), (t, {}))

    def test_password_on_command_line(self):  # the lab's .bash_history
        out, c = mask("mysql -u root -pFakePassword123 -h db.internal.lab")
        self.assertEqual(out, "mysql -u root -p[MASKED] -h db.internal.lab")
        self.assertEqual(mask("mysql -u root -p -h db -P 3306")[1], {})  # -p without a value, -P = port
        self.assertIn("[MASKED]", mask("sshpass -p hunter22 ssh host")[0])

    def test_forms_still_masked(self):
        for t in ("DB_PASSWORD=fake-password-123", "MYSQL_PASSWORD=abc123x",
                  "define('DB_PASSWORD', 'abc123x');", '"password": "s3cr3t!!"', "passwd=abcd1234"):
            self.assertIn("[MASKED]", mask(t)[0], t)


if __name__ == "__main__":
    unittest.main()
