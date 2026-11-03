"""Permissions (weak VM), the shadowed-commands script (really run with bash) and the report."""
import os
import shlex
import shutil
import stat
import subprocess
import tempfile
import unittest

from zerostressriskassess.scanners import integrity, permissions
from zerostressriskassess.ssh_client import TRUSTED_PATH, Remote
from tests.fakes import FakeRemote, make_ctx


class WeakVmPermissionsTest(unittest.TestCase):
    """The stat/find output the weak VM produces, one rule per command."""

    def setUp(self):
        rem = FakeRemote(default_rc=1, rules=[
            ("cat /etc/passwd", "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000::/home/admin:/bin/bash\n", 0),
            ("/etc/passwd /etc/group", "644|root|root|/etc/passwd\n644|root|shadow|/etc/shadow\n777|root|root|/etc/cron.d\n"
                              "755|root|root|/etc\n600|root|root|/etc/ssh/ssh_host_ed25519_key\n", 0),
            ("/tmp /var/tmp /dev/shm", "1777|root|root|/tmp\n1777|root|root|/var/tmp\n1777|root|root|/dev/shm\n", 0),
            ("-type d -perm -0002", "/etc/cron.d\n/srv/customer_backup\n", 0),
            ("find -H /srv", "/srv/customer_backup/customers.csv\n", 0),
            ("-perm -4000", "4755|root|/usr/local/bin/bash_suid\n4755|root|/usr/bin/passwd\n", 0),
        ])
        self.res = permissions.run(make_ctx(rem))

    def by(self, text):
        return [f for f in self.res.findings if text in f.title or text in f.detail]

    def test_readable_shadow_critical(self):
        self.assertEqual([f.severity for f in self.by("/etc/shadow")], ["critical"])

    def test_cron_d_critical_and_not_duplicated(self):  # 0.2.3: it also appeared as "without sticky bit"
        self.assertEqual([f.severity for f in self.by("/etc/cron.d")], ["critical"])

    def test_suid_shell_critical(self):
        self.assertEqual([f.severity for f in self.by("bash_suid")], ["critical"])

    def test_known_suid_ignored(self):
        self.assertEqual(self.by("/usr/bin/passwd"), [])

    def test_directory_and_data_file(self):
        self.assertEqual([f.severity for f in self.by("/srv/customer_backup")], ["high", "medium"])


@unittest.skipUnless(shutil.which("bash"), "requires bash")
class ShadowedCommandsTest(unittest.TestCase):
    """REALLY runs the integrity.py script with a PATH containing a fake `ls`."""

    def test_fake_command_detected_and_not_used(self):
        with tempfile.TemporaryDirectory() as d:
            fake = os.path.join(d, "ls")
            with open(fake, "w") as f:
                f.write("#!/bin/sh\nexec /bin/ls \"$@\"\n")
            os.chmod(fake, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
            script = integrity.SCRIPT.replace("@CMDS@", "ls cat").replace("@TRUSTED@", TRUSTED_PATH)
            out = subprocess.run(["bash", "-c", script], env={"PATH": f"{d}:{TRUSTED_PATH}"},
                                 capture_output=True, text=True).stdout
        shadow = [l for l in out.splitlines() if l.startswith("SHADOW|ls|")]
        self.assertEqual(len(shadow), 1)
        self.assertIn(fake, shadow[0])
        cmd_ls = [l for l in out.splitlines() if l.startswith("CMD|ls|")][0]
        self.assertNotIn(d, cmd_ls)  # the package checks concern the SYSTEM command
        self.assertFalse([l for l in out.splitlines() if l.startswith("SHADOW|cat|")])


class WrapTest(unittest.TestCase):
    def test_trusted_path_and_neutral_locale(self):
        w = Remote._wrap("ps -e", need_sudo=True, has_sudo_pw=True)
        self.assertTrue(w.startswith("sudo -S -p '' bash -c "))
        inner = shlex.split(w)[-1]
        self.assertIn("LC_ALL=C", inner)
        self.assertIn("PATH=" + TRUSTED_PATH, inner)

    def test_normal_path_only_on_request(self):
        inner = shlex.split(Remote._wrap("x", False, False, trusted_path=False))[-1]
        self.assertNotIn("PATH=", inner)


class ToolTextsNotMaskedTest(unittest.TestCase):
    """Secret masking also ran on the texts written by the tool: an Italian sentence like "senza password:
    verificare che..." became "senza password: [MASKED] che..." (seen in the Rocky lab report, 0.9.0).
    No string in the code may be changed by masking."""

    def test_code_strings(self):
        import ast
        from pathlib import Path
        from zerostressriskassess import redact
        root = Path(redact.__file__).parent
        bad = []
        for p in root.rglob("*.py"):
            if p.name == "redact.py":
                continue
            for n in ast.walk(ast.parse(p.read_text(encoding="utf-8"))):
                if isinstance(n, ast.Constant) and isinstance(n.value, str) and redact.mask(n.value)[0] != n.value:
                    bad.append(f"{p.name}:{n.lineno}")
        self.assertEqual(bad, [])


class DetailTruncationTest(unittest.TestCase):
    def test_cut_at_word_end_and_declared(self):
        from zerostressriskassess.report import _code
        detail = ("Anyone can read the published files without a password. " * 6) + "the ftp check verifies it from the inside."
        out = _code(detail, 300)
        self.assertTrue(out.endswith(" [...]"))
        self.assertLessEqual(len(out), 306)
        self.assertTrue(detail.startswith(out[:-6]))          # no word cut in half
        self.assertEqual(_code("short", 300), "short")


if __name__ == "__main__":
    unittest.main()
