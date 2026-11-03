"""sudoers: unrestricted arguments and authorised programs modifiable by non-root users."""
import unittest

from zerostressriskassess.scanners import sudoers
from tests.fakes import FakeRemote, make_ctx


def run_with(rules_text, stat_out=""):
    rem = FakeRemote(rules=[("for f in /etc/sudoers", "### FILE /etc/sudoers.d/lynis\n" + rules_text, 0),
                            ("stat -L", stat_out, 0)])
    return sudoers.run(make_ctx(rem)), rem


class SudoersArgumentsTest(unittest.TestCase):
    def test_laptop_rule(self):
        # Real rule from the laptop: lynis without arguments = lynis with ANY argument, without a password.
        res, _ = run_with("user ALL=(root) NOPASSWD: /usr/sbin/lynis\n",
                          "755|0|/usr/sbin/lynis\n755|0|/usr/sbin\n")
        free = [f for f in res.findings if "without argument restrictions" in f.title]
        self.assertEqual([(f.severity, f.title) for f in free],
                         [("medium", "sudo rule without argument restrictions: /usr/sbin/lynis")])
        self.assertFalse([f for f in res.findings if f.severity == "critical"])

    def test_fixed_arguments_not_reported(self):
        res, _ = run_with('ops ALL=(root) NOPASSWD: /usr/bin/systemctl restart nginx, /usr/sbin/reboot ""\n')
        self.assertFalse([f for f in res.findings if "argument" in f.title])

    def test_script_modifiable_by_user(self):
        res, rem = run_with("ops ALL=(root) NOPASSWD: /opt/tools/backup.sh\n",
                            "755|1001|/opt/tools/backup.sh\n777|0|/opt/tools\n")
        crit = sorted(f.title for f in res.findings if f.severity == "critical")
        self.assertEqual(crit, ["sudo: program directory modifiable by non-root users: /opt/tools",
                                "sudo: program modifiable by non-root users: /opt/tools/backup.sh"])
        self.assertTrue([c for c in rem.calls if c.startswith("stat -L") and "/opt/tools/backup.sh" in c])

    def test_command_alias(self):
        res, rem = run_with("Cmnd_Alias BK = /opt/bk.sh\nops ALL=(root) BK\n", "755|0|/opt/bk.sh\n755|0|/opt\n")
        self.assertTrue([c for c in rem.calls if c.startswith("stat -L") and "/opt/bk.sh" in c])


if __name__ == "__main__":
    unittest.main()
