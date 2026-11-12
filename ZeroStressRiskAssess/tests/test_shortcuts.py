"""Shorter commands: saved targets (zsra save / zsra NAME), zsra SUBCOMMAND, passwords asked only when needed."""
import io
import os
import shutil
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from tests.fakes import FakeRemote
from zerostressriskassess import cli, orchestrator, targets


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        p = mock.patch.dict(os.environ, {"ZSRA_TARGETS": str(self.tmp / "cfg" / "targets.json")})
        p.start()
        self.addCleanup(p.stop)


class TargetsTest(Base):
    LINE = ["192.168.1.14", "-u", "danielb", "-i", "~/.ssh/riskassess_laptop", "--clamav-quick"]

    def test_save_then_run_by_name_with_extra_options(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["save", "laptop", *self.LINE]), 0)
        f = targets.path()
        self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o600)
        self.assertEqual(targets.expand(["laptop", "--skip", "clamav"]),
                         (self.LINE + ["--skip", "clamav"], "laptop"))
        seen = {}
        with mock.patch.object(cli, "build_parser", side_effect=lambda: _capture(seen)), \
                redirect_stdout(io.StringIO()) as out, self.assertRaises(SystemExit):
            cli.main(["laptop", "--skip", "clamav"])
        self.assertEqual(seen["argv"], self.LINE + ["--skip", "clamav"])
        self.assertIn("Saved target laptop", out.getvalue())

    def test_host_names_and_ips_are_never_names(self):
        targets.save("srv", ["10.0.0.9", "-u", "a"])
        for argv in (["10.0.0.1", "-u", "x"], ["srv.lan", "-u", "x"], ["--local"]):
            self.assertEqual(targets.expand(argv), (argv, None))

    def test_refused_names_and_options(self):
        for name in ("web", "1abc", "a.b", "with space"):
            with self.assertRaises(targets.TargetError):
                targets.save(name, ["10.0.0.1"])
        for bad in ("--sudo-pass-env", "--yes", "--out-dir=/x"):
            with self.assertRaises(targets.TargetError):
                targets.save("x", ["10.0.0.1", bad])

    def test_invalid_line_is_not_saved(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            cli.main(["save", "bad", "10.0.0.1", "--no-such-option"])
        self.assertEqual(targets.load(), {})

    def test_list_and_forget(self):
        targets.save("a", ["10.0.0.1", "-u", "x"])
        with redirect_stdout(io.StringIO()) as out:
            cli.main(["targets"])
        self.assertIn("zsra 10.0.0.1 -u x", out.getvalue())
        with redirect_stdout(io.StringIO()):
            cli.main(["forget", "a"])
        self.assertEqual(targets.load(), {})


def _capture(seen):
    ap = cli.argparse.ArgumentParser()

    def parse(argv):
        seen["argv"] = list(argv)
        raise SystemExit(0)
    ap.parse_args = parse
    return ap


class SubcommandTest(Base):
    def test_one_command_for_everything(self):
        for name, module in (("portal", "portal"), ("compare", "compare"), ("web", "web"), ("pdf", "pdfreport")):
            with mock.patch(f"zerostressriskassess.{module}.main", return_value=7) as m:
                self.assertEqual(cli.main([name, "--x"]), 7)
            m.assert_called_once_with(["--x"])


class PromptsTest(Base):
    def test_encrypted_key_is_detected(self):
        import paramiko
        key = paramiko.RSAKey.generate(1024)
        plain, enc = self.tmp / "plain", self.tmp / "enc"
        key.write_private_key_file(str(plain))
        key.write_private_key_file(str(enc), password="secret")
        self.assertFalse(cli.key_is_encrypted(plain))
        self.assertTrue(cli.key_is_encrypted(enc))
        self.assertFalse(cli.key_is_encrypted(self.tmp / "missing"))
        # the ssh-keygen default format (OpenSSH), with and without passphrase
        for name, pw in (("o_plain", ""), ("o_enc", "secret")):
            r = os.system(f"ssh-keygen -q -t ed25519 -N '{pw}' -f {self.tmp / name} >/dev/null 2>&1")
            if r:
                self.skipTest("ssh-keygen not available")
        self.assertFalse(cli.key_is_encrypted(self.tmp / "o_plain"))
        self.assertTrue(cli.key_is_encrypted(self.tmp / "o_enc"))

    def test_sudo_password_asked_once_when_sudo_wants_it(self):
        rem = FakeRemote(rules=[("sudo -S", "0", 0), ("id -u", "sudo: a password is required", 1)])
        rem.sudo_password = None
        asked = []
        rem.ask_sudo = lambda: asked.append(1) or "pw"

        def run(cmd, sudo=False, **kw):   # with a password the same check succeeds
            return FakeRemote.run(rem, ("sudo -S " if rem.sudo_password else "") + cmd, sudo=sudo, **kw)
        rem.run = run
        orchestrator._require_root(rem)
        self.assertEqual((asked, rem.sudo_password), ([1], "pw"))

    def test_without_a_terminal_the_error_says_what_to_add(self):
        rem = FakeRemote(rules=[("id -u", "sudo: a password is required", 1)])
        with self.assertRaises(PermissionError) as e:
            orchestrator._require_root(rem)
        self.assertIn("--ask-sudo-pass", str(e.exception))


if __name__ == "__main__":
    unittest.main()
