"""Mascot banner (from a file) and the interactive `zsra` console."""
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from zerostressriskassess import banner, cli
from zerostressriskassess.console import Console


class Tty(io.StringIO):
    """A stream that reports itself as a UTF-8 terminal (like a real one)."""
    encoding = "utf-8"

    def isatty(self):
        return True


class BannerTest(unittest.TestCase):
    def test_mascot_from_the_package_file(self):
        self.assertTrue(banner.DEFAULT_ART.is_file())
        art = banner.load_art()
        self.assertGreater(len(art.splitlines()), 10)
        self.assertIn("⣿", art)                       # it is the braille image

    def test_mascot_replaceable_with_variable(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write("  /\\_/\\\n ( o.o )\n\x1b[31m > ^ <\n\n\n")   # with a control sequence and empty lines
        try:
            with mock.patch.dict(os.environ, {"ZSRA_MASCOT": f.name}):
                art = banner.load_art()
            self.assertEqual(art, "  /\\_/\\\n ( o.o )\n[31m > ^ <")   # ESC removed, trailing empty lines removed
            self.assertNotIn("\x1b", art)
        finally:
            os.unlink(f.name)

    def test_missing_file_title_only(self):
        with mock.patch.dict(os.environ, {"ZSRA_MASCOT": "/does/not/exist.txt", "NO_COLOR": "1"}):
            out = banner.render(Tty())
        self.assertTrue(out.startswith("  ZeroStressRiskAssess"))

    def test_shown_only_on_a_terminal(self):
        for env, stream, expected in (({}, Tty(), True), ({}, io.StringIO(), False),
                                    ({"ZSRA_NO_BANNER": "1"}, Tty(), False)):
            with mock.patch.dict(os.environ, env):
                banner.show(stream)
            self.assertEqual("ZeroStressRiskAssess" in stream.getvalue(), expected, env)

    def test_no_banner_in_the_direct_command(self):
        with mock.patch.object(banner, "show") as show, mock.patch("sys.stderr"), self.assertRaises(SystemExit):
            cli.main(["10.0.0.1", "--no-banner"])      # -u missing: error, but the banner must NOT be shown first
        show.assert_not_called()


class ConsoleTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = io.StringIO()

    def tearDown(self):
        self.tmp.cleanup()

    def run_cmds(self, *lines):
        c = Console(out_dir=self.tmp.name, stdin=io.StringIO("\n".join(lines) + "\n"), stdout=self.out)
        c.cmdloop()
        return self.out.getvalue()

    def test_zsra_without_arguments_opens_the_console(self):
        with mock.patch("zerostressriskassess.console.run", return_value=0) as run:
            self.assertEqual(cli.main([]), 0)
        run.assert_called_once()

    def test_help_and_unknown_command(self):
        out = self.run_cmds("help", "foo", "exit")
        for cmd in ("scan", "local", "reports", "open", "tools", "options"):
            self.assertIn(cmd, out)
        self.assertIn("Unknown command: foo", out)

    def test_scan_uses_the_same_options_as_the_direct_command(self):
        with mock.patch.object(cli, "main", return_value=0) as main:
            self.run_cmds("scan 10.0.0.5 -u admin --clamav-quick", "local --skip clamav", "exit")
        a1, a2 = main.call_args_list[0][0][0], main.call_args_list[1][0][0]
        self.assertEqual(a1[:4], ["10.0.0.5", "-u", "admin", "--clamav-quick"])
        self.assertIn("--no-banner", a1)
        self.assertEqual(a1[a1.index("--out-dir") + 1], self.tmp.name)
        self.assertEqual(a2[:3], ["--local", "--skip", "clamav"])

    def test_option_error_does_not_close_the_console(self):
        with mock.patch("sys.stderr"):
            out = self.run_cmds("scan 10.0.0.5", "version", "exit")   # -u missing: argparse exits...
        self.assertIn("ZeroStressRiskAssess", out)                          # ...but the console carries on

    def test_tilde_in_the_console_is_expanded(self):
        # Real case: `scan HOST -u USER -i ~/.ssh/KEY` in the console. No shell expands "~" there, so the tool
        # received the literal path and failed with FileNotFoundError, after nmap and ssh-audit had already run.
        with tempfile.TemporaryDirectory() as home:
            key = Path(home, ".ssh", "lab_key")
            key.parent.mkdir()
            key.write_text("fake")
            with mock.patch.dict(os.environ, {"HOME": home}), \
                    mock.patch.object(cli, "assess", side_effect=RuntimeError("stop")) as fake, mock.patch("sys.stderr"):
                self.run_cmds("scan 10.0.0.5 -u admin -i ~/.ssh/lab_key --yes", "exit")
            self.assertEqual(fake.call_args[0][0].key_file, str(key))

    def test_missing_key_stops_before_any_check(self):
        with mock.patch.object(cli, "assess") as fake, mock.patch("sys.stderr") as err:
            self.run_cmds("scan 10.0.0.5 -u admin -i /does/not/exist --yes", "exit")
        fake.assert_not_called()
        self.assertIn("file not found: /does/not/exist", "".join(c.args[0] for c in err.write.call_args_list))

    def test_reports_listed_newest_first(self):
        for n, (target, level) in enumerate((("10.0.0.1", "HIGH"), ("10.0.0.2", "LOW"))):
            d = Path(self.tmp.name) / f"r{n}"
            d.mkdir()
            f = d / "report.json"
            f.write_text(json.dumps({"meta": {"target": target, "timestamp": f"2026-10-14 1{n}:00"},
                                     "summary": {"level": level}, "risks": [{}] * (n + 1)}))
            os.utime(f, (1000 + n, 1000 + n))
        out = self.run_cmds("reports", "open 9", "exit")
        rows = [r for r in out.splitlines() if "10.0.0." in r]
        self.assertIn("10.0.0.2", rows[0])            # newest first
        self.assertIn("LOW", rows[0])
        self.assertIn("Invalid number", out)
