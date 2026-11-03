"""Smoke tests: every check must survive a target that answers in unexpected ways.

The orchestrator catches the checks' exceptions (one broken check does not stop the others), so a
programming error does not stop the tool: it only produces a "check failed" line in the report, which is
easy to miss. It happened with `NameError: STICKY_DIRS` in 0.2.3. Here the checks are called DIRECTLY,
without that safety net: any exception fails the test.
"""
import unittest

from zerostressriskassess.scanners import ALL_NAMES, INTERNAL
from tests.fakes import FakeRemote, make_ctx

# Checks that need an installed tool: tested both with the tool "present" and "missing".
TOOLS = {"lynis", "chkrootkit", "clamav", "rkhunter"}


class SmokeTest(unittest.TestCase):
    def _run_all(self, rem, tools_ok):
        for name, fn in INTERNAL:
            with self.subTest(scanner=name, tools=bool(tools_ok), rc=rem.default_rc):
                ctx = make_ctx(rem, tools_ok=tools_ok)
                res = fn(ctx)
                self.assertIn(res.status, ("ok", "skipped", "error"))
                for f in res.findings:
                    self.assertIn(f.severity, ("critical", "high", "medium", "low", "info"))

    def test_empty_output(self):
        self._run_all(FakeRemote(), set())
        self._run_all(FakeRemote(), TOOLS)

    def test_failed_commands(self):
        self._run_all(FakeRemote(default_rc=1), set())
        self._run_all(FakeRemote(default_rc=1), TOOLS)

    def test_garbage_output(self):
        # Meaningless (or hostile) text instead of the expected output.
        junk = "\x1b[31mERR\x1b[0m |||| ;;; $(rm -rf /) 'quote\" \n" * 3
        self._run_all(FakeRemote(rules=[("", junk)]), TOOLS)

    def test_unique_names(self):
        self.assertEqual(len(ALL_NAMES), len(set(ALL_NAMES)))


if __name__ == "__main__":
    unittest.main()
