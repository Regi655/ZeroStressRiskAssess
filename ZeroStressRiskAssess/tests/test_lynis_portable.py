"""Portable Lynis: copied from the controller, run from a root-owned temporary directory, deleted.

The LocalRemote tests REALLY run the shell scripts (sha256sum, mktemp, tar, chown, rm) on this system, with
a fake "lynis" that writes a report.dat: they exercise the copy, the checksum verification and the cleanup.
They need root privileges (chown): elsewhere they are skipped.
lynis_318_laptop_report.dat is the REAL report of Lynis 3.1.8 (official repository) run in portable mode in
the development sandbox.
"""
import os
import tempfile
import unittest
from pathlib import Path

from zerostressriskassess import portable
from zerostressriskassess.models import ScanResult
from zerostressriskassess.scanners import lynis_scan
from tests.fakes import FakeRemote, LocalRemote, fixture, make_ctx

FAKE_LYNIS = """#!/bin/sh
# Fake Lynis: writes the report where asked and prints the owner of its files.
while [ $# -gt 0 ]; do [ "$1" = "--report-file" ] && R="$2"; shift; done
echo "PROGRAM_VERSION=\\"9.9.9\\"" >/dev/null
printf 'lynis_version=9.9.9\\nhardening_index=55\\nwarning[]=TEST-0001|Test|-|-|\\n' > "$R"
echo "owner=$(stat -c %U lynis) dir=$(dirname "$(pwd)")"
"""


def fake_lynis_dir(base):
    d = Path(base) / "lynis-src"
    (d / "include").mkdir(parents=True)
    (d / ".git").mkdir()
    (d / ".git" / "HEAD").write_text("ref")
    (d / "lynis").write_text('PROGRAM_VERSION="9.9.9"\n' + FAKE_LYNIS)
    (d / "lynis").chmod(0o755)
    return d


@unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0, "requires root (chown of the Lynis files)")
class RealRunTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.src = fake_lynis_dir(self.tmp.name)
        self.home = Path(self.tmp.name) / "home"
        self.home.mkdir()
        self.rem = LocalRemote(self.home)

    def tearDown(self):
        self.tmp.cleanup()

    def test_copies_runs_and_deletes(self):
        before = set(Path("/tmp").glob("zerostressriskassess-lynis.*"))
        rc, out, rep = portable.run_lynis(self.rem, str(self.src), 60)
        self.assertEqual(rc, 0, out)
        self.assertIn("hardening_index=55", rep)
        self.assertRegex(out, r"owner=root dir=/tmp/zerostressriskassess-lynis\.\w{6}")
        self.assertEqual(set(Path("/tmp").glob("zerostressriskassess-lynis.*")), before)   # directory deleted
        self.assertFalse((self.home / portable.ARCHIVE).exists())                 # archive deleted

    def test_tampered_archive_is_not_run(self):
        real_upload = self.rem.upload_bytes
        self.rem.upload_bytes = lambda path, data: real_upload(path, data + b"x")
        rc, out, rep = portable.run_lynis(self.rem, str(self.src), 60)
        self.assertNotEqual(rc, 0)
        self.assertIn("CHECKSUM", out)
        self.assertEqual(rep, "")
        self.assertFalse(any("./lynis audit" in c for c in self.rem.calls))
        self.assertFalse((self.home / portable.ARCHIVE).exists())


class DirectoryTest(unittest.TestCase):
    def test_version_and_wrong_directory(self):
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual(portable.check_dir(str(fake_lynis_dir(t))), "9.9.9")
            with self.assertRaises(ValueError):
                portable.check_dir(t)

    def test_archive_without_git(self):
        import io
        import tarfile
        with tempfile.TemporaryDirectory() as t:
            data, sha = portable.pack(str(fake_lynis_dir(t)))
            names = tarfile.open(fileobj=io.BytesIO(data)).getnames()
        self.assertIn("lynis/lynis", names)
        self.assertFalse([n for n in names if ".git" in n])
        self.assertEqual(len(sha), 64)


class RealReportTest(unittest.TestCase):
    def test_lynis_318(self):
        ctx = make_ctx(FakeRemote())
        res = lynis_scan.parse(ScanResult("lynis"), fixture("lynis_318_laptop_report.dat"), ctx)
        self.assertEqual(res.data["lynis_version"], "3.1.8")
        self.assertEqual(res.data["hardening_index"], 63)
        self.assertEqual(res.data["suggestions_total"], 41)

    def test_check_in_portable_mode(self):
        ctx = make_ctx(FakeRemote(default_rc=1))
        ctx.opts.lynis_dir = "/x"
        import unittest.mock as m
        with m.patch.object(portable, "available", return_value=True), m.patch.object(portable, "run_lynis", return_value=(0, "ok", fixture("lynis_318_laptop_report.dat"))):
            res = lynis_scan.run(ctx)
        self.assertEqual(res.data["target_logs"], "none: temporary directory deleted")
        self.assertNotIn("Lynis logs remain on the target", " ".join(f.title for f in res.findings))


if __name__ == "__main__":
    unittest.main()
