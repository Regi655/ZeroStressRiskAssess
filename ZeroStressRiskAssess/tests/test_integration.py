"""Integration: a complete assess() against the fake target, from the connection to the report on disk.

It does not test the individual checks (the other tests do) but how the pieces are WIRED together:
orchestrator, tool management, checks, cleanup, local and remote report.
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from zerostressriskassess.models import Options
from zerostressriskassess.orchestrator import assess
from zerostressriskassess.scanners import ALL_NAMES
from tests.fakes import FakeRemote, fixture

# Output of osinfo.SCRIPT: os-release lines tagged OSR|, package managers found tagged PM|
OS_DETECT = 'OSR|ID=ubuntu\nOSR|VERSION_ID="22.04"\nOSR|PRETTY_NAME="Ubuntu 22.04.5 LTS"\nPM|apt-get\n'


class AssessTest(unittest.TestCase):
    def test_complete_assess(self):
        rem = FakeRemote(default_rc=1, rules=[
            ("id -u", "0", 0),
            ("for m in apt-get dnf yum", OS_DETECT, 0),
            ("uname -r", "5.15.0-198-generic", 0),
            ("uname -m", "x86_64", 0),
            ("${Package}", "installed bash\ninstalled coreutils\ninstalled openssh-server\n", 0),  # snapshot (dpkg state + name)
            ("install -D -m 600", "", 0),                            # manifest write
            ("cat /etc/passwd", fixture("passwd_weak.txt"), 0),
            ("awk -F:", fixture("shadow_weak.txt"), 0),
            ("command -v sshd", "/usr/sbin/sshd", 0),
            ("sshd -T", fixture("sshd_T_weak.txt"), 0),
        ])
        logs = []
        with tempfile.TemporaryDirectory() as out:
            rep = assess(rem, Options(skip={"nmap"}, scan_timeout=60), out, log=logs.append)
            files = list(Path(out).rglob("report.*"))
            modes = {f.name: oct(f.stat().st_mode & 0o777) for f in files}
            saved = json.loads([f for f in files if f.suffix == ".json"][0].read_text())
        self.assertEqual(set(modes.values()), {"0o600"})  # reports readable by the owner only
        names = [s["name"] for s in rep["scans"]]
        self.assertEqual(names, [n for n in ALL_NAMES if n != "nmap"])  # all of them, in order, none lost
        self.assertFalse([s["name"] for s in rep["scans"] if s["status"] == "error"])
        expected = ["report.html", "report.json", "report.json.sha256", "report.md"]
        if importlib.util.find_spec("reportlab"):   # report.pdf only with the optional ReportLab
            expected.append("report.pdf")
        self.assertEqual(sorted(f.name for f in files), expected)
        # The report stays ONLY on the machine running the tool, never on the target.
        self.assertFalse([c for c in rem.calls if "report.md" in c or "report.json" in c])
        self.assertEqual(saved["summary"], rep["summary"])
        # The risk table exists and is sorted by decreasing risk.
        risks = [r["risk"] for r in rep["risks"]]
        self.assertTrue(risks and risks == sorted(risks, reverse=True))
        self.assertEqual(rep["summary"]["level"], rep["risks"][0]["level"])
        self.assertTrue(all(r["id"] == f"R{n:02d}" for n, r in enumerate(rep["risks"], 1)))
        crit = [f["title"] for s in rep["scans"] for f in s["findings"] if f["severity"] == "critical"]
        self.assertTrue(any("backdoor" in t for t in crit))
        self.assertTrue(any("PermitEmptyPasswords" in t for t in crit))
        self.assertIsNotNone(rem.progress)  # the orchestrator wires up the progress messages
        # No new package after the checks -> no removal attempted.
        self.assertFalse([c for c in rem.calls if "purge -y" in c])


if __name__ == "__main__":
    unittest.main()
