"""Fixes from the REAL report of the Rocky lab with 0.11.0 (container, portable Lynis 3.1.8, ClamAV in
quick mode). rocky_0110_report.json is that report (titles translated to the current English wording).

The report.dat lines below are rebuilt with the REAL IDs and texts of that report (the original report.dat
stays on the target for a few seconds and is deleted with the temporary directory).
"""
import json
import unittest

from zerostressriskassess.correlate import analyze
from zerostressriskassess.models import ScanResult
from zerostressriskassess.scanners import clamav_scan, lynis_scan
from tests.fakes import FakeRemote, fixture, make_ctx

REPORT_DAT = """lynis_version=3.1.8
hardening_index=59
warning[]=LOGG-2138|klogd is not running, which could lead to missing kernel messages in log files|-|-|
warning[]=AUTH-9208|Multiple accounts found with same UID|-|-|
suggestion[]=BOOT-5264|Consider hardening system services|Run '/usr/bin/systemd-analyze security SERVICE' for each service|-|
suggestion[]=KRNL-5820|If not required, consider explicit disabling of core dump in /etc/security/limits.conf file|-|-|
suggestion[]=FILE-6310|To decrease the impact of a full /home file system, place /home on a separate partition|-|-|
suggestion[]=USB-1000|Disable drivers like USB storage when not used, to prevent unauthorized storage or data theft|-|-|
suggestion[]=STRG-1846|Disable drivers like firewire storage when not used, to prevent unauthorized storage or data theft|-|-|
suggestion[]=NETW-3200|Determine if protocol 'dccp' is really needed on this system|-|-|
suggestion[]=LOGG-2130|Check if any syslog daemon is running and correctly configured.|-|-|
suggestion[]=ACCT-9622|Enable process accounting|-|-|
suggestion[]=BANN-7126|Add a legal banner to /etc/issue, to warn unauthorized users|-|-|
suggestion[]=AUTH-9282|When possible set expire dates for all password protected accounts|-|-|
"""


def lynis(container):
    ctx = make_ctx(FakeRemote())
    ctx.cache["container"] = container
    return lynis_scan.parse(ScanResult("lynis"), REPORT_DAT, ctx)


class LynisInContainerTest(unittest.TestCase):
    def test_klogd_is_not_high_in_a_container(self):
        res = lynis(True)
        self.assertFalse([f for f in res.findings if f.severity == "high"])
        info = [f for f in res.findings if "not applicable in a container" in f.title]
        self.assertEqual(info[0].title, "9 Lynis tests not applicable in a container (they concern the host)")
        self.assertEqual(sorted(f.title.split(" [")[0] for f in res.findings if f.severity == "low"),
                         ["Add a legal banner to /etc/issue, to warn unauthorized users",
                          "When possible set expire dates for all password protected accounts"])

    def test_on_a_real_machine_they_remain(self):
        res = lynis(False)
        self.assertIn("high", {f.severity for f in res.findings})
        self.assertEqual(len([f for f in res.findings if f.severity == "low"]), 10)


class EicarTest(unittest.TestCase):
    def test_test_file_is_not_high(self):
        rem = FakeRemote(rules=[("MemAvailable", "4000", 0), ("clamscan", "/srv/ftp/upload/eicar_test.txt: "
                                                              "Eicar-Signature FOUND\n/tmp/x: Unix.Trojan.Mirai-1 FOUND", 0)])
        res = clamav_scan.run(make_ctx(rem, tools_ok={"clamav"}))
        got = {(f.severity, f.title) for f in res.findings}
        self.assertIn(("low", "EICAR antivirus test file (harmless)"), got)
        self.assertIn(("high", "ClamAV: Unix.Trojan.Mirai-1"), got)


class LynisTipsOneProblemTest(unittest.TestCase):
    def test_report_rocky_0110(self):
        rep = json.loads(fixture("rocky_0110_report.json"))
        issues = analyze(rep["scans"])
        tips = [i for i in issues if i["key"] == "lynis-tips"]
        self.assertEqual(tips[0]["title"], "Lynis hardening suggestions (18)")
        self.assertEqual(len([i for i in issues if i["severity"] == "low"]), 6)   # it was 23


if __name__ == "__main__":
    unittest.main()
