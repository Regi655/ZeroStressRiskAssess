"""Correlation (findings -> problems), severity of the problems, MITRE ATT&CK / CIS references.

rocky_092_report.json is the REAL report of the Rocky lab produced by version 0.9.2 (lab data, no personal
data; the titles are translated to the current English wording). The only addition is data.anon_root of the
ftp check, which 0.9.2 did not record yet: the value (/srv/ftp) is the one written in the detail of finding
F033 of the same report.
"""
import json
import unittest

from zerostressriskassess.correlate import REFS, analyze, refs_for
from zerostressriskassess.models import ScanResult
from zerostressriskassess.report import build_report
from tests.fakes import fixture


def rocky():
    rep = json.loads(fixture("rocky_092_report.json"))
    for sc in rep["scans"]:
        for f in sc["findings"]:
            f.pop("issue", None)
        if sc["name"] == "ftp":
            sc["data"]["anon_root"] = "/srv/ftp"
    return rep


class RockyTest(unittest.TestCase):
    def setUp(self):
        self.rep = rocky()
        self.issues = analyze(self.rep["scans"])
        self.by_ev = {tuple(sorted(i["evidence"])): i for i in self.issues}

    def test_anonymous_ftp_is_one_problem(self):
        i = self.by_ev[("F002", "F024", "F025", "F033")]
        self.assertEqual((i["severity"], i["title"]),
                         ("high", "Anonymous FTP with file upload by anyone"))
        self.assertIn("anonymous_enable=NO", i["fix"])

    def test_opt_app_stays_separate(self):   # also 777, but unrelated to FTP
        self.assertIn(("F023",), self.by_ev)

    def test_passwordless_ssh_chain(self):
        i = self.by_ev[("F011", "F016")]
        self.assertEqual((i["severity"], i["title"]), ("critical", "SSH login without password (accounts: guest)"))
        self.assertEqual(i["refs"]["mitre"], ["T1078.003", "T1021.004"])

    def test_cleartext_ftp_seen_by_nmap_and_ftp(self):
        i = self.by_ev[("F001", "F034")]
        self.assertTrue(i["title"].startswith("Network-exposed service on port 21"))
        self.assertIn("SFTP", i["fix"])

    def test_every_finding_has_its_problem(self):
        for sc in self.rep["scans"]:
            for f in sc["findings"]:
                self.assertEqual("issue" in f, f["severity"] != "info", f["id"])


def br(results):
    return build_report({"target": "t"}, results, [], {"nmap": None})["risks"]


def res(name, *findings, data=None):
    r = ScanResult(name)
    for sev, title, detail in findings:
        r.add(sev, title, detail)
    r.data = data or {}
    return r


class RulesTest(unittest.TestCase):
    def test_same_defect_counts_once(self):
        two = br([res("sshd", ("medium", "SSH: weak ciphers enabled", "3des-cbc")),
                  res("ssh_audit", ("medium", "SSH: weak algorithms enabled in the configuration (ssh-audit)", "x"))])
        self.assertEqual([r["title"] for r in two], ["Weak SSH algorithms enabled"])

    def test_777_directory_outside_the_ftp_root(self):
        scans = br([
            res("ftp", ("high", "FTP: the anonymous user can WRITE to the server", ""), data={"anon_root": "/srv/ftp"}),
            res("permissions", ("high", "World-writable directory without sticky bit", "/srv/ftpx"),
                ("high", "World-writable directory without sticky bit", "/srv/ftp/in"))])
        self.assertEqual(sorted(len(i["evidence"]) for i in scans), [1, 2])

    def test_mysql_and_redis_ports(self):
        rep = br([
            res("nmap", ("medium", "Open port 3306/tcp: mysql MySQL 8.0.46", "MySQL/MariaDB database exposed"),
                ("high", "Open port 6379/tcp: redis Redis", ""),
                ("critical", "Redis answers WITHOUT a password (6379/tcp)", "")),
            res("mysql", ("medium", "MySQL reachable from the controller (port 3306)", ""))])
        titles = {i["title"]: (i["severity"], len(i["evidence"])) for i in rep}
        self.assertEqual(titles["Network-exposed service on port 3306 (mysql MySQL 8.0.46)"], ("medium", 2))
        self.assertEqual(titles["Network-exposed service on port 6379 (redis Redis)"], ("critical", 2))

    def test_group_of_one_is_not_a_group(self):
        rep = br([res("accounts", ("critical", "Account 'x' with an empty password in /etc/shadow", ""))])
        self.assertEqual(rep[0]["title"], "Account 'x' with an empty password in /etc/shadow")

    def test_references(self):
        self.assertEqual(refs_for("sudoers", "'dev' can run any command as root")["mitre"], ["T1548.003"])
        self.assertEqual(refs_for("sudoers", "Members of group wheel: none"), {"mitre": [], "cis": []})
        for _, _, mitre, cis in REFS:
            for t in mitre:
                self.assertRegex(t, r"^T\d{4}(\.\d{3})?$")
            for c in cis:
                self.assertRegex(c, r"^\d{1,2}\.\d{1,2}$")

    def test_ns1_zones_and_sudo_line(self):
        # REAL report of ns1 (ISP lab, 0.6.1): two transferable zones = one missing allow-transfer line;
        # NOPASSWD and "any command" come from the same sudoers line.
        issues = analyze(json.loads(fixture("ns1_061_report.json"))["scans"])
        ev = {tuple(i["evidence"]): i for i in issues}
        self.assertTrue(ev[("F022", "F023")]["title"].startswith("DNS: zone transfer (AXFR)"))
        self.assertIn("allow-transfer", ev[("F022", "F023")]["fix"])
        self.assertEqual(ev[("F007", "F008")]["severity"], "high")
        self.assertIn("NOPASSWD", ev[("F007", "F008")]["fix"])

    def test_reports_of_other_labs(self):
        for name in ("ns1_061_report.json",):
            rep = json.loads(fixture(name))
            issues = analyze(rep["scans"])
            self.assertTrue(issues)
            self.assertEqual(len({i["id"] for i in issues}), len(issues))
