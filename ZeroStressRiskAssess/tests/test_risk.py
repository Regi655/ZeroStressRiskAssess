"""Risk model (impact x likelihood), Markdown/HTML report, command line, local execution.

rocky_0110_report.json is a REAL report (Rocky lab): its findings are the input of the model. The ports
"seen by nmap" are the real ones of that report (21 and 22).
"""
import json
import os
import unittest
from pathlib import Path
from unittest import mock

from zerostressriskassess import cli, risk
from zerostressriskassess.correlate import analyze
from zerostressriskassess.models import ScanResult
from zerostressriskassess.cve import db_info
from zerostressriskassess.htmlreport import to_html
from zerostressriskassess.report import _md, build_report, save, to_markdown
from zerostressriskassess.ssh_client import Local
from tests.fakes import fixture


def rocky(nmap):
    rep = json.loads(fixture("rocky_0110_report.json"))
    scans = rep["scans"]
    for sc in scans:
        for f in sc["findings"]:
            f.pop("issue", None)
    return risk.assess(scans, analyze(scans), {"nmap": nmap, "ssh_port": 22, "why_no_nmap": "local mode"})


class ScaleTest(unittest.TestCase):
    def test_levels(self):
        self.assertEqual([risk.level(r) for r in (1, 4, 5, 9, 10, 14, 15, 25)],
                         ["LOW", "LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH", "CRITICAL", "CRITICAL"])

    def test_every_rule_has_valid_values_and_a_fix(self):
        for s, rx, i, p, v, svc, fx in risk.RULES:
            self.assertTrue(1 <= i <= 5 and 1 <= p <= 5, rx.pattern)
            self.assertIn(v, risk.VECTOR, rx.pattern)
            self.assertTrue(fx, rx.pattern)
        self.assertEqual(sorted(risk.IMPACT), [1, 2, 3, 4, 5])
        self.assertEqual(sorted(risk.PROBABILITY), [1, 2, 3, 4, 5])


class RockyTest(unittest.TestCase):
    def test_risk_order(self):
        r = rocky({21, 22})
        top = [(x["title"], x["risk"], x["impact"], x["probability"]) for x in r[:3]]
        self.assertEqual(top[0], ("SSH login without password (accounts: guest)", 25, 5, 5))
        self.assertIn(("Anonymous FTP with file upload by anyone", 20, 4, 5), top)
        self.assertEqual([x["risk"] for x in r], sorted((x["risk"] for x in r), reverse=True))

    def test_unreachable_port_lowers_likelihood(self):
        ftp = lambda rs: next(x for x in rs if x["title"].startswith("Anonymous FTP with"))  # noqa: E731
        open_, closed = ftp(rocky({21, 22})), ftp(rocky({22}))
        self.assertEqual((open_["probability"], closed["probability"]), (5, 3))
        self.assertIn("NOT reachable from the controller", closed["probability_why"])

    def test_local_mode_is_stated(self):
        ssh = next(x for x in rocky(None) if x["title"].startswith("SSH login without password"))
        self.assertIn("exposure not verified from outside: local mode", ssh["probability_why"])

    def test_every_row_has_a_fix(self):
        missing = [x["title"] for x in rocky({21, 22}) if not x.get("fix")]
        self.assertEqual(missing, [])


class PatchTest(unittest.TestCase):
    def rate(self, cves):
        scans = [{"name": "updates", "findings": [{"id": "F001", "severity": "high",
                                                   "title": "3 security updates not installed", "detail": ""}],
                  "data": {}},
                 {"name": "cve", "findings": [{"id": "F002", "severity": "high",
                                               "title": "openssl: 1 CVEs fixed by the update already available (x)",
                                               "detail": ""}], "data": {}}]
        return risk.assess(scans, analyze(scans), {"nmap": set(), "cve_now": cves})[0]

    def test_kev_maximum_likelihood(self):
        r = self.rate([{"severity": "medium", "kev": True, "cvss": []}])
        self.assertEqual((r["impact"], r["probability"]), (3, 5))
        self.assertIn("CISA KEV", r["probability_why"])

    def test_network_and_local(self):
        net = self.rate([{"severity": "high", "kev": False, "cvss": ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"]}])
        loc = self.rate([{"severity": "high", "kev": False, "cvss": ["CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"]}])
        self.assertEqual((net["probability"], loc["probability"]), (4, 3))
        self.assertEqual(net["title"], "Security updates not installed (1 packages with fixable known CVEs)")

    def test_automatic_updates_are_not_the_patch_group(self):
        # "Automatic security updates not enabled" contains "security updates": it must stay a separate,
        # low risk and must not be merged into (or rated like) the missing-patches problem.
        scans = [{"name": "updates", "findings": [
            {"id": "F001", "severity": "high", "title": "3 security updates not installed", "detail": ""},
            {"id": "F002", "severity": "low", "title": "Automatic security updates not enabled", "detail": ""}],
            "data": {}}]
        rows = risk.assess(scans, analyze(scans), {"nmap": set()})
        auto = next(x for x in rows if x["title"] == "Automatic security updates not enabled")
        self.assertEqual((auto["impact"], auto["probability"], auto["level"]), (2, 2, "LOW"))
        self.assertEqual(len(rows), 2)


class RootkitRulesTest(unittest.TestCase):
    def rate(self, scan, sev, title):
        scans = [{"name": scan, "findings": [{"id": "F001", "severity": sev, "title": title, "detail": ""}], "data": {}}]
        r = risk.assess(scans, analyze(scans), {"nmap": None})[0]
        return r["impact"], r["probability"], r["level"]

    def test_false_positive_is_low_and_real_infection_critical(self):
        self.assertEqual(self.rate("chkrootkit", "low", "chkrootkit: 'date' reported INFECTED, but identical to "
                                   "package coreutils"), (1, 1, "LOW"))
        self.assertEqual(self.rate("chkrootkit", "critical", "chkrootkit: 'date' INFECTED and DIFFERENT from "
                                   "package coreutils"), (5, 5, "CRITICAL"))
        self.assertEqual(self.rate("chkrootkit", "low", "chkrootkit: Possible Linux BPFDoor Malware installed - "
                                   "processes from intact packages (probable false positive)"), (1, 1, "LOW"))
        self.assertEqual(self.rate("rkhunter", "low", "rkhunter: /usr/sbin/sshd changed since the baseline, but "
                                   "identical to package openssh-server"), (1, 1, "LOW"))
        self.assertEqual(self.rate("rkhunter", "critical", "rkhunter: rootkit detected"), (5, 5, "CRITICAL"))


def res(name, *findings, data=None):
    r = ScanResult(name)
    for sev, title, detail in findings:
        r.add(sev, title, detail)
    r.data = data or {}
    return r


class ReportTest(unittest.TestCase):
    def setUp(self):
        self.rep = build_report(
            {"target": "srv1", "timestamp": "2026-10-14 13:00", "os": "Ubuntu 24.04", "kernel": "6.8",
             "mode": "remote over SSH", "sources": ["nmap", "Lynis 3.1.8"], "version": "1.0.0"},
            [res("nmap", ("critical", "Redis answers WITHOUT a password (6379/tcp)", "")),
             res("sshd", ("low", "SSH: X11Forwarding enabled", "")),
             res("accounts", ("medium", "Account <b>x</b> | [link](http://evil)", "x"))], [],
            {"nmap": {6379, 22}, "ssh_port": 22})
        self.md = to_markdown(self.rep)

    def test_structure(self):
        for h in ("## Overall risk: **CRITICAL**", "## Risk matrix", "## Risk table", "## Method",
                  "## Appendix"):
            self.assertIn(h, self.md)
        self.assertLess(self.md.index("## Risk matrix"), self.md.index("## Risk table"))
        first = next(l for l in self.md.splitlines() if l.startswith("| R01"))
        self.assertIn("Redis answers WITHOUT a password", first)
        self.assertIn("25 (5x5)", first)

    def test_matrix_counts_every_problem(self):
        self.assertEqual(sum(self.rep["summary"]["matrix"].values()), len(self.rep["risks"]))

    def test_target_text_is_neutralised(self):
        self.assertNotIn("<b>", self.md)
        self.assertIn("\\[link\\](http://evil)", self.md)   # square brackets escaped: no link
        self.assertEqual(_md("a|b"), "a\\|b")    # a pipe does not break the table

    def test_markdown_graphics_ascii_only(self):
        # Unicode arrows, dots and "×" in Markdown were rendered as boxes in VS Code and terminals
        for ch in "\u2193\u2192\u00b7\u2026\u00d7":
            self.assertNotIn(ch, self.md)

    def test_html(self):
        h = to_html(self.rep)
        self.assertTrue(h.startswith("<!doctype html>"))
        self.assertIn("default-src 'none'", h)          # no external resources, no scripts
        self.assertNotIn("<script", h)
        self.assertNotIn("<b>x</b>", h)                  # target text: escaped
        self.assertIn("&lt;b&gt;x&lt;/b&gt;", h)
        self.assertNotIn('href="http://evil"', h)
        self.assertIn('class="matrix"', h)
        self.assertLess(h.index("Risk matrix"), h.index("Risk table"))
        self.assertIn("Redis answers WITHOUT a password", h)

    def test_save_also_writes_private_html(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = save(self.rep, self.md, d, "srv1", "20261014-130000", html=to_html(self.rep))
            for n in ("report.html", "report.md", "report.json", "report.json.sha256"):
                self.assertEqual(os.stat(p / n).st_mode & 0o777, 0o600, n)

    def test_grype_db_info(self):
        self.assertEqual(db_info({"descriptor": {"version": "0.92.2", "db": {"status": {"built": "2026-10-14T04:12:00Z"}}}}),
                         "v0.92.2, database of 2026-10-14")
        self.assertEqual(db_info({"descriptor": {"db": {"built": "2024-08-01T00:00:00Z"}}}), "database of 2024-08-01")
        self.assertEqual(db_info({}), "")

    def test_findings_point_to_problems(self):
        f = [f for sc in self.rep["scans"] for f in sc["findings"]]
        self.assertEqual({x["issue"] for x in f}, {r["id"] for r in self.rep["risks"]})


class CliTest(unittest.TestCase):
    def test_no_arguments_opens_the_console(self):
        with mock.patch("zerostressriskassess.console.run", return_value=0) as run:
            self.assertEqual(cli.main([]), 0)
        run.assert_called_once()

    def test_host_or_local(self):
        for argv in (["--no-banner"], ["10.0.0.1", "--local"], ["10.0.0.1"]):
            with self.assertRaises(SystemExit), mock.patch("sys.stderr"):
                cli.main(argv)

    def test_default_lynis_inside_the_project(self):
        args = cli.build_parser().parse_args(["--local"])
        self.assertTrue(args.lynis_dir.endswith(os.path.join("vendor", "lynis")))

    def test_sudo_pass_env(self):
        # the password comes from the named variable and reaches the SSH client; an empty variable is an error
        with mock.patch.dict(os.environ, {"TEST_SUDO": "secret"}), \
                mock.patch.object(cli, "assess", side_effect=RuntimeError("stop")) as fake, \
                mock.patch("sys.stderr"):
            self.assertEqual(cli.main(["10.0.0.1", "-u", "dev", "--yes", "--sudo-pass-env", "TEST_SUDO"]), 2)
            self.assertEqual(fake.call_args[0][0].sudo_password, "secret")
        with mock.patch.dict(os.environ, {}, clear=True), self.assertRaises(SystemExit), mock.patch("sys.stderr"):
            cli.main(["10.0.0.1", "-u", "dev", "--yes", "--sudo-pass-env", "DOES_NOT_EXIST"])
        with self.assertRaises(SystemExit), mock.patch("sys.stderr"):   # the two options are mutually exclusive
            cli.build_parser().parse_args(["--local", "--ask-sudo-pass", "--sudo-pass-env", "X"])


class LabTest(unittest.TestCase):
    """The lab: valid scripts, four profiles consistent across lab.sh, docker-compose.yml and profiles/."""
    LAB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lab")

    def test_bash_scripts_are_valid(self):
        import subprocess
        scripts = ["lab.sh", "entrypoint.sh"] + [os.path.join("profiles", p)
                                                 for p in os.listdir(os.path.join(self.LAB, "profiles"))]
        for f in scripts:
            r = subprocess.run(["bash", "-n", os.path.join(self.LAB, f)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, f + r.stderr)

    def test_profiles_are_consistent(self):
        profiles = {p[:-3] for p in os.listdir(os.path.join(self.LAB, "profiles")) if p.endswith(".sh")}
        self.assertEqual(profiles, {"severe", "medium", "clean", "secure"})
        lab = Path(self.LAB, "lab.sh").read_text(encoding="utf-8")
        compose = Path(self.LAB, "docker-compose.yml").read_text(encoding="utf-8")
        for p in profiles:
            self.assertIn(f"[{p}]=", lab)
            self.assertIn(f"PROFILE: {p}", compose)
            # every profile script refuses to run outside the image build (it must NEVER touch your machine)
            script = Path(self.LAB, "profiles", p + ".sh").read_text(encoding="utf-8")
            self.assertIn('LAB_BUILD:-}" = 1', script)


class LocalTest(unittest.TestCase):
    def test_really_runs(self):
        loc = Local()
        r = loc.run("echo $LC_ALL; echo $PATH")
        self.assertEqual(r.rc, 0)
        self.assertEqual(r.out.splitlines(), ["C", "/usr/sbin:/usr/bin:/sbin:/bin"])
        self.assertEqual(loc.run("exit 3").rc, 3)
        self.assertEqual(loc.run("sleep 5", timeout=1).rc, 124)


class MultipleExposureTest(unittest.TestCase):
    def test_counts_the_reachable_port(self):
        # Real run in the sandbox: "2024/tcp, 2025/tcp, 21/tcp" with only 21 seen by nmap.
        f = {"title": "No active firewall and services reachable besides SSH: 2024/tcp, 2025/tcp, 21/tcp"}
        self.assertEqual(risk.exposure("network", "port", f, {"nmap": {21, 22}})[0], 0)
        self.assertEqual(risk.exposure("network", "port", f, {"nmap": {22}})[0], -2)


if __name__ == "__main__":
    unittest.main()
