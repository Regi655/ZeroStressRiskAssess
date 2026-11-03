"""nmap NSE scripts, ssh-audit and FTP, run from the controller.

REAL fixtures collected in the development sandbox with nmap 7.94 and ssh-audit 3.9.0:
  - nmap_nse_weak.xml: vsftpd with anonymous FTP and a writable directory, nginx with /.git published,
    Allow header with PUT/DELETE/TRACE and an expired self-signed certificate, Redis without a password,
    open memcached;
  - nmap_nse_ok.xml: the same services fixed (anonymous off, requirepass, .git removed);
  - nmap_nse_tls.xml (with ssl-enum-ciphers): nginx with TLS 1.0/1.1 and 1024-bit DH, stock Samba;
  - sshaudit_default.json: freshly installed Ubuntu OpenSSH 9.6;
  - sshaudit_weak.json: the same with 3des-cbc, aes128-cbc, hmac-md5, group1-sha1, ssh-rsa enabled.
The Terrapin and short host key cases are SYNTHETIC, in ssh-audit's JSON format (the strings come from
its source code): there is no old OpenSSH here.
"""
import json
import subprocess
import unittest
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from unittest import mock

from zerostressriskassess import nse, orchestrator
from zerostressriskassess.models import Options, ScanResult
from zerostressriskassess.scanners import ftp, nmap_scan, ssh_audit
from tests.fakes import FakeRemote, fixture, make_ctx

NOW = datetime(2026, 10, 13)


def nse_findings(name):
    _, found = nmap_scan.parse_xml(ET.fromstring(fixture(name)), NOW)
    return [(s, t) for s, t, _ in found if not t.startswith("Open port")]


class NseTest(unittest.TestCase):
    def test_weak_services(self):
        got = nse_findings("nmap_nse_weak.xml")
        self.assertEqual(sorted(got), sorted([
            ("high", "Anonymous FTP with WRITABLE directories (21/tcp): upload"),
            ("high", "Git repository published by the website (80/tcp): 192.0.2.2:80/.git/"),
            ("high", "Git repository published by the website (443/tcp): 192.0.2.2:443/.git/"),
            ("low", "Potentially dangerous HTTP methods advertised (80/tcp): PUT DELETE TRACE"),
            ("low", "Potentially dangerous HTTP methods advertised (443/tcp): PUT DELETE TRACE"),
            ("medium", "TLS certificate EXPIRED (443/tcp) on 2025-01-01"),
            ("low", "Self-signed TLS certificate (443/tcp): commonName=web.lab.example"),
            ("critical", "Redis answers WITHOUT a password (6379/tcp)"),
            ("high", "Memcached reachable without authentication (11211/tcp)"),
        ]))

    def test_fixed_services(self):
        got = nse_findings("nmap_nse_ok.xml")
        self.assertFalse([t for _, t in got if any(w in t for w in ("FTP", "Git", "Redis", "methods"))], got)

    def test_tls_and_smb(self):
        got = nse_findings("nmap_nse_tls.xml")
        self.assertIn(("medium", "Obsolete TLS protocols enabled (443/tcp): TLSv1.0, TLSv1.1"), got)
        self.assertIn(("medium", "Diffie-Hellman Key Exchange Insufficient Group Strength (443/tcp) "
                                 "[ssl-dh-params: VULNERABLE]"), got)
        self.assertIn(("medium", "SMB: message signing NOT required"), got)
        self.assertFalse([t for _, t in got if "lowest grade" in t])   # nmap rates these ciphers A

    def test_anonymous_ftp_read_only(self):
        sc = ET.fromstring('<script id="ftp-anon" output="Anonymous FTP login allowed (FTP code 230)&#10;'
                           'drwxr-xr-x 2 0 0 4096 Oct 13 17:32 pub"/>')
        self.assertEqual([s for s, *_ in nse.evaluate(sc, "21/tcp")], ["medium"])

    def test_script_list(self):
        self.assertNotIn("ssl-enum-ciphers", nmap_scan.script_list(Options()))
        self.assertIn("ssl-enum-ciphers", nmap_scan.script_list(Options(nse_tls=True)))
        self.assertEqual(nmap_scan.script_list(Options(nse=False)), [])

    def test_safe_scripts_only(self):
        # Checks the categories declared by the installed scripts (if nmap is present).
        d = Path("/usr/share/nmap/scripts")
        if not d.is_dir():
            self.skipTest("nmap not installed")
        for s in nse.SAFE_SCRIPTS:
            cats = next(l for l in (d / f"{s}.nse").read_text().splitlines() if l.startswith("categories"))
            self.assertIn('"safe"', cats, s)
            self.assertNotIn('"intrusive"', cats, s)

    def test_nmap_command(self):
        done = subprocess.CompletedProcess([], 0, fixture("nmap_nse_weak.xml"), "")
        with mock.patch.object(nmap_scan.shutil, "which", return_value="/usr/bin/nmap"), \
                mock.patch.object(nmap_scan.subprocess, "run", return_value=done) as run:
            res = nmap_scan.run(make_ctx(FakeRemote(host="192.0.2.2")))
        cmd = run.call_args[0][0]
        self.assertIn("--script", cmd)
        self.assertEqual(cmd[-1], "192.0.2.2")
        self.assertIn("critical", {f.severity for f in res.findings})
        self.assertEqual(len(res.data["open_ports"]), 6)


def audit(name):
    return [(s, t) for s, t, _ in ssh_audit.evaluate(json.loads(fixture(name)))]


class SshAuditTest(unittest.TestCase):
    def test_stock_openssh_info_only(self):
        got = audit("sshaudit_default.json")
        self.assertEqual({s for s, _ in got}, {"info"})
        self.assertIn(("info", "ssh-audit: 17 DEFAULT algorithms flagged as improvable"), got)

    def test_added_algorithms(self):
        got = dict((t, s) for s, t in audit("sshaudit_weak.json"))
        self.assertEqual(got["SSH: weak algorithms enabled in the configuration (ssh-audit)"], "medium")
        self.assertEqual(got["SSH: discouraged algorithms enabled in the configuration (ssh-audit)"], "low")
        detail = ssh_audit.evaluate(json.loads(fixture("sshaudit_weak.json")))[0][2]
        for alg in ("3des-cbc", "hmac-md5", "diffie-hellman-group1-sha1", "ssh-rsa"):
            self.assertIn(alg, detail)
        self.assertNotIn("curve25519", detail)   # stock: goes in the info line

    def test_terrapin_and_short_key(self):
        d = {"banner": {"raw": "SSH-2.0-OpenSSH_8.2p1"},
             "enc": [{"algorithm": "chacha20-poly1305@openssh.com", "notes": {"warn": [
                 "vulnerable to the Terrapin attack (CVE-2023-48795), allowing message prefix truncation"]}}],
             "key": [{"algorithm": "rsa-sha2-512", "keysize": 1024, "notes": {"fail": ["using small 1024-bit modulus"]}}]}
        got = [(s, t) for s, t, _ in ssh_audit.evaluate(d)]
        self.assertIn(("medium", "SSH vulnerable to Terrapin (CVE-2023-48795)"), got)
        self.assertIn(("medium", "SSH: host key too short"), got)

    def test_ports_and_command(self):
        ctx = make_ctx(FakeRemote(host="192.0.2.2", port=2222))
        ctx.cache["nmap_open"] = [{"port": 2222, "service": "ssh OpenSSH"}, {"port": 2223, "service": "ssh"},
                                  {"port": 80, "service": "http"}]
        self.assertEqual(ssh_audit.targets(ctx), [2222, 2223])
        out = [subprocess.CompletedProcess([], 3, fixture("sshaudit_default.json"), ""),
               subprocess.CompletedProcess([], 1, "", "connection refused")]
        with mock.patch.object(ssh_audit.shutil, "which", return_value="/usr/bin/ssh-audit"), \
                mock.patch.object(ssh_audit.subprocess, "run", side_effect=out) as run:
            res = ssh_audit.run(ctx)
        self.assertIn("--skip-rate-test", run.call_args_list[0][0][0])
        self.assertEqual(res.data["ports"], [2222])
        self.assertIn("ssh-audit: no SSH answer on port 2223", [f.title for f in res.findings])

    def test_not_installed(self):
        with mock.patch.object(ssh_audit.shutil, "which", return_value=None):
            self.assertEqual(ssh_audit.run(make_ctx(FakeRemote())).status, "skipped")


def ftp_scan(conf_fixture, nmap_titles=(), find=""):
    rules = [("ps -eo pid=,comm=", "1 sshd\n9 vsftpd\n", 0),
             ("cmdline", "vsftpd /etc/vsftpd/vsftpd.conf ", 0),
             ("find /srv/ftp", find, 0),
             ("getent passwd ftp", "ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin\n", 0)]
    if conf_fixture:
        rules.insert(0, ("cat /etc/vsftpd/vsftpd.conf", fixture(conf_fixture), 0))
    ctx = make_ctx(FakeRemote(default_rc=1, rules=rules))
    ctx.cache["nmap_titles"] = list(nmap_titles)
    res = ftp.run(ctx)
    return res, [(f.severity, f.title) for f in res.findings if f.severity != "info"]


class FtpTest(unittest.TestCase):
    """REAL report of the Rocky lab with 0.9.0: nmap saw anonymous FTP but, with pasv_enable=NO, not the
    file list, hence not the writable directories. Reproduced here with the same vsftpd.conf
    (nmap_ftp_no_pasv.xml, real)."""

    def test_nmap_without_listing_says_so(self):
        sc = ET.fromstring(fixture("nmap_ftp_no_pasv.xml")).find(".//script[@id='ftp-anon']")
        (sev, title, detail), = nse.evaluate(sc, "21/tcp")
        self.assertEqual(sev, "medium")
        self.assertIn("PASV failed", detail)
        self.assertIn("NOT possible to tell", detail)

    def test_rocky_lab(self):
        res, got = ftp_scan("vsftpd_rocky_lab.conf", ["Anonymous FTP allowed (21/tcp)"],
                            find="/srv/ftp/pub\n/srv/ftp/upload\n")
        self.assertEqual(got, [
            ("high", "FTP: the anonymous user can WRITE to the server"),
            ("medium", "FTP: system users with clear-text passwords (local_enable=YES, ssl_enable=NO)"),
            ("low", "FTP: local users not confined to their home directory (chroot_local_user=NO)")])
        self.assertIn("/srv/ftp/upload", res.findings[0].detail)

    def test_stock_ubuntu_configuration(self):
        # Real file of the Ubuntu 24.04 vsftpd package: anonymous off, local users without TLS.
        _, got = ftp_scan("vsftpd_ubuntu_default.conf")
        self.assertEqual([s for s, _ in got], ["medium", "low"])
        self.assertFalse([t for _, t in got if "nonymous" in t])

    def test_without_file_stock_values(self):
        # Verified: vsftpd 3.0.5 with only listen=YES accepts anonymous login (read-only).
        res, got = ftp_scan(None)
        self.assertEqual(got, [("medium", "Anonymous FTP enabled in the configuration (anonymous_enable=YES)")])
        self.assertEqual(res.data["config"], "(no file: built-in defaults)")

    def test_anonymous_seen_by_nmap_info_only(self):
        self.assertEqual(ftp.evaluate(ftp.parse_conf("anonymous_enable=YES\n"), [], True)[0][0], "info")

    def test_no_ftp(self):
        self.assertEqual(ftp.run(make_ctx(FakeRemote(rules=[("ps -eo", "1 sshd\n", 0)]))).status, "skipped")


class OrchestratorTest(unittest.TestCase):
    def test_nmap_ports_not_overwritten(self):
        seen = {}

        def fake_nmap(ctx):
            r = ScanResult("nmap")
            r.data["open_ports"] = [{"port": 22, "service": "ssh"}]
            return r

        def spy(ctx):
            seen["open"] = ctx.cache.get("nmap_open")
            return ScanResult("spy")

        class Stop(Exception):
            pass

        rem = FakeRemote()
        rem.connect = mock.Mock(side_effect=Stop)
        ext = [("nmap", fake_nmap), ("ssh_audit", lambda c: ScanResult("ssh_audit")), ("spy", spy)]
        with mock.patch.object(orchestrator, "EXTERNAL", ext), self.assertRaises(Stop):
            orchestrator.assess(rem, Options(), "/nonexistent", log=lambda *_: None)
        self.assertEqual(seen["open"], [{"port": 22, "service": "ssh"}])


if __name__ == "__main__":
    unittest.main()
