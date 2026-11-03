"""Real cases from the lab virtual machines: every test reproduces a problem found (and fixed) in the field.

The test name states what must NOT happen again. If one of these fails, an old bug has come back.
"""
import unittest

from zerostressriskassess.scanners import accounts, firewall, listeners, lynis_scan, rootkit, sshd_conf, updates
from tests.fakes import FakeRemote, fixture, make_ctx


def sev(res, severity):
    return [f for f in res.findings if f.severity == severity]


def titles(res):
    return " | ".join(f.title for f in res.findings)


class ChkrootkitTest(unittest.TestCase):
    def run_chk(self, name):
        rem = FakeRemote(rules=[("chkrootkit", fixture(name))])
        return rootkit.run_chkrootkit(make_ctx(rem, tools_ok={"chkrootkit"}))

    def test_headers_are_not_warnings(self):  # 0.2.3
        res = self.run_chk("chkrootkit_weak.txt")
        self.assertNotIn("item to verify", titles(res))

    def test_files_after_infected_attached_to_the_alert(self):  # 0.2.3
        res = self.run_chk("chkrootkit_weak.txt")
        xor = [f for f in res.findings if "Xor.DDoS" in f.detail]
        self.assertEqual(len(xor), 1)
        # 0.11.0: an executable in /tmp is chkrootkit's generic heuristic (see rootkit.py): medium.
        self.assertEqual(xor[0].severity, "medium")
        self.assertIn("/tmp/prepare_weak_target.sh", xor[0].detail)
        self.assertEqual(res.data["hidden_files_listed"], 1)  # only .build-id, not the script

    def test_backdoor_port_critical(self):
        res = self.run_chk("chkrootkit_weak.txt")
        self.assertTrue(any("31337" in f.detail for f in sev(res, "critical")))

    def test_networkd_sniffer_info_only(self):  # 0.2.3
        res = self.run_chk("chkrootkit_clean.txt")
        self.assertEqual(sev(res, "critical") + sev(res, "high") + sev(res, "medium"), [])


class ChkrootkitSandboxTest(unittest.TestCase):
    """REAL output of chkrootkit 0.58b in the development sandbox (working paths replaced with /tmp/work):
    38 executables in /tmp, 33 "RTNETLINK answers" lines, 19 "/proc/1/fd/N: Permission denied"."""

    def setUp(self):
        rem = FakeRemote(default_rc=1, rules=[("chkrootkit -q", fixture("chkrootkit_sandbox_tmp.txt"), 0)])
        self.res = rootkit.run_chkrootkit(make_ctx(rem, tools_ok={"chkrootkit"}))

    def test_executables_in_tmp_one_medium_line(self):
        tmp = [f for f in self.res.findings if f.title.startswith("Executable files in /tmp")]
        self.assertEqual([(f.severity, f.title) for f in tmp], [("medium", "Executable files in /tmp (38)")])

    def test_command_errors_are_not_findings(self):
        self.assertFalse([f for f in self.res.findings if "RTNETLINK" in f.title
                          or (f.title.endswith("to verify") and f.severity == "medium")])
        err = [f for f in self.res.findings if "error messages" in f.title]
        self.assertEqual(err[0].title, "chkrootkit: error messages from the commands it runs (2 distinct)")
        self.assertEqual(self.res.data["hidden_files_unpackaged"], 16)   # it was 35 with /proc/1/fd/N

    def test_specific_ioc_stays_critical(self):
        d = rootkit.parse_chkrootkit("WARNING: Possible Linux.Xor.DDoS installed:\n/etc/cron.hourly/gcc.sh\n/tmp/a\n")
        self.assertEqual(d["alerts"][0]["files"], ["/etc/cron.hourly/gcc.sh", "/tmp/a"])
        rem = FakeRemote(default_rc=1, rules=[("chkrootkit -q", "WARNING: Possible Linux.Xor.DDoS installed:\n"
                                               "/etc/cron.hourly/gcc.sh\n", 0)])
        res = rootkit.run_chkrootkit(make_ctx(rem, tools_ok={"chkrootkit"}))
        self.assertEqual([f.severity for f in res.findings], ["critical"])


class FirewallTest(unittest.TestCase):
    def run_fw(self, ss):
        # default_rc=1: anything not listed "fails" (e.g. firewalld not running, nft missing)
        rem = FakeRemote(default_rc=1, rules=[("iptables -S", fixture("iptables_empty.txt")),
                                              ("ss -tuln", fixture(ss)), ("ufw status", "Status: inactive")])
        return firewall.run(make_ctx(rem))

    def test_dhcp_client_is_not_a_service(self):  # 0.3.1: 68/udp produced a false "high"
        res = self.run_fw("ss_clean.txt")
        self.assertEqual(sev(res, "high"), [])
        self.assertEqual(len(sev(res, "medium")), 1)

    def test_exposed_port_without_firewall_is_high(self):
        res = self.run_fw("ss_weak.txt")
        self.assertEqual(len(sev(res, "high")), 1)
        self.assertIn("31337/tcp", sev(res, "high")[0].title)
        self.assertNotIn("68/udp", sev(res, "high")[0].title)


class ListenersTest(unittest.TestCase):
    def test_parse_real_ss(self):
        socks = listeners.parse_ss(fixture("ss_weak.txt"))
        self.assertEqual(len(socks), 6)
        p = [s for s in socks if s["port"] == 31337][0]
        self.assertFalse(p["loopback"])
        self.assertEqual(p["procs"], [("python3", 121818)])
        self.assertTrue([s for s in socks if s["port"] == 53][0]["loopback"])  # 127.0.0.53%lo

    def test_exposed_interpreter_is_high(self):
        rem = FakeRemote(rules=[
            ("ss -tulpn", fixture("ss_weak.txt")),
            ("for p in", "PID|121818|nobody|/usr/bin/python3.10|/usr/bin/python3 -m http.server 31337 --directory /srv/fake\n"
                         "PID|1032|root|/usr/sbin/sshd|sshd: /usr/sbin/sshd -D\n"),
            ("dpkg -S", "openssh-server: /usr/sbin/sshd")])
        res = listeners.run(make_ctx(rem))
        high = sev(res, "high")
        self.assertEqual(len(high), 1)
        self.assertIn("31337", high[0].title)
        self.assertIn("nobody", high[0].detail)


class AccountsTest(unittest.TestCase):
    def test_backdoor_single_finding(self):  # 0.3.0: it was 3-4 lines for the same account
        rem = FakeRemote(rules=[("cat /etc/passwd", fixture("passwd_weak.txt")),
                                ("awk -F:", fixture("shadow_weak.txt"))])
        res = accounts.run(make_ctx(rem))
        backdoor = [f for f in res.findings if "backdoor" in f.title]
        self.assertEqual(len(backdoor), 1)
        self.assertEqual(backdoor[0].severity, "critical")
        self.assertIn("GID 0", backdoor[0].detail)
        self.assertTrue(any("user_nopw" in f.title for f in sev(res, "critical")))
        self.assertNotIn("UID 0 shared", titles(res))


class SshdTest(unittest.TestCase):
    def run_sshd(self, text, rc=0):
        rem = FakeRemote(rules=[("command -v sshd", "/usr/sbin/sshd"), ("sshd -T", text, rc)])
        return sshd_conf.run(make_ctx(rem))

    def test_empty_passwords_critical(self):
        res = self.run_sshd(fixture("sshd_T_weak.txt"))
        self.assertTrue(any("PermitEmptyPasswords" in f.title for f in sev(res, "critical")))

    def test_ubuntu_defaults_without_false_crypto_alarms(self):
        # The default MACs include umac-64 and hmac-sha1: they must not be reported as broken.
        res = self.run_sshd(fixture("sshd_T_weak.txt"))
        self.assertNotIn("weak", titles(res))

    def test_permitempty_no_no_critical(self):  # the run in which the drop-in was not applied
        res = self.run_sshd(fixture("sshd_T_weak.txt").replace("permitemptypasswords yes", "permitemptypasswords no"))
        self.assertEqual(sev(res, "critical"), [])


class UpdatesTest(unittest.TestCase):
    def run_upd(self, apt_check="71;3"):
        rem = FakeRemote(rules=[
            ("apt-get -s upgrade", fixture("apt_upgrade_vm.txt")),
            ("apt-get -s dist-upgrade", fixture("apt_dist_upgrade_vm.txt")),
            ("apt-check", apt_check),
            ("dpkg-query -W -f='${Status}'", "install ok installed"),
            ("apt-config", 'APT::Periodic::Unattended-Upgrade "1";'),
            ("reboot-required", "", 1)])  # no pending reboot
        return updates.run(make_ctx(rem))

    def test_new_packages_from_security_are_not_vulnerabilities(self):  # 0.3.3
        res = self.run_upd()
        self.assertEqual(res.data["security"], 0)
        self.assertEqual(sorted(res.data["new_from_security"]), ["jq", "libjq1", "libprotobuf-c1"])
        self.assertEqual(sev(res, "medium") + sev(res, "high"), [])

    def test_new_packages_do_not_count_as_updates(self):  # 0.3.2
        res = self.run_upd()
        self.assertEqual(res.data["upgradable"], 4)  # apparmor, apt, fwupd, netplan.io (lines with [old version])

    def test_unexplained_apt_check_difference_raises_severity(self):
        res = self.run_upd(apt_check="71;5")  # 5 = 3 explained + 2 unexplained
        self.assertEqual(res.data["security"], 2)
        self.assertEqual(len(sev(res, "medium")), 1)
        self.assertIn("not identified", sev(res, "medium")[0].detail)

    def test_held_back_read(self):
        res = self.run_upd()
        self.assertEqual(res.data["held_back"], 4)


class LynisTest(unittest.TestCase):
    def run_lynis(self, skip=()):
        # Only portable Lynis is used: this exercises the parsing of report.dat.
        from zerostressriskassess.models import ScanResult
        return lynis_scan.parse(ScanResult("lynis"), fixture("lynis_report.dat"), make_ctx(FakeRemote(), skip=skip))

    def test_covered_warnings_become_info(self):  # 0.3.0: no double counting
        res = self.run_lynis()
        covered = [f for f in res.findings if "(already covered by the" in f.title]
        self.assertEqual(len(covered), 4)
        self.assertTrue(all(f.severity == "info" for f in covered))
        self.assertEqual([f.detail for f in sev(res, "high")], ["TIME-3185"])  # not covered: stays high

    def test_skipped_check_warning_is_high_again(self):
        res = self.run_lynis(skip={"firewall"})
        self.assertTrue(any("iptables" in f.title for f in sev(res, "high")))

    def test_suggestions_with_same_id_merged(self):  # 0.3.0 (sshd skipped: otherwise SSH-7408 is "already covered")
        res = self.run_lynis(skip={"sshd"})
        ssh = [f for f in res.findings if f.detail.startswith("SSH-7408")]
        self.assertEqual(len(ssh), 1)
        self.assertIn("(3 items)", ssh[0].title)
        self.assertIn("X11Forwarding", ssh[0].detail)
        file = [f for f in res.findings if f.detail.startswith("FILE-6310")]
        self.assertIn("similar", file[0].title)

    def test_covered_suggestions_not_repeated(self):  # 0.6.0
        res = self.run_lynis()
        self.assertFalse([f for f in res.findings if f.severity == "low" and f.detail.startswith("SSH-7408")])
        info = [f for f in res.findings if "not repeated" in f.title]
        self.assertEqual([f.detail for f in info], ["SSH-7408 (sshd)"])

    def test_hardening_index_info_only(self):  # 0.6.0: it was "medium" and counted the suggestions twice
        res = self.run_lynis()
        idx = [f for f in res.findings if "hardening index" in f.title]
        self.assertEqual([f.severity for f in idx], ["info"])

