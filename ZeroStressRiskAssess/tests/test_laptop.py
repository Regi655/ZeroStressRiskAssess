"""Real cases from the Ubuntu 26.04 laptop (first run on real hardware, 2026-10-11).

Every test matches a row of the "tool noise" table that came out of that report.
"""
import unittest

from zerostressriskassess.scanners import clamav_scan, integrity, listeners, permissions, rootkit
from tests.fakes import FakeRemote, fixture, make_ctx

COREUTILS = ["basename", "date", "dirname", "echo", "env"]


def sev(res, s):
    return [f for f in res.findings if f.severity == s]


def chk_remote(dpkg_v_coreutils=""):
    return FakeRemote(default_rc=1, rules=[
        ("chkrootkit -q", fixture("chkrootkit_laptop.txt"), 0),
        ("type -P $c", "".join(f"{c}|/usr/bin/{c}\n" for c in COREUTILS), 0),
        ("readlink /proc/$p/exe", "2066|/usr/sbin/chronyd\n", 0),
        ("dpkg -S /usr/sbin/chronyd", "chrony: /usr/sbin/chronyd", 0),
        ("dpkg -S /usr/bin/", "coreutils: /usr/bin/x", 0),
        ("dpkg -V coreutils", dpkg_v_coreutils, 0),
        ("dpkg -V chrony", "", 0),
    ])


class ChkrootkitLaptopTest(unittest.TestCase):
    def test_058_format_parser(self):
        d = rootkit.parse_chkrootkit(fixture("chkrootkit_laptop.txt"))
        self.assertEqual(d["infected_cmds"], COREUTILS)
        self.assertEqual(d["other"], [])  # no more "WARNING: ..." taken for anomalies
        self.assertEqual(len(d["sniffers"]), 1)
        self.assertGreater(len(d["hidden_pkg"]), 20)
        self.assertEqual(d["alerts"][0]["files"], ["/proc/2066/stack"])

    def test_infected_but_identical_to_package_are_low(self):  # empty `dpkg -V coreutils` on the laptop
        res = rootkit.run_chkrootkit(make_ctx(chk_remote(), tools_ok={"chkrootkit"}))
        self.assertEqual(sev(res, "critical") + sev(res, "high") + sev(res, "medium"), [])
        self.assertEqual(len([f for f in sev(res, "low") if "identical to package coreutils" in f.title]), 5)

    def test_infected_and_modified_stays_critical(self):
        res = rootkit.run_chkrootkit(make_ctx(chk_remote("??5??????   /usr/bin/date\n"), tools_ok={"chkrootkit"}))
        crit = sev(res, "critical")
        self.assertEqual(len(crit), 1)
        self.assertIn("'date'", crit[0].title)

    def test_bpfdoor_on_intact_chronyd(self):
        res = rootkit.run_chkrootkit(make_ctx(chk_remote(), tools_ok={"chkrootkit"}))
        bpf = [f for f in res.findings if "BPFDoor" in f.title]
        self.assertEqual([f.severity for f in bpf], ["low"])
        self.assertIn("chronyd", bpf[0].detail)

    def test_networkmanager_wpa_sniffer(self):
        res = rootkit.run_chkrootkit(make_ctx(chk_remote(), tools_ok={"chkrootkit"}))
        self.assertTrue(any("sniffer" in f.title for f in sev(res, "info")))


class RkhunterLaptopTest(unittest.TestCase):
    def setUp(self):
        rem = FakeRemote(default_rc=1, rules=[
            ("dpkg -S /usr/sbin/sshd", "openssh-server: /usr/sbin/sshd", 0),
            ("dpkg -S /usr/bin/ssh", "openssh-client: /usr/bin/ssh", 0),
            ("dpkg -V", "", 0)])
        ctx = make_ctx(rem)
        ctx.cache["tool_installed"] = {"clamav", "clamav-base", "chkrootkit"}
        self.out = rootkit.classify_rkhunter(ctx, rootkit.parse_rkhunter(fixture("rkhunter_laptop.txt")))

    def test_one_finding_per_block(self):  # it was 30 lines for ~13 warnings
        self.assertEqual(len(self.out), len([l for l in fixture("rkhunter_laptop.txt").splitlines()
                                             if l.startswith("Warning:")]))

    def test_updated_ssh_is_low(self):
        ssh = [o for o in self.out if "/usr/sbin/sshd" in o[1] or "/usr/bin/ssh " in o[1]]
        self.assertEqual([o[0] for o in ssh], ["low", "low"])
        self.assertIn("propupd", ssh[0][2])

    def test_clamav_user_created_by_the_tool(self):
        cl = [o for o in self.out if "'clamav'" in o[1]]
        self.assertEqual([o[0] for o in cl], ["info", "info"])

    def test_not_installed_is_info_and_never_installed(self):
        res = rootkit.run_rkhunter(make_ctx(FakeRemote()))
        self.assertEqual((res.status, [f.severity for f in res.findings]), ("skipped", ["info"]))
        # Design decision: rkhunter is only detected, never installed (a fresh baseline would be worthless),
        # while chkrootkit is installed with binutils as a support package.
        from zerostressriskassess import toolmgr
        self.assertNotIn("rkhunter", toolmgr.TOOLS)
        self.assertEqual(toolmgr.DETECT_ONLY, {"rkhunter": "rkhunter"})
        self.assertEqual(toolmgr.TOOLS["chkrootkit"]["apt"], ["chkrootkit", "binutils"])
        self.assertIn("binutils", toolmgr.HELPER_PKGS)


class BuiltinCommandTest(unittest.TestCase):
    def test_echo_resolved_as_a_file(self):  # 0.4.2 on the laptop: 'echo' -> "not verifiable", critical
        import subprocess
        out = subprocess.run(["bash", "-c", 'for c in echo ls; do echo "$c|$(type -P $c 2>/dev/null)"; done'],
                             capture_output=True, text=True).stdout
        echo = [l for l in out.splitlines() if l.startswith("echo|")][0]
        self.assertTrue(echo.split("|")[1].startswith("/"), echo)


class ListenersLaptopTest(unittest.TestCase):
    SS = "\n".join(f'udp   UNCONN 0      0      {a}:{p}      0.0.0.0:*    users:(("python3",pid=12630,fd=10))'
                   for a, p in (("0.0.0.0", 55476), ("0.0.0.0", 41380), ("172.16.96.1", 3702), ("*", 40042)))
    PID = "PID|12630|user|/usr/bin/python3.14|python3 /usr/bin/wsdd --no-host --discovery --listen /run/user/1000/gvfsd/wsdd\n"

    def test_packaged_wsdd_script_one_low_line(self):  # it was 7 "high"
        rem = FakeRemote(default_rc=1, rules=[("ss -tulpn", self.SS, 0), ("for p in", self.PID, 0),
                                              ("dpkg -S /usr/bin/wsdd", "wsdd: /usr/bin/wsdd", 0)])
        res = listeners.run(make_ctx(rem))
        f, = [f for f in res.findings if "wsdd" in f.title]
        self.assertEqual(f.severity, "low")
        self.assertIn("40042/udp", f.title)

    def test_script_outside_packages_stays_high(self):
        rem = FakeRemote(default_rc=1, rules=[("ss -tulpn", self.SS, 0), ("for p in", self.PID, 0)])
        res = listeners.run(make_ctx(rem))
        self.assertEqual(len(sev(res, "high")), 1)

    def test_script_of(self):
        self.assertEqual(listeners.script_of("python3 /usr/bin/wsdd --x"), "/usr/bin/wsdd")
        self.assertIsNone(listeners.script_of("/usr/bin/python3 -m http.server 31337"))
        self.assertIsNone(listeners.script_of("perl -e 'print 1'"))


class LaptopPermissionsTest(unittest.TestCase):
    def setUp(self):
        H = "/home/user"
        rem = FakeRemote(default_rc=1, rules=[
            ("-type d -perm -0002", f"{H}/vmware/weak-target/weak-target.vmdk.lck\n", 0),
            ("find -H /srv", f"/var/www/site.example/wp/wp-config.php\n{H}/.cache/uv/.lock\n"
                             f"{H}/.cache/huggingface/hub/blobs/0c/abc.refs\n", 0),
            ("-perm -4000", f"4755|root|{H}/.app-electron/app/linux-unpacked/chrome-sandbox\n"
                            "4711|root|/usr/lib/vmware/bin/vmware-vmx\n4711|root|/usr/sbin/vmware-authd\n", 0),
        ])
        self.res = permissions.run(make_ctx(rem))

    def find(self, text):
        return [f for f in self.res.findings if text in f.title or text in f.detail]

    def test_wp_config_high(self):
        self.assertEqual([f.severity for f in self.find("wp-config.php")], ["high"])

    def test_lock_info_only(self):
        f, = self.find("lock")
        self.assertEqual(f.severity, "info")

    def test_chrome_sandbox_high_not_critical(self):
        self.assertEqual([f.severity for f in self.find("chrome-sandbox")], ["high"])

    def test_suid_outside_packages_grouped(self):
        f, = self.find("vmware-vmx")
        self.assertIn("2 SUID/SGID files", f.title)

    def test_home_grouped_low(self):
        f, = self.find("home directories")
        self.assertEqual(f.severity, "low")


class LaptopIntegrityTest(unittest.TestCase):
    def test_updated_programs_to_restart(self):  # ssh/ssh-agent "(deleted)" after an OpenSSH update
        rem = FakeRemote(default_rc=1, rules=[
            ("readlink \"$p/exe\"", "11626|/usr/bin/ssh-agent (deleted)\n2784|/usr/bin/ssh-agent (deleted)\n"
                                    "23867|/usr/bin/ssh (deleted)\n", 0),
            ("dpkg -S /usr/bin/ssh", "openssh-client: x", 0)])
        res = integrity.run(make_ctx(rem))
        f, = [f for f in res.findings if "updated programs" in f.title]
        self.assertEqual(f.severity, "low")
        self.assertIn("11626", f.detail)
        self.assertFalse([f for f in res.findings if f.severity == "medium" and "deleted" in f.title])


class ClamavLaptopTest(unittest.TestCase):
    def run_clam(self, rc, quick=False):
        rem = FakeRemote(default_rc=0, rules=[("MemAvailable", "8000", 0), ("clamscan", "", rc)])
        ctx = make_ctx(rem, tools_ok={"clamav"})
        ctx.opts.clamav_quick = quick
        return clamav_scan.run(ctx), rem

    def test_timeout_does_not_look_clean(self):  # on the laptop: "ok, 0 findings" after 3645 s
        res, rem = self.run_clam(124)
        self.assertEqual(res.status, "error")
        self.assertTrue(any("PARTIAL" in f.title for f in res.findings))

    def test_timeout_runs_on_the_target(self):
        res, rem = self.run_clam(0)
        cmd = [c for c in rem.calls if "clamscan" in c][0]
        self.assertTrue(cmd.startswith("timeout -k 30 "))
        self.assertIn("--exclude-dir='/\\.cache/'", cmd)

    def test_quick_without_home(self):
        res, rem = self.run_clam(0, quick=True)
        cmd = [c for c in rem.calls if "clamscan" in c][0]
        self.assertNotIn("/home", cmd)
        self.assertEqual(res.data["mode"], "quick")


if __name__ == "__main__":
    unittest.main()
