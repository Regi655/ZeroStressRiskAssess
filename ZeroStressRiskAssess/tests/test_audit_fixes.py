"""Security audit of 1.6.1 (fixed in 1.6.2): one test per finding that is not covered elsewhere.

#1 dns.py injection: tests/test_dns.py (UntrustedPathsTest, the impostor test); #3 pinned Lynis:
tests/test_lynis_portable.py. Here: #2 host key, #4 cleanup, #5 container IDs, #6 sudo -k, #7 quoting, #8 host
validation, #10 PID reuse.
"""
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import paramiko

from tests.fakes import FakeRemote, make_ctx
from zerostressriskassess import targets, toolmgr
from zerostressriskassess.pkgmgr import Apt, Dnf
from zerostressriskassess.scanners import containers
from zerostressriskassess.ssh_client import AcceptNewAndSave, Remote
from zerostressriskassess.validate import valid_host
from zerostressriskassess.web import jobs


class Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)


class HostKeyTest(Tmp):
    """#2: --accept-new-hostkey must SAVE the key, so the next run verifies it."""

    def test_accepted_key_is_saved_hashed_and_then_verified(self):
        kh = self.tmp / "ssh" / "known_hosts"
        key = paramiko.RSAKey.generate(1024)
        client = paramiko.SSHClient()
        AcceptNewAndSave(str(kh)).missing_host_key(client, "[10.0.0.5]:2222", key)
        self.assertEqual(stat.S_IMODE(kh.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(kh.parent.stat().st_mode), 0o700)
        text = kh.read_text()
        self.assertTrue(text.startswith("|1|"))            # hashed name, as ssh with HashKnownHosts
        self.assertNotIn("10.0.0.5", text)
        later = paramiko.HostKeys(str(kh))                 # what the next connection loads
        self.assertEqual(later.lookup("[10.0.0.5]:2222")[key.get_name()], key)
        self.assertIsNone(later.lookup("10.0.0.6"))

    def test_the_flag_cannot_be_saved_in_a_target(self):
        with mock.patch.dict(os.environ, {"ZSRA_TARGETS": str(self.tmp / "t.json")}):
            with self.assertRaises(targets.TargetError):
                targets.save("x", ["10.0.0.5", "-u", "a", "--accept-new-hostkey"])


class Sequence(FakeRemote):
    """FakeRemote whose answer to a pattern can change between calls (before / after the installation)."""

    def __init__(self, seq, **kw):
        super().__init__(**kw)
        self.seq = {k: list(v) for k, v in seq.items()}

    def run(self, cmd, sudo=False, timeout=600, trusted_path=True, **kw):
        for pat, outs in self.seq.items():
            if pat in cmd:
                self.calls.append(cmd)
                out = outs.pop(0) if len(outs) > 1 else outs[0]
                return type("R", (), {"out": out, "rc": 0})()
        return super().run(cmd, sudo, timeout, trusted_path, **kw)


class CleanupTest(unittest.TestCase):
    """#4: the target goes back to how it was: accounts created by OUR packages removed, the owner's cache kept."""

    def test_only_new_accounts_of_the_tools_are_removed(self):
        before = "u:root\nu:danielb\ng:root\ng:danielb\ng:docker"
        after = before + "\nu:clamav\ng:clamav\nu:mallory\ng:newgrp"
        rem = Sequence({"getent passwd": [before, after]})
        b = toolmgr.accounts(rem)
        done = toolmgr.remove_new_accounts(rem, b)
        self.assertEqual(done, ["user clamav", "group clamav"])
        self.assertIn("userdel clamav", rem.calls)
        self.assertFalse([c for c in rem.calls if "mallory" in c or "newgrp" in c or "danielb" in c])

    def test_an_account_that_existed_before_is_kept(self):
        same = "u:root\nu:clamav\ng:clamav"
        rem = Sequence({"getent passwd": [same, same]})
        self.assertEqual(toolmgr.remove_new_accounts(rem, toolmgr.accounts(rem)), [])
        self.assertEqual(toolmgr.remove_new_accounts(rem, None), [])     # old manifest: nothing touched

    def test_apt_deletes_only_the_package_files_of_the_run(self):
        rem = Sequence({"ls -1 /var/cache/apt/archives": ["owner_1.0_amd64.deb\nlock\npartial",
                                                          "owner_1.0_amd64.deb\nclamav_1.5_amd64.deb\nlock\nx;y.deb"]})
        apt = Apt(rem)
        before = apt.cache_snapshot()
        apt.remove(["clamav"], cache_before=before)
        cleaned = [c for c in rem.calls if c.startswith("rm -f -- ")]
        self.assertEqual(cleaned, ["rm -f -- /var/cache/apt/archives/clamav_1.5_amd64.deb"])
        self.assertFalse([c for c in rem.calls if "apt-get clean" in c])

    def test_without_the_list_nothing_is_deleted(self):
        rem = FakeRemote()
        Apt(rem).remove(["clamav"], cache_before=None)
        Dnf(rem).remove(["clamav"])
        self.assertFalse([c for c in rem.calls if "rm -f --" in c or " clean" in c])   # "apt-get clean", "dnf clean all"


class SmallFixesTest(Tmp):
    def test_5_container_ids_are_allow_listed(self):
        rem = FakeRemote(rules=[("command -v docker", "/usr/bin/docker", 0),
                                ("docker ps -q", "a1b2c3d4e5f6\n$(touch${IFS}/x)\n", 0)])
        containers.run(make_ctx(rem))
        inspect = [c for c in rem.calls if "docker inspect" in c]
        self.assertEqual(len(inspect), 1)
        self.assertTrue(inspect[0].endswith("a1b2c3d4e5f6"))

    def test_6_sudo_always_reads_the_password(self):
        self.assertTrue(Remote._wrap("id", True, True).startswith("sudo -k -S -p '' "))
        self.assertTrue(Remote._wrap("id", True, False).startswith("sudo -n "))

    def test_7_package_names_are_quoted(self):
        rem = FakeRemote()
        Apt(rem).status("x;id")
        self.assertTrue(all("'x;id'" in c for c in rem.calls))

    def test_8_host_validation(self):
        for ok in ("10.0.0.1", "server.lan", "::1", "fe80::1%eth0", "fe80::1%enp0s3"):
            self.assertTrue(valid_host(ok), ok)
        for bad in ("fe80::1%$(id)", "fe80::1%a b", "10.0.0.1%eth0", "host%x", "-oN/x", "a;b"):
            self.assertFalse(valid_host(bad), bad)

    def test_10_a_reused_pid_is_not_our_run(self):
        pid = os.getpid()                                   # a live process that is NOT the run
        mine = jobs.Job("j", self.tmp, {"pid": pid, "starttime": jobs._starttime(pid)})
        other = jobs.Job("j", self.tmp, {"pid": pid, "starttime": (jobs._starttime(pid) or 0) + 1})
        with mock.patch.object(jobs, "_alive", return_value=True):
            self.assertTrue(mine.running)
            self.assertFalse(other.running)
            with mock.patch.object(jobs.os, "killpg") as kill:
                self.assertFalse(other.stop())
            kill.assert_not_called()


if __name__ == "__main__":
    unittest.main()
