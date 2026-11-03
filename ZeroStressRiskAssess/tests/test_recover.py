"""--recover and the final cleanup remove ONLY the packages zsra installed, not what appeared meanwhile.

Case seen on the laptop: run interrupted, then a kernel update and the owner's packages (courier, expect) were
installed before --recover; the whole difference was proposed for removal (kernel included), the simulation
saw linux-generic in it and refused, and the target could not be cleaned up at all.
"""
import json
import re
import unittest

from tests.fakes import FakeRemote
from zerostressriskassess.osinfo import OSInfo
from zerostressriskassess.toolmgr import recover_interrupted

UBUNTU = OSInfo("ubuntu", "26.04", "Ubuntu 26.04.1 LTS", "apt", "7.0.0-38-generic", "x86_64")
BEFORE = ["bash", "libc6", "linux-generic", "linux-image-7.0.0-38-generic", "chkrootkit"]
OURS = ["clamav", "clamav-base", "clamav-freshclam", "libclamav12", "libmspack0t64", "smartmontools"]
FOREIGN = ["courier-mta", "expect", "tcl-expect", "linux-image-7.0.0-42-generic", "linux-modules-7.0.0-42-generic"]
# apt-cache depends --recurse --installed clamav chkrootkit binutils smartmontools: names at column 0
DEPENDS = """clamav
  Depends: libclamav12
  Depends: clamav-freshclam
  Depends: libc6
libclamav12
  Depends: libmspack0t64
clamav-freshclam
  Depends: clamav-base
clamav-base
libmspack0t64
<debconf-2.0>
libc6
chkrootkit
  Depends: libc6
smartmontools
  Depends: libc6
"""


def dpkg(pkgs):
    return "".join(f"installed {p}\n" for p in pkgs)


def purge_sim(cmd_pkgs):
    return "".join(f"Purg {p} [1.0]\n" for p in cmd_pkgs)


def remote(manifest, depends=DEPENDS, depends_rc=0):
    sim = purge_sim(OURS)
    return FakeRemote(rules=[
        ("cat /var/lib/zerostressriskassess/manifest.json", json.dumps(manifest)),
        ("dpkg-query -W", dpkg(BEFORE + OURS + FOREIGN)),
        ("apt-cache depends", depends, depends_rc),
        (re.compile(r"apt-get -s purge"), sim),
    ])


class RecoverTest(unittest.TestCase):
    def _recover(self, rem):
        logs = []
        ok = recover_interrupted(rem, UBUNTU, confirm=lambda m: True, log=logs.append)
        purges = [c for c in rem.calls if "purge -y" in c and "-s purge" not in c]
        return ok, logs, purges

    def test_old_manifest_removes_only_tool_packages(self):
        ok, logs, purges = self._recover(remote({"version": 1, "before": BEFORE}))
        self.assertTrue(ok, logs)
        self.assertEqual(len(purges), 1)
        for p in OURS:
            self.assertIn(p, purges[0])
        for p in FOREIGN:
            self.assertNotIn(p, purges[0])
        self.assertTrue(any("NOT by zsra" in l and "linux-image-7.0.0-42-generic" in l for l in logs), logs)

    def test_planned_list_from_new_manifest_is_used(self):
        rem = remote({"version": 1, "before": BEFORE, "planned": ["clamav", "smartmontools"]})
        ok, _, purges = self._recover(rem)
        self.assertTrue(ok)
        dep_cmd = next(c for c in rem.calls if "apt-cache depends" in c)
        self.assertIn("clamav", dep_cmd)
        self.assertNotIn("chkrootkit", dep_cmd)
        self.assertNotIn("courier-mta", purges[0])

    def test_unknown_dependencies_fall_back_to_simulation_guard(self):
        # apt-cache fails: the whole difference is proposed, the simulation must still block it
        rem = remote({"version": 1, "before": BEFORE}, depends="", depends_rc=1)
        rem.rules.insert(0, ("apt-get -s purge", purge_sim(OURS + FOREIGN + ["linux-generic"])))
        ok, logs, purges = self._recover(rem)
        self.assertFalse(ok)
        self.assertEqual(purges, [])
        self.assertTrue(any("Cancelled" in l for l in logs), logs)


if __name__ == "__main__":
    unittest.main()
