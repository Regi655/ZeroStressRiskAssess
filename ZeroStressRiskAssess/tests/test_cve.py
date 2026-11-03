"""Package CVEs with Grype, checked against the updates the target can actually install.

REAL fixtures:
  - vercmp_real.json: results of rpm 4.18.2 (rpm.ver) and dpkg 1.22.6 (--compare-versions);
  - inventory_ubuntu_sandbox.txt: output of the INVENTORY script on the sandbox Ubuntu 24.04
    (150 of 1128 packages plus openssl/libarchive, and every available update);
  - rocky_dnf_check_update.txt: `dnf -q check-update` on the Rocky lab (2026-10-14);
  - rocky_grype_only_fixed.txt: the 48 CVEs "with a fix" seen only by Grype when compared with Trivy on
    the same lab (CVE, package, installed version, fixed version).
The Grype matches are rebuilt from those lines in Grype's JSON format (vulnerability.fix.versions,
artifact.name/version): the values are real, the structure is the documented one.
"""
import json
import subprocess
import unittest
from unittest import mock

from zerostressriskassess import cve
from zerostressriskassess.scanners import cve_scan
from zerostressriskassess.vercmp import deb_cmp, rpm_cmp
from tests.fakes import FakeRemote, fixture, make_ctx


class VercmpTest(unittest.TestCase):
    def test_same_as_real_rpm_and_dpkg(self):
        d = json.loads(fixture("vercmp_real.json"))
        self.assertEqual([c for c in d["rpm"] if rpm_cmp(c[0], c[1]) != c[2]], [])
        self.assertEqual([c for c in d["deb"] if deb_cmp(c[0], c[1]) != c[2]], [])
        self.assertGreater(len(d["rpm"]) + len(d["deb"]), 500)


def rocky_avail():
    avail = {}
    for line in fixture("rocky_dnf_check_update.txt").splitlines():
        p = line.split()
        if len(p) == 3 and "." in p[0]:       # same filter as the awk in INVENTORY
            avail[p[0].rsplit(".", 1)[0]] = p[1]
    return avail


def rocky_grype():
    matches = []
    for line in fixture("rocky_grype_only_fixed.txt").splitlines():
        cve_id, pkg, inst, _, fix = line.split()
        matches.append({"vulnerability": {"id": cve_id, "severity": "High",
                                          "fix": {"state": "fixed", "versions": [fix]}},
                        "artifact": {"name": pkg, "version": inst}})
    return {"matches": matches}


class RockyTest(unittest.TestCase):
    """Grype's 48 CVEs "with a fix", split using the versions Rocky actually offered."""

    def setUp(self):
        self.c = cve.classify(cve.parse_grype(rocky_grype()), rocky_avail(), "rpm")

    def test_33_fixable_15_waiting(self):
        self.assertEqual((len(self.c["now"]), len(self.c["waiting"])), (33, 15))

    def test_which_packages(self):
        self.assertEqual(sorted({v["pkg"] for v in self.c["now"]}),
                         ["curl-minimal", "libcurl-minimal", "openssl", "openssl-fips-provider", "openssl-libs"])
        self.assertEqual(sorted({v["pkg"] for v in self.c["waiting"]}), ["libcap", "pcre2", "pcre2-syntax"])

    def test_report(self):
        got = cve.evaluate(self.c)
        fips = [t for s, t, d in got if t.startswith("openssl-fips-provider")]
        self.assertEqual(fips, ["openssl-fips-provider: 27 CVEs fixed by the update already available "
                                "(1:3.5.8-2.el9_8)"])
        self.assertIn(("info", "15 CVEs fixed upstream but without an update available here yet"),
                      [(s, t) for s, t, d in got])


class InventoryTest(unittest.TestCase):
    def setUp(self):
        self.inv = cve.parse_inventory(fixture("inventory_ubuntu_sandbox.txt"))

    def test_real_ubuntu(self):
        self.assertEqual((self.inv["os"], self.inv["version"], self.inv["kind"]), ("ubuntu", "24.04", "deb"))
        self.assertEqual(len(self.inv["avail"]), 48)
        self.assertEqual(self.inv["avail"]["libarchive13t64"], "3.7.2-2ubuntu0.9")

    def test_purl_with_source_package(self):
        bom = cve.cyclonedx(self.inv)
        ssl = [c["purl"] for c in bom["components"] if c.get("name") == "libssl3t64"]
        self.assertEqual(ssl, ["pkg:deb/ubuntu/libssl3t64@3.0.13-0ubuntu3.16?arch=amd64&upstream=openssl"
                               "&distro=ubuntu-24.04"])
        self.assertEqual(bom["metadata"]["component"], {"type": "operating-system", "name": "ubuntu",
                                                        "version": "24.04"})

    def test_real_script_on_this_system(self):
        p = subprocess.run(["bash", "-c", cve.INVENTORY], capture_output=True, text=True)
        inv = cve.parse_inventory(p.stdout)
        if not inv["pkgs"]:
            self.skipTest("neither dpkg nor rpm on this machine")
        self.assertTrue(inv["os"] and inv["kind"] in ("deb", "rpm"))


class GrypeTest(unittest.TestCase):
    def test_rhsa_advisory_mapped_to_cves_and_kev(self):
        data = {"matches": [
            {"vulnerability": {"id": "RHSA-2026:1", "severity": "Medium", "fix": {"state": "fixed", "versions": ["2"]},
                               "knownExploited": [{"cve": "CVE-2026-1"}]},
             "relatedVulnerabilities": [{"id": "CVE-2026-1"}, {"id": "CVE-2026-2"}],
             "artifact": {"name": "x", "version": "1"}},
            {"vulnerability": {"id": "CVE-2026-3", "severity": "Negligible", "fix": {"state": "not-fixed"}},
             "artifact": {"name": "y", "version": "1"}}]}
        v = cve.parse_grype(data)
        self.assertEqual([(x["cve"], x["severity"], x["kev"]) for x in v],
                         [("CVE-2026-1", "medium", True), ("CVE-2026-2", "medium", True), ("CVE-2026-3", "low", False)])
        c = cve.classify(v, {"x": "2"}, "rpm")
        got = cve.evaluate(c)
        self.assertEqual(got[0][0], "critical")          # actively exploited: at the top, whatever the severity
        self.assertIn("1 CVEs without a fix", got[-1][1])

    def test_check_with_fake_grype(self):
        rem = FakeRemote(rules=[("OS|", "OS|ubuntu|24.04\nKIND|deb\n"
                                        "PKG|libssl3t64|3.0.13-0ubuntu3.16|amd64|openssl|3.0.13-0ubuntu3.16\n"
                                        "AVAIL|libssl3t64|3.0.13-0ubuntu3.17\n", 0)])
        out = {"matches": [{"vulnerability": {"id": "CVE-2026-2673", "severity": "High",
                                              "fix": {"state": "fixed", "versions": ["3.0.13-0ubuntu3.17"]}},
                            "artifact": {"name": "libssl3t64", "version": "3.0.13-0ubuntu3.16"}}],
               "descriptor": {"db": {"built": "2026-10-14"}}}
        done = subprocess.CompletedProcess([], 0, json.dumps(out), "")
        only_grype = lambda name: "/usr/bin/grype" if name == "grype" else None  # noqa: E731
        with mock.patch.object(cve_scan.shutil, "which", side_effect=only_grype), \
                mock.patch.object(cve.shutil, "which", side_effect=only_grype), \
                mock.patch.object(cve.subprocess, "run", return_value=done) as run:
            res = cve_scan.run(make_ctx(rem))
        args = run.call_args[0][0]
        self.assertEqual(args[2:4], ["--distro", "ubuntu:24.04"])
        self.assertEqual([(f.severity, f.title) for f in res.findings],
                         [("high", "libssl3t64: 1 CVEs fixed by the update already available (3.0.13-0ubuntu3.17)")])
        self.assertEqual(res.data["now"], 1)

    def test_without_grype_or_trivy(self):
        with mock.patch.object(cve_scan.shutil, "which", return_value=None):
            self.assertEqual(cve_scan.run(make_ctx(FakeRemote())).status, "skipped")


# ---------------------------------------------------------------------------------------------- Trivy
# SYNTHETIC Trivy output, in the JSON format documented by Trivy ("Results" -> "Vulnerabilities"): it could not be
# recorded in the development sandbox, where Trivy's database registry is not reachable. Values are plausible
# Ubuntu 24.04 data, not a real scan.
TRIVY_OUT = {"SchemaVersion": 2, "ArtifactType": "cyclonedx",
             "Metadata": {"OS": {"Family": "ubuntu", "Name": "24.04"}},
             "Results": [{"Target": "inventory (ubuntu 24.04)", "Class": "os-pkgs", "Type": "ubuntu",
                          "Vulnerabilities": [
                              {"VulnerabilityID": "CVE-2026-0001", "PkgName": "libssl3t64",
                               "InstalledVersion": "3.0.13-0ubuntu3.16",
                               "FixedVersion": "3.0.13-0ubuntu3.17, 3.0.13-0ubuntu3.18", "Status": "fixed",
                               "Severity": "HIGH",
                               "CVSS": {"redhat": {"V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"},
                                        "nvd": {"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}},
                              {"VulnerabilityID": "CVE-2026-0001", "PkgName": "libssl3t64",
                               "InstalledVersion": "3.0.13-0ubuntu3.16", "FixedVersion": "3.0.13-0ubuntu3.17",
                               "Status": "fixed", "Severity": "HIGH"},
                              {"VulnerabilityID": "CVE-2026-0002", "PkgName": "bash", "InstalledVersion": "5.2.21-2ubuntu4",
                               "Status": "affected", "Severity": "UNKNOWN"},
                              {"VulnerabilityID": "CVE-2026-0003", "PkgName": "openssl",
                               "InstalledVersion": "3.0.13-0ubuntu3.16", "FixedVersion": "3.0.13-0ubuntu3.17",
                               "Status": "fixed", "Severity": "MEDIUM"}]}]}
TRIVY_VERSION = {"Version": "0.69.3", "VulnerabilityDB": {"Version": 2, "UpdatedAt": "2026-10-15T00:00:00Z"}}
UBUNTU_INV = ("OS|ubuntu|24.04\nKIND|deb\n"
              "PKG|libssl3t64|3.0.13-0ubuntu3.16|amd64|openssl|3.0.13-0ubuntu3.16\n"
              "PKG|openssl|3.0.13-0ubuntu3.16|amd64|openssl|3.0.13-0ubuntu3.16\n"
              "PKG|bash|5.2.21-2ubuntu4|amd64|bash|5.2.21-2ubuntu4\n"
              "AVAIL|libssl3t64|3.0.13-0ubuntu3.17\nAVAIL|openssl|3.0.13-0ubuntu3.17\n")


def fake_tools(present, version=TRIVY_VERSION, grype_out=None):
    """Patches for: which programs exist, and what `trivy version`, `trivy sbom` and `grype` print."""
    def which(name):
        return f"/usr/bin/{name}" if name in present else None

    def run(args, **kw):
        if args[0].endswith("trivy") and args[1] == "version":
            return subprocess.CompletedProcess(args, 0, json.dumps(version), "")
        if args[0].endswith("trivy"):
            return subprocess.CompletedProcess(args, 0, json.dumps(TRIVY_OUT), "")
        return subprocess.CompletedProcess(args, 0, json.dumps(grype_out or {"matches": []}), "")
    return which, run


class TrivyTest(unittest.TestCase):
    def test_parse(self):
        v = cve.parse_trivy(TRIVY_OUT)
        self.assertEqual([(x["cve"], x["pkg"], x["severity"], x["state"]) for x in v],
                         [("CVE-2026-0001", "libssl3t64", "high", "fixed"),       # the duplicate counts once
                          ("CVE-2026-0002", "bash", "low", "affected"),           # UNKNOWN -> low, Status kept
                          ("CVE-2026-0003", "openssl", "medium", "fixed")])
        self.assertEqual(v[0]["fix"], ["3.0.13-0ubuntu3.17", "3.0.13-0ubuntu3.18"])
        self.assertEqual(v[0]["cvss"], ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"])   # NVD vector preferred
        self.assertFalse(any(x["kev"] for x in v))

    def test_trivy_sbom_uses_source_packages(self):
        inv = cve.parse_inventory(fixture("inventory_ubuntu_sandbox.txt"))
        bom = cve.cyclonedx_trivy(inv)
        ssl = next(c for c in bom["components"] if c.get("name") == "libssl3t64")
        props = {p["name"].split(":")[-1]: p["value"] for p in ssl["properties"]}
        self.assertEqual(props, {"PkgType": "ubuntu", "SrcName": "openssl", "SrcVersion": "3.0.13",
                                 "SrcRelease": "0ubuntu3.16"})
        os_dep = next(d for d in bom["dependencies"] if d["ref"] == "os")
        self.assertEqual(len(os_dep["dependsOn"]), len(inv["pkgs"]))
        # The Grype SBOM is unchanged: no dependency graph and no Trivy properties.
        grype_bom = cve.cyclonedx(inv)
        self.assertNotIn("dependencies", grype_bom)
        self.assertFalse([c for c in grype_bom["components"] if "properties" in c])

    def test_versions_split(self):
        self.assertEqual(cve._split_deb("1:2.3-4ubuntu1"), ("1", "2.3", "4ubuntu1"))
        self.assertEqual(cve._split_deb("2.3"), ("", "2.3", ""))
        inv = cve.parse_inventory("OS|ubuntu|24.04\nKIND|deb\nPKG|libfoo1|1:2.3-4ubuntu1|amd64|foo|1:2.3-4ubuntu1\n")
        props = {p["name"].split(":")[-1]: p["value"] for p in cve.cyclonedx_trivy(inv)["components"][1]["properties"]}
        self.assertEqual((props["SrcName"], props["SrcVersion"], props["SrcRelease"], props["SrcEpoch"]),
                         ("foo", "2.3", "4ubuntu1", "1"))

    def test_merge(self):
        g = [{"cve": "CVE-1", "pkg": "a", "installed": "1", "severity": "medium", "state": "not-fixed", "fix": [],
              "kev": True, "cvss": []}]
        t = [{"cve": "CVE-1", "pkg": "a", "installed": "1", "severity": "high", "state": "fixed", "fix": ["2"],
              "kev": False, "cvss": ["CVSS:3.1/AV:N"]},
             {"cve": "CVE-1", "pkg": "b", "installed": "1", "severity": "low", "state": "fixed", "fix": ["2"],
              "kev": False, "cvss": []}]
        m = {(v["cve"], v["pkg"]): v for v in cve.merge(g, t)}
        a, b = m[("CVE-1", "a")], m[("CVE-1", "b")]
        self.assertEqual((a["sources"], a["severity"], a["state"], a["fix"], a["cvss"]),
                         (["grype", "trivy"], "high", "fixed", ["2"], ["CVSS:3.1/AV:N"]))
        self.assertTrue(b["kev"])            # KEV belongs to the CVE: also marked on the package only Trivy found
        self.assertEqual(b["sources"], ["trivy"])

    def test_check_with_trivy_only(self):
        which, run = fake_tools({"trivy"})
        rem = FakeRemote(rules=[("OS|", UBUNTU_INV, 0)])
        with mock.patch.object(cve_scan.shutil, "which", side_effect=which), \
                mock.patch.object(cve.shutil, "which", side_effect=which), \
                mock.patch.object(cve.subprocess, "run", side_effect=run) as sp:
            res = cve_scan.run(make_ctx(rem))
        self.assertEqual(sp.call_args_list[1][0][0][1:6], ["sbom", "--scanners", "vuln", "--format", "json"])
        self.assertEqual(res.data["sources"], ["Trivy v0.69.3, database of 2026-10-15"])
        self.assertEqual((res.data["now"], res.data["unfixed"]), (2, 1))
        self.assertIn("KEV data comes from Grype only", cve.sources_text(res.data))

    def test_compromised_trivy_is_never_run(self):
        which, run = fake_tools({"trivy"}, version={"Version": "0.69.4"})
        rem = FakeRemote(rules=[("OS|", UBUNTU_INV, 0)])
        with mock.patch.object(cve_scan.shutil, "which", side_effect=which), \
                mock.patch.object(cve.shutil, "which", side_effect=which), \
                mock.patch.object(cve.subprocess, "run", side_effect=run) as sp:
            res = cve_scan.run(make_ctx(rem))
        self.assertEqual(sp.call_count, 1)                       # only `trivy version`, never `trivy sbom`
        self.assertEqual(res.status, "error")
        self.assertIn("CVE-2026-33634", res.findings[0].detail)

    def test_check_with_both(self):
        grype_out = {"matches": [{"vulnerability": {"id": "CVE-2026-0001", "severity": "Medium",
                                                    "fix": {"state": "fixed", "versions": ["3.0.13-0ubuntu3.17"]},
                                                    "knownExploited": [{"cve": "CVE-2026-0001"}]},
                                  "artifact": {"name": "libssl3t64", "version": "3.0.13-0ubuntu3.16"}},
                                 {"vulnerability": {"id": "CVE-2026-0009", "severity": "Low", "fix": {"state": "not-fixed"}},
                                  "artifact": {"name": "bash", "version": "5.2.21-2ubuntu4"}}],
                     "descriptor": {"version": "0.92.2", "db": {"status": {"built": "2026-10-15T00:00:00Z"}}}}
        which, run = fake_tools({"grype", "trivy"}, grype_out=grype_out)
        rem = FakeRemote(rules=[("OS|", UBUNTU_INV, 0)])
        with mock.patch.object(cve_scan.shutil, "which", side_effect=which), \
                mock.patch.object(cve.shutil, "which", side_effect=which), \
                mock.patch.object(cve.subprocess, "run", side_effect=run):
            res = cve_scan.run(make_ctx(rem))
        self.assertEqual(res.data["overlap"], {"both": 1, "only_grype": 1, "only_trivy": 2})
        self.assertEqual(len(res.data["sources"]), 2)
        ssl = next(v for v in res.data["now_detail"] if v["pkg"] == "libssl3t64")
        self.assertEqual((ssl["severity"], ssl["kev"], ssl["sources"]), ("high", True, ["grype", "trivy"]))
        self.assertEqual(res.findings[0].severity, "critical")    # KEV from Grype puts it on top


if __name__ == "__main__":
    unittest.main()
