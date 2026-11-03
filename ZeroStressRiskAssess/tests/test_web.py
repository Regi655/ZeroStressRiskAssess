"""Web interface: command lines built from the form, detached runs, secrets never on argv, access token, pages."""
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from zerostressriskassess import cli
from zerostressriskassess.web import build_command, jobs

FIXTURE_REPORTS = Path(__file__).resolve().parent.parent / "reports"


def wait(job, seconds=30):
    end = time.time() + seconds
    while job.running and time.time() < end:
        time.sleep(0.1)
    return job


class ArgvTest(unittest.TestCase):
    def test_scan(self):
        argv = jobs.build_argv("scan", " 10.0.0.5 ", "admin", 2222, "~/.ssh/k",
                               {"clamav": "quick", "skip": ["lynis"], "nse": "tls", "accept_new_hostkey": True,
                                "nmap_ports": "1-1024", "dns_zones": "a.lab b.lab", "scan_timeout": 90})
        self.assertEqual(argv, ["10.0.0.5", "-u", "admin", "-i", "~/.ssh/k", "-p", "2222", "--accept-new-hostkey",
                                "--nmap-ports", "1-1024", "--nse-tls", "--dns-zone", "a.lab", "b.lab",
                                "--clamav-quick", "--skip", "lynis", "--scan-timeout", "90"])
        cli.build_parser().parse_args(argv)   # accepted by the real parser

    def test_recon_has_no_login_options(self):
        argv = jobs.build_argv("recon", "ns1.lab", "admin", 22, "~/.ssh/k", {"clamav": "full", "no_install": True})
        self.assertEqual(argv, ["ns1.lab", "--recon-only"])

    def test_recover(self):
        self.assertEqual(jobs.build_argv("recover", "h", "u", 22, "", {"skip": ["nmap"]}), ["h", "-u", "u", "--recover"])

    def test_server_only_on_loopback_and_without_telemetry(self):
        cmd = build_command(8501, "/tmp/x")
        self.assertIn("--server.address=127.0.0.1", cmd)
        self.assertIn("--browser.gatherUsageStats=false", cmd)


class JobTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_failed_run_records_rc_and_log_and_keeps_secrets_off_argv(self):
        job = jobs.start(self.tmp / "reports", ["not a host!", "-u", "x"], {"sudo": "S3cret-pw"}, kind="scan")
        wait(job)
        self.assertEqual(job.rc, 2)
        self.assertEqual(job.status, "failed (rc=2)")
        self.assertIn("invalid host", job.log)
        info = (job.dir / "job.json").read_text()
        self.assertNotIn("S3cret-pw", info + job.log)
        self.assertEqual(os.stat(job.dir).st_mode & 0o777, 0o700)
        self.assertEqual(os.stat(job.dir / "log.txt").st_mode & 0o777, 0o600)
        self.assertEqual([j.id for j in jobs.list_jobs(self.tmp / "reports")], [job.id])

    def test_preview_answers_no_to_the_question(self):
        # runner reads stdin first: a run that waits forever on the confirmation question is a good target
        job = jobs.start(self.tmp / "reports", ["127.0.0.1", "--recon-only"], kind="recon", confirm=False)
        wait(job)   # answers "no" by itself: aborted, rc 1
        self.assertEqual(job.rc, 1)
        self.assertIn("Aborted", job.log)


class SecretsTest(unittest.TestCase):
    def test_secrets_replace_prompts(self):
        seen = {}

        class FakeRemote:
            def __init__(self, host, user, port, key, pwd, spwd, accept, passphrase=None):
                seen.update(pwd=pwd, spwd=spwd, kpwd=passphrase)

        with tempfile.NamedTemporaryFile() as key, \
                mock.patch.object(cli, "Remote", FakeRemote), \
                mock.patch.object(cli.getpass, "getpass", side_effect=AssertionError("prompted")), \
                mock.patch.object(cli, "recover", return_value=True):
            rc = cli.main(["10.0.0.1", "-u", "a", "-i", key.name, "--recover", "--yes", "--no-banner"],
                          secrets={"ssh": "p1", "key": "p2", "sudo": "p3"})
        self.assertEqual(rc, 0)
        self.assertEqual(seen, {"pwd": "p1", "kpwd": "p2", "spwd": "p3"})


try:
    from streamlit.testing.v1 import AppTest
except ImportError:   # optional dependency
    AppTest = None

APP = str(Path(jobs.__file__).with_name("app.py"))


@unittest.skipIf(AppTest is None, "streamlit not installed (pip install -e '.[web]')")
class AppPagesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        src = next(FIXTURE_REPORTS.glob("*/report.json"), None)
        if src:
            shutil.copytree(src.parent, self.tmp / "reports" / src.parent.name)
        env = mock.patch.dict(os.environ, {"ZSRA_WEB_TOKEN": "tok", "ZSRA_WEB_OUT_DIR": str(self.tmp / "reports")})
        env.start()
        self.addCleanup(env.stop)

    def _app(self, token="tok"):
        at = AppTest.from_file(APP, default_timeout=30)
        if token:
            at.query_params["token"] = token
        return at.run()

    def test_without_token_access_is_denied(self):
        at = self._app(token="wrong")
        self.assertTrue(at.error)
        self.assertEqual(len(at.sidebar.radio), 0)

    def test_every_page_renders(self):
        at = self._app()
        self.assertFalse(at.exception)
        for page in ["New assessment", "Runs", "Reports", "Compare", "Tools"]:
            at.sidebar.radio[0].set_value(page).run()
            self.assertFalse(at.exception, f"{page}: {at.exception}")

    def test_invalid_target_is_refused_without_starting(self):
        at = self._app()
        at.text_input[0].input("bad host!")
        at.button[0].click().run()
        self.assertTrue(any("Invalid target" in e.value for e in at.error))
        self.assertEqual(jobs.list_jobs(self.tmp / "reports"), [])


if __name__ == "__main__":
    unittest.main()
