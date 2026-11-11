"""Upload to the ZeroStressRiskAssessWeb portal (portal.py, zsra-portal, zsra --upload).

The stub server below answers like the portal's ApiController (POST /api/v1/reports): Bearer token, an empty JSON
body is 400 for a valid token (what `check` relies on), 201 for a new report, 200 "duplicate" for the same one
again, 400 if X-Report-SHA256 does not match the body. The contract is checked on the portal side by its own
ApiTokenTest; here the client is tested against it, including TLS with a private authority.
"""
import datetime
import hashlib
import http.server
import io
import json
import os
import shutil
import ssl
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from zerostressriskassess import cli, portal

TOKEN = "zsra_" + "A" * 43
REPORT = {"meta": {"target": "10.0.0.5", "timestamp": "2026-11-11 10:00", "version": "1.5.0"},
          "summary": {"level": "HIGH", "counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0}},
          "risks": [{"id": "R01", "risk": 12, "impact": 4, "probability": 3, "level": "HIGH", "title": "x"}]}


class FakePortal(http.server.BaseHTTPRequestHandler):
    seen = None          # set per server: list of (path, headers, body)
    stored = None        # set of sha256 already "in the area"

    def log_message(self, *a):
        pass

    def _answer(self, code, body, extra=None):
        data = json.dumps(body).encode()
        self.send_response(code)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.server.seen.append((self.path, self.headers, body))   # case-insensitive, like any HTTP server
        if self.path == "/moved/api/v1/reports":
            return self._answer(302, {}, {"Location": "http://127.0.0.1:1/steal"})
        if self.path != "/api/v1/reports":
            return self._answer(404, {"status": "error", "message": "not found"})
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            return self._answer(401, {"status": "error", "message": "Missing, wrong, expired or revoked token."})
        digest = hashlib.sha256(body).hexdigest()
        sha = self.headers.get("X-Report-SHA256")
        if sha is not None and sha.split()[0].lower() != digest:
            return self._answer(400, {"status": "error", "message": "Report refused: fingerprint mismatch"})
        rep = json.loads(body or b"{}")
        if "risks" not in rep:
            return self._answer(400, {"status": "error", "message": "Report refused: not a report"})
        if digest in self.server.stored:
            return self._answer(200, {"status": "duplicate", "message": "This report is already in your area."})
        self.server.stored.add(digest)
        return self._answer(201, {"status": "added", "id": "1", "target": rep["meta"]["target"],
                                  "level": rep["summary"]["level"], "url": "/reports/1"})


def serve(tls_ctx=None):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakePortal)
    srv.seen, srv.stored = [], set()
    if tls_ctx:
        srv.socket = tls_ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def write_report(d: Path, data=REPORT, sha=True) -> Path:
    d.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(data).encode()
    (d / "report.json").write_bytes(raw)
    if sha:
        (d / "report.json.sha256").write_text(hashlib.sha256(raw).hexdigest() + "  report.json\n")
    return d


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        env = {k: v for k, v in os.environ.items() if not k.startswith("ZSRA_PORTAL")}
        env["ZSRA_PORTAL_CONFIG"] = str(self.tmp / "cfg" / "portal.json")
        p = mock.patch.dict(os.environ, env, clear=True)
        p.start()
        self.addCleanup(p.stop)
        a = mock.patch.object(portal, "AGENT_ENV", self.tmp / "no-agent.env")
        a.start()
        self.addCleanup(a.stop)
        self.srv = serve()
        self.addCleanup(self.srv.shutdown)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def cfg(self, token=TOKEN, **kw):
        return portal.Config(self.url, token, **kw)


class AddressTest(unittest.TestCase):
    def test_https_or_local_http_only(self):
        self.assertEqual(portal.check_url("https://zsra.example.org/"), "https://zsra.example.org")
        for ok in ("http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080"):
            portal.check_url(ok)
        for bad in ("http://192.168.1.50", "http://zsra.lan", "ftp://x", "zsra.example.org",
                    "https://u:p@zsra.example.org", "https://zsra.example.org/api/v1/reports"):
            with self.assertRaises(portal.PortalError, msg=bad):
                portal.check_url(bad)


class UploadTest(Base):
    def test_check_valid_and_wrong_token(self):
        self.assertTrue(portal.token_ok(portal.check(self.cfg())))
        a = portal.check(self.cfg(token="zsra_wrong"))
        self.assertEqual(a.code, 401)
        self.assertIn("token refused", portal.describe(a, self.cfg())[1])
        self.assertEqual(self.srv.stored, set())   # check stores nothing

    def test_upload_new_then_duplicate_with_hash(self):
        d = write_report(self.tmp / "rep")
        a = portal.upload(self.cfg(), d)
        self.assertEqual((a.code, a.status), (201, "added"))
        ok, line = portal.describe(a, self.cfg())
        self.assertTrue(ok)
        self.assertIn(self.url + "/reports/1", line)
        path, headers, body = self.srv.seen[-1]
        self.assertEqual(body, (d / "report.json").read_bytes())          # sent exactly as on disk
        self.assertEqual(headers["X-Report-SHA256"], hashlib.sha256(body).hexdigest())
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertTrue(portal.describe(portal.upload(self.cfg(), d / "report.json"), self.cfg())[0])  # duplicate

    def test_altered_report_is_refused(self):
        d = write_report(self.tmp / "rep")
        (d / "report.json").write_text(json.dumps(dict(REPORT, risks=[])))   # changed after the scan
        ok, line = portal.describe(portal.upload(self.cfg(), d), self.cfg())
        self.assertFalse(ok)
        self.assertIn("refused", line)

    def test_redirect_is_not_followed(self):
        cfg = self.cfg()
        cfg.url = self.url
        with mock.patch.object(portal, "API", "/moved/api/v1/reports"):
            with self.assertRaises(portal.PortalError) as e:
                portal.check(cfg)
        self.assertIn("redirect", str(e.exception))
        self.assertEqual(len(self.srv.seen), 1)   # nothing sent to the Location

    def test_unreachable_and_missing_report(self):
        with self.assertRaises(portal.PortalError):
            portal.check(portal.Config("http://127.0.0.1:1", TOKEN))
        with self.assertRaises(portal.PortalError):
            portal.upload(self.cfg(), self.tmp / "nothing")


class ConfigTest(Base):
    def test_login_checks_then_saves_with_mode_600(self):
        out = io.StringIO()
        with mock.patch("sys.stdin", io.StringIO(TOKEN + "\n")), redirect_stdout(out):
            rc = portal.main(["login", self.url, "--token-stdin", "--auto"])
        self.assertEqual(rc, 0, out.getvalue())
        p = portal.config_path()
        self.assertEqual(p.stat().st_mode & 0o777, 0o600)
        self.assertEqual(p.parent.stat().st_mode & 0o777, 0o700)
        cfg = portal.load_config()
        self.assertEqual((cfg.url, cfg.token, cfg.auto), (self.url, TOKEN, True))
        self.assertNotIn(TOKEN, out.getvalue())
        with redirect_stdout(io.StringIO()) as o:
            portal.main(["status"])
        self.assertNotIn(TOKEN, o.getvalue())

    def test_wrong_token_is_not_saved(self):
        with mock.patch("sys.stdin", io.StringIO("zsra_wrong\n")), redirect_stderr(io.StringIO()):
            self.assertEqual(portal.main(["login", self.url, "--token-stdin"]), 1)
        self.assertFalse(portal.config_path().exists())

    def test_environment_wins_and_agent_file_is_the_fallback(self):
        agent = self.tmp / "upload.env"
        agent.write_text(f'# written by zsra-upload.sh setup\nZSRA_URL="{self.url}"\nZSRA_TOKEN={TOKEN}\n'
                         "ZSRA_SCAN_ARGS=--clamav-quick\n")
        with mock.patch.object(portal, "AGENT_ENV", agent):
            self.assertEqual(portal.load_config().source, str(agent))
            with mock.patch.dict(os.environ, {"ZSRA_PORTAL_URL": "https://other", "ZSRA_PORTAL_TOKEN": "t"}):
                self.assertEqual(portal.load_config().url, "https://other")

    def test_upload_command_and_latest(self):
        portal.save_config(self.cfg())
        write_report(self.tmp / "reports" / "10.0.0.5_20261111-1000")
        with redirect_stdout(io.StringIO()) as o:
            rc = portal.main(["upload", "--latest", "--out-dir", str(self.tmp / "reports")])
        self.assertEqual(rc, 0)
        self.assertIn("uploaded", o.getvalue())


class CliTest(Base):
    def test_upload_without_configuration_fails_before_scanning(self):
        with mock.patch.object(cli, "assess", side_effect=AssertionError("scanned")), \
                redirect_stderr(io.StringIO()) as err, self.assertRaises(SystemExit) as e:
            cli.main(["10.0.0.5", "-u", "a", "--upload", "--yes", "--no-banner"])
        self.assertEqual(e.exception.code, 2)
        self.assertIn("zsra-portal login", err.getvalue())

    def _run(self, *extra, auto=False):
        portal.save_config(self.cfg(auto=auto))
        d = write_report(self.tmp / "out" / "10.0.0.5_x")
        rep = dict(REPORT, paths={"dir": str(d), "html": str(d / "report.html"), "md": "", "json": ""})
        with mock.patch.object(cli, "assess", return_value=rep), mock.patch.object(cli, "Remote"), \
                redirect_stdout(io.StringIO()) as out:
            rc = cli.main(["10.0.0.5", "-u", "a", "--yes", "--no-banner", *extra])
        return rc, out.getvalue()

    def test_assessment_then_upload(self):
        rc, out = self._run("--upload")
        self.assertEqual(rc, 0, out)
        self.assertIn("[+] Portal: uploaded", out)

    def test_auto_and_no_upload(self):
        self.assertIn("Portal: uploaded", self._run(auto=True)[1])
        self.assertNotIn("Portal", self._run("--no-upload", auto=True)[1])
        self.assertNotIn("Portal", self._run(auto=False)[1])

    def test_failed_upload_is_exit_code_4(self):
        portal.save_config(self.cfg(token="zsra_revoked"))
        d = write_report(self.tmp / "out" / "10.0.0.5_y")
        rep = dict(REPORT, paths={"dir": str(d), "html": "", "md": "", "json": ""})
        with mock.patch.object(cli, "assess", return_value=rep), mock.patch.object(cli, "Remote"), \
                redirect_stdout(io.StringIO()) as out:
            rc = cli.main(["10.0.0.5", "-u", "a", "--yes", "--no-banner", "--upload"])
        self.assertEqual(rc, 4)
        self.assertIn("zsra-portal upload", out.getvalue())


def _self_signed(d: Path):
    """CA-less self-signed certificate for 127.0.0.1, as a stand-in for Caddy's internal authority."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    import ipaddress
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "zsra test portal")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(key, hashes.SHA256()))
    (d / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (d / "key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                  serialization.NoEncryption()))
    return d / "cert.pem", d / "key.pem"


class TlsTest(Base):
    def test_private_authority_needs_ca_file(self):
        try:
            cert, key = _self_signed(self.tmp)
        except ImportError:
            self.skipTest("cryptography not installed")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        srv = serve(ctx)
        self.addCleanup(srv.shutdown)
        url = f"https://127.0.0.1:{srv.server_address[1]}"
        with self.assertRaises(portal.PortalError) as e:
            portal.check(portal.Config(url, TOKEN))
        self.assertIn("--ca-file", str(e.exception))
        self.assertTrue(portal.token_ok(portal.check(portal.Config(url, TOKEN, ca_file=str(cert)))))


if __name__ == "__main__":
    unittest.main()
