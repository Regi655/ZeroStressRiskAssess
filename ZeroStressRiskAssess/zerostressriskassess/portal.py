"""Upload of reports to ZeroStressRiskAssessWeb, the private portal of the suite (`zsra-portal`).

    zsra-portal login https://zsra.example.org          # asks the API token, checks it, saves the configuration
    zsra-portal check                                   # is the token still accepted? (uploads nothing)
    zsra-portal upload reports/HOST_20261103-1600       # an existing report (folder or report.json)
    zsra-portal upload --latest                         # the newest report in ./reports
    zsra-portal status | logout
    zsra HOST -u admin ... --upload                     # assessment, then upload of its report

The portal side is `POST /api/v1/reports` with a personal token (portal: Account > API tokens), which can ONLY
upload reports. The body is report.json as it is, with the content of report.json.sha256 in X-Report-SHA256: the
portal recomputes the hash and refuses a report altered on the way.

Where the configuration comes from, first match wins:
  1. ZSRA_PORTAL_URL + ZSRA_PORTAL_TOKEN (+ ZSRA_PORTAL_CA): automation, a single command;
  2. the JSON file in ZSRA_PORTAL_CONFIG, or ~/.config/zsra/portal.json (written by `login`, mode 600);
  3. /etc/zsra/upload.env, the file of the portal's agent script (zsra-upload.sh setup): ZSRA_URL, ZSRA_TOKEN.
     A machine already set up with the agent uploads with no further step, also with `sudo zsra --local`.

Security:
  - the token is never on the command line (`ps` shows it to every user): asked without echo, or read from stdin;
  - HTTPS only; plain HTTP only towards this machine (http://localhost:8080, the portal's `./start.sh local`);
  - the portal's certificate is verified. For a portal with its own authority (`./start.sh hosted`, Caddy's
    internal CA) pass that CA with --ca-file instead of disabling the check;
  - redirects are not followed: the token would go along with the request to wherever the answer points.
Standard library only (urllib): no new dependency.
"""
from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from . import __version__

API = "/api/v1/reports"
AGENT_ENV = Path("/etc/zsra/upload.env")
TIMEOUT = 300
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


class PortalError(Exception):
    """Configuration, connection or TLS problem: the upload did not reach a decision of the portal."""


def config_path() -> Path:
    if os.environ.get("ZSRA_PORTAL_CONFIG"):
        return Path(os.environ["ZSRA_PORTAL_CONFIG"]).expanduser()
    base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / "zsra" / "portal.json"


@dataclass
class Config:
    url: str
    token: str
    ca_file: str = ""
    auto: bool = False        # upload after every assessment, without --upload
    source: str = ""          # where it was read from (shown by `status`)

    @property
    def masked(self) -> str:
        return self.token[:9] + "…" if len(self.token) > 12 else "…"


def check_url(url: str) -> str:
    """Normalised portal address, or PortalError. HTTPS, or HTTP to this machine only."""
    url = (url or "").strip().rstrip("/")
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.scheme not in ("https", "http") or not host:
        raise PortalError(f"invalid portal address {url!r}: it must start with https://")
    if parts.username or parts.password:
        raise PortalError("no user name or password in the portal address: the API token is the credential")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise PortalError("give only the portal address (https://NAME[:PORT]), without a path")
    if parts.scheme == "http" and not _is_loopback(host):
        raise PortalError(f"{url}: plain HTTP would send the token in clear over the network. Use https:// "
                          "(on the portal: ./start.sh hosted)")
    return url


def _is_loopback(host: str) -> bool:
    if host in LOCAL_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _agent_env(path: Path) -> dict:
    """KEY=VALUE lines of the agent's upload.env, read as data (never sourced, as the agent script does)."""
    out = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return out
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        out[key.strip()] = value.strip().strip('"').strip("'")
    return out


def load_config(path: Path | None = None) -> Config | None:
    env = os.environ
    if env.get("ZSRA_PORTAL_URL") and env.get("ZSRA_PORTAL_TOKEN"):
        return Config(env["ZSRA_PORTAL_URL"], env["ZSRA_PORTAL_TOKEN"], env.get("ZSRA_PORTAL_CA", ""),
                      auto=env.get("ZSRA_PORTAL_AUTO", "") == "1", source="environment (ZSRA_PORTAL_*)")
    path = path or config_path()
    if path.exists():
        try:
            d = json.loads(path.read_text(encoding="utf-8"))
            return Config(d["url"], d["token"], d.get("ca_file", ""), bool(d.get("auto")), source=str(path))
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise PortalError(f"{path}: unreadable configuration ({exc}): run zsra-portal login again")
    agent = _agent_env(AGENT_ENV)
    if agent.get("ZSRA_URL") and agent.get("ZSRA_TOKEN"):
        return Config(agent["ZSRA_URL"], agent["ZSRA_TOKEN"], agent.get("ZSRA_CA", ""), source=str(AGENT_ENV))
    return None


def save_config(cfg: Config, path: Path | None = None) -> Path:
    path = path or config_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    data = json.dumps({"url": cfg.url, "token": cfg.token, "ca_file": cfg.ca_file, "auto": cfg.auto}, indent=2)
    tmp = path.with_name(path.name + ".tmp")
    # Created already with mode 600 (write + chmod would leave a window in which the token is readable).
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(data + "\n")
    os.replace(tmp, path)
    return path


# ---------------------------------------------------------------------- HTTP
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise PortalError(f"the portal answered with a redirect ({code}) to {newurl}: not followed, the token would "
                          "go along. Configure the final address (zsra-portal login)")


@dataclass
class Answer:
    code: int
    body: dict

    @property
    def status(self) -> str:
        return str(self.body.get("status", ""))

    @property
    def message(self) -> str:
        return str(self.body.get("message", ""))


def _post(cfg: Config, data: bytes, sha: str = "") -> Answer:
    url = check_url(cfg.url)
    if cfg.ca_file and not os.path.isfile(os.path.expanduser(cfg.ca_file)):
        raise PortalError(f"CA file not found: {cfg.ca_file}")
    ctx = ssl.create_default_context(cafile=os.path.expanduser(cfg.ca_file) if cfg.ca_file else None)
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), _NoRedirect())
    headers = {"Authorization": f"Bearer {cfg.token}", "Content-Type": "application/json",
               "Accept": "application/json", "User-Agent": f"zsra/{__version__}"}
    if sha:
        headers["X-Report-SHA256"] = sha
    req = urllib.request.Request(url + API, data=data, headers=headers, method="POST")
    try:
        with opener.open(req, timeout=TIMEOUT) as r:
            return Answer(r.status, _json(r.read()))
    except urllib.error.HTTPError as exc:
        try:
            return Answer(exc.code, _json(exc.read()))
        finally:
            exc.close()
    except ssl.SSLCertVerificationError as exc:
        raise PortalError(f"the portal's certificate is not trusted ({exc.verify_message}). If the portal uses its "
                          "own authority (./start.sh hosted), pass it: zsra-portal login URL --ca-file root.crt")
    except urllib.error.URLError as exc:
        reason = exc.reason
        if isinstance(reason, ssl.SSLCertVerificationError):
            raise PortalError(f"the portal's certificate is not trusted ({reason.verify_message}). If the portal "
                              "uses its own authority (./start.sh hosted), pass it with --ca-file root.crt")
        raise PortalError(f"portal unreachable at {url}: {reason}")
    except (OSError, ValueError) as exc:
        raise PortalError(f"portal unreachable at {url}: {exc}")


def _json(raw: bytes) -> dict:
    try:
        d = json.loads(raw.decode("utf-8") or "{}")
        return d if isinstance(d, dict) else {}
    except (UnicodeDecodeError, ValueError):
        return {"message": raw[:200].decode("utf-8", "replace")}


def check(cfg: Config) -> Answer:
    """An empty JSON body: a valid token gets 400 (report refused), a wrong one 401. Nothing is stored."""
    return _post(cfg, b"{}")


def token_ok(a: Answer) -> bool:
    return a.code == 400


def find_report(path) -> Path:
    """A report folder or its report.json -> path of report.json."""
    p = Path(path).expanduser()
    if p.is_dir():
        p = p / "report.json"
    if p.name != "report.json" or not p.is_file():
        raise PortalError(f"{path}: no report.json there")
    return p


def upload(cfg: Config, path) -> Answer:
    """Upload one report as it is on disk, with its .sha256 if present."""
    rep = find_report(path)
    data = rep.read_bytes()
    sha = ""
    sha_file = rep.with_name("report.json.sha256")
    if sha_file.is_file():
        sha = sha_file.read_text(encoding="ascii", errors="replace").split()[0] if sha_file.stat().st_size else ""
    return _post(cfg, data, sha)


def describe(a: Answer, cfg: Config) -> tuple[bool, str]:
    """(ok, one line for the terminal). ok = the report is in the portal (added now or already there)."""
    if a.code == 201:
        return True, f"uploaded: {a.body.get('target', '?')} {a.body.get('level', '')} -> {cfg.url}{a.body.get('url', '')}"
    if a.code == 200 and a.status == "duplicate":
        return True, "already in the portal (same report): nothing to do"
    if a.code == 200 and a.status == "too_old":
        return False, f"not kept by the portal: {a.message}"
    if a.code == 401:
        return False, "token refused (wrong, expired or revoked): create a new one in the portal, Account > API tokens"
    if a.code == 429:
        return False, f"too many invalid tokens from this address: {a.message or 'try again later'}"
    if a.code == 400:
        return False, f"report refused by the portal: {a.message}"
    if a.code == 413:
        return False, "report too large for the portal (ZSRA_REPORT_MAX_BYTES on the portal)"
    return False, f"unexpected answer from the portal (HTTP {a.code}): {a.message or a.body}"


def upload_report(rep_dir, log=print, cfg: Config | None = None) -> bool:
    """For zsra --upload and the console: upload and print the outcome. True if the report is in the portal."""
    try:
        cfg = cfg or load_config()
        if cfg is None:
            log("[!] Portal: not configured (zsra-portal login URL): report NOT uploaded.")
            return False
        ok, line = describe(upload(cfg, rep_dir), cfg)
    except PortalError as exc:
        ok, line = False, str(exc)
    log(("[+] Portal: " if ok else "[!] Portal: ") + line)
    return ok


# ---------------------------------------------------------------------- command line
def _latest(out_dir) -> Path:
    from .console import list_reports
    rows = list_reports(out_dir)
    if not rows:
        raise PortalError(f"no reports in {out_dir}")
    return rows[0][0]


def build_parser():
    ap = argparse.ArgumentParser(prog="zsra-portal",
                                 description="Upload reports to ZeroStressRiskAssessWeb (the private portal of the suite)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    lg = sub.add_parser("login", help="save the portal address and API token (checked first)")
    lg.add_argument("url", help="portal address, e.g. https://zsra.example.org")
    lg.add_argument("--ca-file", default="", help="CA of a portal with its own authority (Caddy internal CA)")
    lg.add_argument("--auto", action="store_true", help="upload after EVERY assessment, without --upload")
    lg.add_argument("--token-stdin", action="store_true", help="read the token from standard input (automation)")
    sub.add_parser("check", help="is the token accepted? (uploads nothing)")
    up = sub.add_parser("upload", help="upload existing reports (folders or report.json)")
    up.add_argument("paths", nargs="*", help="report folders or report.json files")
    up.add_argument("--latest", action="store_true", help="the newest report in --out-dir")
    up.add_argument("--out-dir", default="./reports", help="report directory for --latest (default ./reports)")
    sub.add_parser("status", help="where the configuration is and what it says (token masked)")
    sub.add_parser("logout", help="delete the saved configuration (the token stays valid: revoke it in the portal)")
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return _main(args)
    except PortalError as exc:
        print(f"zsra-portal: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print()
        return 130


def _main(args) -> int:
    if args.cmd == "login":
        url = check_url(args.url)
        token = (sys.stdin.readline() if args.token_stdin else getpass.getpass("API token (zsra_...): ")).strip()
        if not token:
            raise PortalError("no token given")
        cfg = Config(url, token, os.path.expanduser(args.ca_file) if args.ca_file else "", args.auto)
        a = check(cfg)
        if not token_ok(a):
            print(f"zsra-portal: {describe(a, cfg)[1]}: configuration NOT saved", file=sys.stderr)
            return 1
        path = save_config(cfg)
        print(f"Token accepted by {url}. Configuration saved in {path} (mode 600).")
        print("Upload after every assessment: " + ("yes (--no-upload to skip once)" if cfg.auto else
                                                   "only with --upload (login again with --auto to change)"))
        return 0

    if args.cmd == "logout":
        path = config_path()
        if path.exists():
            path.unlink()
            print(f"Deleted {path}. The token is still valid: revoke it in the portal (Account > API tokens).")
        else:
            print(f"Nothing saved in {path}.")
        return 0

    cfg = load_config()
    if cfg is None:
        raise PortalError("not configured: zsra-portal login https://PORTAL (token from Account > API tokens)")

    if args.cmd == "status":
        print(f"Portal:     {cfg.url}\nToken:      {cfg.masked}\nCA file:    {cfg.ca_file or '(system certificates)'}\n"
              f"Auto:       {'yes, after every assessment' if cfg.auto else 'no, only with --upload'}\n"
              f"From:       {cfg.source}")
        return 0

    if args.cmd == "check":
        a = check(cfg)
        if token_ok(a):
            print(f"Token accepted by {cfg.url}.")
            return 0
        print(f"zsra-portal: {describe(a, cfg)[1]}", file=sys.stderr)
        return 1

    paths = list(args.paths) + ([str(_latest(args.out_dir))] if args.latest else [])
    if not paths:
        raise PortalError("which report? give a folder, a report.json or --latest")
    failed = 0
    for p in paths:
        ok, line = describe(upload(cfg, p), cfg)
        print(f"{p}: {line}", file=sys.stdout if ok else sys.stderr)
        failed += not ok
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
