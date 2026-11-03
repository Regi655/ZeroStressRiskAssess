"""`zsra-web`: the web interface (Streamlit), on this machine only.

    zsra-web                       # http://127.0.0.1:8501, opens the browser
    zsra-web --port 8600 --no-browser --out-dir ~/assessments

The server listens on 127.0.0.1 ONLY and asks for a random token generated at every start (printed in the
address): the interface starts assessments with this user's SSH keys, so it must not be reachable by other users
or machines. From another computer use an SSH tunnel: ssh -L 8501:127.0.0.1:8501 THIS_MACHINE.

Requires the optional dependency: .venv/bin/pip install -e '.[web]'
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import secrets
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path


def build_command(port: int, out_dir: str):
    app = Path(__file__).with_name("app.py")
    return [sys.executable, "-m", "streamlit", "run", str(app),
            "--server.address=127.0.0.1", f"--server.port={port}", "--server.headless=true",
            "--browser.gatherUsageStats=false",      # no telemetry: report data and targets stay here
            "--server.fileWatcherType=none", "--server.runOnSave=false",
            "--server.enableXsrfProtection=true", "--client.toolbarMode=minimal",
            "--", "--out-dir", str(Path(out_dir).expanduser().resolve())]


def _when_ready(port: int, url: str, browser: bool):
    for _ in range(150):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                break
        except OSError:
            time.sleep(0.2)
    else:
        return
    time.sleep(0.5)   # after Streamlit's own banner, whose address has no token and would be refused
    print(f"\n  ZeroStressRiskAssess: open  {url}\n"
          "  (the token changes at every start; Ctrl-C stops the interface, NOT the runs in progress)\n", flush=True)
    if browser:
        webbrowser.open(url)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="zsra-web", description="ZeroStressRiskAssess web interface (127.0.0.1 only)")
    ap.add_argument("--port", type=int, default=8501, help="local port (default 8501)")
    ap.add_argument("--out-dir", default="./reports", help="report directory (default ./reports)")
    ap.add_argument("--no-browser", action="store_true", help="do not open the browser")
    args = ap.parse_args(argv)
    if importlib.util.find_spec("streamlit") is None:
        print("Streamlit is not installed: .venv/bin/pip install -e '.[web]'", file=sys.stderr)
        return 2
    token = secrets.token_urlsafe(24)
    url = f"http://127.0.0.1:{args.port}/?token={token}"
    print("ZeroStressRiskAssess web interface, this machine only: starting...", flush=True)
    threading.Thread(target=_when_ready, args=(args.port, url, not args.no_browser), daemon=True).start()
    env = dict(os.environ, ZSRA_WEB_TOKEN=token)
    try:
        return subprocess.call(build_command(args.port, args.out_dir), env=env)
    except KeyboardInterrupt:
        return 0
