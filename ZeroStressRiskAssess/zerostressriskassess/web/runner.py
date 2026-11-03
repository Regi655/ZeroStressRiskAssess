"""Process started by jobs.start(): runs ONE zsra command line and records how it ended.

    python -m zerostressriskassess.web.runner JOB_DIR ZSRA_ARGS...

First stdin line: JSON with the secrets ({"ssh": ..., "key": ..., "sudo": ...}), read once and passed to cli.main
in memory. The rest of stdin answers the [yes/no] questions (jobs.start sends "no" for a recovery preview).
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def main() -> int:
    job_dir, argv = Path(sys.argv[1]), sys.argv[2:]
    try:
        secrets = json.loads(sys.stdin.readline() or "{}")
    except ValueError:
        secrets = {}
    from ..cli import main as cli_main
    result = {}
    try:
        rc = cli_main(argv, result=result, secrets=secrets if isinstance(secrets, dict) else {})
    except SystemExit as exc:          # argparse: invalid options (the message is already in the log)
        rc = exc.code if isinstance(exc.code, int) else 2
    except KeyboardInterrupt:          # Stop pressed before the assessment started
        print("\nInterrupted.")
        rc = 130
    except EOFError:                   # a question with no answer on stdin
        print("\nAborted: no answer to the confirmation question.")
        rc = 1
    finally:
        secrets = None
    rep_dir = (result.get("report") or {}).get("paths", {}).get("dir")
    if rep_dir:
        _write(job_dir / "report", rep_dir)
    _write(job_dir / "rc", str(rc))
    return rc


def _write(path: Path, text: str):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)


if __name__ == "__main__":
    sys.exit(main())
