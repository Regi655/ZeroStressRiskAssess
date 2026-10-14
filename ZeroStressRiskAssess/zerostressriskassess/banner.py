"""Startup banner: the mascot (mascot.txt) and the tool name.

Shown only on an interactive terminal able to encode UTF-8, and never when disabled
(--no-banner or ZSRA_NO_BANNER): logs, pipes and scripts receive only useful output.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

from . import __version__

# The artwork lives in a separate file so it can be replaced without touching the code:
#   - edit zerostressriskassess/mascot.txt (applies to every user);
#   - or point the ZSRA_MASCOT environment variable to another file (applies to the current user only).
# Any text is accepted (braille, classic ASCII art...). If the file is missing, only the name is shown.
DEFAULT_ART = Path(__file__).with_name("mascot.txt")
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")   # control sequences: an art file must not alter the terminal


def load_art(path=None) -> str:
    """Mascot text from the given file, ZSRA_MASCOT or mascot.txt; empty string if unreadable."""
    p = Path(path or os.environ.get("ZSRA_MASCOT") or DEFAULT_ART).expanduser()
    try:
        text = p.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""
    lines = [_CTRL.sub("", ln).rstrip() for ln in text.splitlines()]
    while lines and not lines[-1].strip("\u2800 "):   # trailing blank lines (including blank braille)
        lines.pop()
    return "\n".join(lines[:60])                        # cap: a wrong file cannot flood the screen


TITLE = "ZeroStressRiskAssess"
SUBTITLE = "Ubuntu risk assessment: risk = impact × likelihood"


def _color(code: str, text: str, stream) -> str:
    # ANSI colours only on a terminal and unless disabled by the user (NO_COLOR convention).
    if not getattr(stream, "isatty", lambda: False)() or os.environ.get("NO_COLOR"):
        return text
    return f"\x1b[{code}m{text}\x1b[0m"


def can_show(stream=None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("ZSRA_NO_BANNER"):
        return False
    if not getattr(stream, "isatty", lambda: False)():
        return False
    try:
        "\u28ff".encode(stream.encoding or "ascii")   # can the terminal encode braille characters?
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def render(stream=None, art=None) -> str:
    stream = stream or sys.stdout
    art = load_art() if art is None else art
    head = _color("1;36", TITLE, stream) + f" {__version__}"
    top = f"{_color('36', art, stream)}\n\n" if art else ""
    return f"{top}  {head}\n  {SUBTITLE}\n"


def show(stream=None) -> None:
    stream = stream or sys.stdout
    if can_show(stream):
        print(render(stream), file=stream)
