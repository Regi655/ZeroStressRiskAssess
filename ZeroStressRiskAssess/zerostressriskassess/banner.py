"""Startup banner: the ZSRA logo (logo.txt) and the tool name.

Shown only on an interactive terminal able to encode UTF-8, and never when disabled
(--no-banner or ZSRA_NO_BANNER): logs, pipes and scripts receive only useful output.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

from . import __version__

# The logo lives in a separate file so it can be replaced without touching the code:
#   - edit zerostressriskassess/logo.txt (applies to every user);
#   - or point the ZSRA_LOGO environment variable to another file (applies to the current user only).
# Block letters with a box-drawing shadow, in red, like the title of Ghidra. If the file is missing, only the name
# is shown.
DEFAULT_ART = Path(__file__).with_name("logo.txt")
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")   # control sequences: an art file must not alter the terminal
# 256-colour red (Ghidra's red); terminals without 256 colours show their nearest red.
LOGO_COLOUR = "1;38;5;160"


def load_art(path=None) -> str:
    """Logo text from the given file, ZSRA_LOGO (or the older ZSRA_MASCOT) or logo.txt; empty if unreadable."""
    p = Path(path or os.environ.get("ZSRA_LOGO") or os.environ.get("ZSRA_MASCOT") or DEFAULT_ART).expanduser()
    try:
        text = p.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""
    lines = [_CTRL.sub("", ln).rstrip() for ln in text.splitlines()]
    while lines and not lines[-1].strip("\u2800 "):   # trailing blank lines (including blank braille)
        lines.pop()
    return "\n".join(lines[:60])                        # cap: a wrong file cannot flood the screen


TITLE = "ZeroStressRiskAssess"
SUBTITLE = "Linux risk assessment: risk = impact × likelihood"


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
        "\u2588\u2557".encode(stream.encoding or "ascii")   # can the terminal encode the block and box characters?
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def render(stream=None, art=None) -> str:
    stream = stream or sys.stdout
    art = load_art() if art is None else art
    head = _color("1", TITLE, stream) + f" {__version__}"
    top = f"{_color(LOGO_COLOUR, art, stream)}\n" if art else ""
    return f"{top}  {head}\n  {SUBTITLE}\n"


def show(stream=None) -> None:
    stream = stream or sys.stdout
    if can_show(stream):
        print(render(stream), file=stream)
