"""Static check: every module imports and (if pyflakes is available) no name is undefined.

pyflakes reads the code without running it: it finds variables used but never defined (like STICKY_DIRS
in 0.2.3), unused imports, variables assigned and never used. Installation: pip install pyflakes
"""
import importlib
import importlib.util
import pkgutil
import subprocess
import sys
import unittest
from pathlib import Path

import zerostressriskassess

ROOT = Path(zerostressriskassess.__file__).parent
# Optional dependencies (pyproject.toml, [project.optional-dependencies]): a module needing one is skipped without it
OPTIONAL = {"streamlit", "reportlab"}


class LintTest(unittest.TestCase):
    def test_every_module_imports(self):
        for m in pkgutil.walk_packages([str(ROOT)], prefix="zerostressriskassess."):
            with self.subTest(module=m.name):
                try:
                    importlib.import_module(m.name)
                except ModuleNotFoundError as exc:
                    if exc.name not in OPTIONAL:
                        raise
                    self.skipTest(f"{m.name}: optional dependency {exc.name} not installed")

    def test_pyflakes(self):
        if importlib.util.find_spec("pyflakes") is None:
            self.skipTest("pyflakes not installed (pip install pyflakes)")
        r = subprocess.run([sys.executable, "-m", "pyflakes", str(ROOT)], capture_output=True, text=True)
        self.assertEqual(r.stdout + r.stderr, "", "pyflakes found problems")


if __name__ == "__main__":
    unittest.main()
