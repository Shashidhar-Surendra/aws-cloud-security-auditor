"""
conftest.py — pytest session setup.

Python's zipfile.extractall() does not restore Unix executable bits from
ZIP external attributes (known CPython behaviour).  This hook re-applies
the correct mode to run_audit.sh so that test_shell_launcher_exists_and_is_executable
passes regardless of how the archive was extracted.

The chmod is idempotent and harmless when the bit is already present (e.g.
after a git clone or a CLI unzip).
"""

from __future__ import annotations

import stat
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def pytest_configure(config: object) -> None:
    """Restore executable permission on run_audit.sh before any test runs."""
    sh = ROOT / "run_audit.sh"
    if sh.exists():
        sh.chmod(sh.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
