"""
Shared Utilities
================
Helper functions shared across modules.
"""

import subprocess
import sys


def get_subprocess_startupinfo():
    """Return a STARTUPINFO that hides the console window on Windows."""
    if sys.platform == "win32":
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 0  # SW_HIDE
        return si
    return None
