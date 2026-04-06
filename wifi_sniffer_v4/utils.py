"""
Utility helpers shared across the application.
"""

import subprocess
import sys


def get_subprocess_startupinfo():
    """Return startupinfo that hides console windows on Windows."""
    if sys.platform == "win32":
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 0  # SW_HIDE
        return si
    return None
