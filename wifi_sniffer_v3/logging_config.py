"""
Logging Configuration
=====================
Centralized logging setup with console and optional rotating file handler.
"""

import logging
import logging.handlers
import os
import sys


def setup_logging(log_level: str = "INFO", log_file: str | None = None):
    """
    Configure the root logger for the application.

    Args:
        log_level: Minimum log level (DEBUG, INFO, WARNING, ERROR).
        log_file: Optional path for a rotating log file.
    """
    level = getattr(logging, log_level.upper(), logging.INFO)

    fmt = "[%(asctime)s] %(levelname)-7s %(name)s: %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"
    formatter = logging.Formatter(fmt, datefmt=datefmt)

    root = logging.getLogger()
    root.setLevel(level)

    # Avoid duplicate handlers on repeated calls
    if root.handlers:
        return

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    root.addHandler(console)

    if log_file:
        os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
        )
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)
