"""
Logging Configuration
=====================
Centralised logging setup for the application.
"""

import logging
import sys
from typing import Optional


def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None):
    """Configure root logger with consistent formatting."""
    level = getattr(logging, log_level.upper(), logging.INFO)

    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        handlers=handlers,
        force=True,
    )
    # Silence noisy libraries
    logging.getLogger("engineio").setLevel(logging.WARNING)
    logging.getLogger("socketio").setLevel(logging.WARNING)
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
