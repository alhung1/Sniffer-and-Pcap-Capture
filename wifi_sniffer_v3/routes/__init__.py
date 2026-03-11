"""
Routes Module
=============
Flask blueprints for the WiFi Sniffer v3 application.
"""

from flask import Blueprint

api_bp = Blueprint("api", __name__, url_prefix="/api")
views_bp = Blueprint("views", __name__)

from . import api   # noqa: E402, F401
from . import views  # noqa: E402, F401

__all__ = ["api_bp", "views_bp"]
