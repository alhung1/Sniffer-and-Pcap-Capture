"""
Routes package – Flask Blueprints for API and views.
"""

from flask import Blueprint

api_bp = Blueprint("api", __name__, url_prefix="/api")
views_bp = Blueprint("views", __name__)

# Import routes to register them
from . import api  # noqa: F401, E402
from . import views  # noqa: F401, E402

__all__ = ["api_bp", "views_bp"]
