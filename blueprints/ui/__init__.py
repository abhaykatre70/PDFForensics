"""blueprints/ui/__init__.py"""
from flask import Blueprint

ui_bp = Blueprint("ui", __name__)

from . import routes  # noqa: F401, E402
