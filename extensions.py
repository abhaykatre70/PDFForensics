"""extensions.py — Shared extension instances (avoids circular imports)."""
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
