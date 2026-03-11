"""Auth blueprint – user registration, login, profile, and token management."""

from flask import Blueprint

auth_bp = Blueprint('auth', __name__, url_prefix='/api/v1/auth')

from routes.auth import routes  # noqa: E402, F401
