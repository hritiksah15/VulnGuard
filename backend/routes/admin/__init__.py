"""Admin blueprint – user management and administrative operations."""

from flask import Blueprint

admin_bp = Blueprint('admin', __name__, url_prefix='/api/v1/admin')

from routes.admin import routes  # noqa: E402, F401
