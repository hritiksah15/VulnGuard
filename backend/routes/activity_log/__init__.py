"""Activity Log blueprint – CRUD for vulnerability activity log entries."""

from flask import Blueprint

activity_log_bp = Blueprint('activity_log', __name__, url_prefix='/api/v1/vulnerabilities')

from routes.activity_log import routes  # noqa: E402, F401
