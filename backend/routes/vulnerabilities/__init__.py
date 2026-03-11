"""Vulnerabilities blueprint – CRUD operations for vulnerability records."""

from flask import Blueprint

vulnerabilities_bp = Blueprint('vulnerabilities', __name__, url_prefix='/api/v1/vulnerabilities')

from routes.vulnerabilities import routes  # noqa: E402, F401
