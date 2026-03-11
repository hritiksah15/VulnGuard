"""Remediation blueprint – CRUD for remediation steps sub-documents."""

from flask import Blueprint

remediation_bp = Blueprint('remediation', __name__, url_prefix='/api/v1/vulnerabilities')

from routes.remediation import routes  # noqa: E402, F401
