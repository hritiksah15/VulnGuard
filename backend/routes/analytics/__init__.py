"""Analytics blueprint – aggregation pipelines and dashboard KPIs."""

from flask import Blueprint

analytics_bp = Blueprint('analytics', __name__, url_prefix='/api/v1/analytics')

from routes.analytics import routes  # noqa: E402, F401
