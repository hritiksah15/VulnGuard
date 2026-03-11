"""VulnGuard Blueprints Package.

Provides a single entry-point for registering all API blueprints with the
Flask application instance.

Blueprints
----------
- **auth**           – Authentication, registration, profile & token management
- **vulnerabilities** – CRUD operations on vulnerability records
- **remediation**    – Remediation-step sub-document CRUD
- **activity_log**   – Activity-log sub-document CRUD
- **analytics**      – Aggregation pipelines, dashboards & KPIs
- **admin**          – User administration (role / status / CRUD)
"""

from flask import Flask


def register_blueprints(app: Flask) -> None:
    """Import and register every API blueprint with the application.

    Each blueprint already carries its own ``url_prefix`` so no prefix is
    passed at registration time.

    Args:
        app: The Flask application instance.
    """
    from routes.auth import auth_bp
    from routes.vulnerabilities import vulnerabilities_bp
    from routes.remediation import remediation_bp
    from routes.activity_log import activity_log_bp
    from routes.analytics import analytics_bp
    from routes.admin import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(vulnerabilities_bp)
    app.register_blueprint(remediation_bp)
    app.register_blueprint(activity_log_bp)
    app.register_blueprint(analytics_bp)
    app.register_blueprint(admin_bp)

    app.logger.info(
        "Registered %d blueprint(s): %s",
        6,
        ", ".join([
            auth_bp.name,
            vulnerabilities_bp.name,
            remediation_bp.name,
            activity_log_bp.name,
            analytics_bp.name,
            admin_bp.name,
        ]),
    )
