"""VulnGuard – Flask application factory."""

import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, jsonify, request, g
from flask_cors import CORS
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
import time

from config import config_by_name


def _configure_logging(app: Flask) -> None:
    """Set up structured logging with console and file handlers.

    Args:
        app: Flask application instance.
    """
    log_level = logging.DEBUG if app.debug else logging.INFO
    log_format = logging.Formatter(
        '[%(asctime)s] %(levelname)s in %(module)s (%(funcName)s:%(lineno)d): %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(log_format)
    console_handler.setLevel(log_level)

    # File handler – rotates at 10 MB, keeps 5 backups
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
    os.makedirs(log_dir, exist_ok=True)
    file_handler = RotatingFileHandler(
        os.path.join(log_dir, 'vulnguard.log'),
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
    )
    file_handler.setFormatter(log_format)
    file_handler.setLevel(log_level)

    # Apply to Flask logger and root logger
    app.logger.handlers.clear()
    app.logger.addHandler(console_handler)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(log_level)

    # Quieten noisy third-party loggers
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    logging.getLogger('pymongo').setLevel(logging.WARNING)


def create_app(config_name: str | None = None) -> Flask:
    """Create and configure the Flask application.

    Args:
        config_name: Configuration environment name (development, testing, production).

    Returns:
        Configured Flask application instance.
    """
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')

    app = Flask(__name__)
    app.config.from_object(config_by_name[config_name])

    # Configure logging
    _configure_logging(app)
    app.logger.info("Starting VulnGuard API [env=%s]", config_name)

    # Initialise CORS
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # Initialise MongoDB (short timeout so startup is not blocked)
    client = MongoClient(
        app.config['MONGO_URI'],
        serverSelectionTimeoutMS=5000,
    )
    db_name = app.config['MONGO_URI'].rsplit('/', 1)[-1].split('?')[0]
    db = client[db_name]
    app.extensions["mongo_db"] = db

    # Test MongoDB connection at startup
    try:
        client.admin.command('ping')
        app.logger.info("MongoDB connected successfully [%s]", app.config['MONGO_URI'])
    except (ConnectionFailure, ServerSelectionTimeoutError) as e:
        app.logger.warning(
            "WARNING: MongoDB is not reachable at %s — %s. "
            "The server will start, but database operations will fail "
            "until MongoDB becomes available.",
            app.config['MONGO_URI'], e,
        )

    # Create indexes (fail gracefully if MongoDB is unreachable at startup)
    try:
        _create_indexes(db)
    except Exception as e:
        app.logger.warning("Could not create indexes at startup: %s", e)

    # Register error handlers
    from middleware.error_handler import register_error_handlers
    register_error_handlers(app)

    # Register routes
    from routes import register_blueprints
    register_blueprints(app)

    # Request timing & logging middleware
    @app.before_request
    def _before_request():
        g.start_time = time.time()

    @app.after_request
    def _after_request(response):
        duration = round((time.time() - getattr(g, 'start_time', time.time())) * 1000, 2)
        app.logger.info(
            "%s %s %s %sms",
            request.method,
            request.path,
            response.status_code,
            duration,
        )
        return response

    # Health check endpoint
    @app.route('/api/v1/health', methods=['GET'])
    def health_check():
        """Return API health status."""
        return jsonify({"status": "success", "message": "VulnGuard API is running"}), 200

    return app


def _create_indexes(db) -> None:
    """Create all required indexes for optimal query performance.

    Args:
        db: PyMongo database instance.
    """
    # Single field indexes
    db.vulnerabilities.create_index("severity")
    db.vulnerabilities.create_index("status")
    db.vulnerabilities.create_index("cvss_score")
    db.vulnerabilities.create_index("department")
    db.vulnerabilities.create_index("patch_due_date")
    db.vulnerabilities.create_index("patch_applied")
    db.vulnerabilities.create_index("created_at")
    db.vulnerabilities.create_index("vulnerability_type")
    db.vulnerabilities.create_index("discovery_method")

    # Compound index for common filter combinations
    db.vulnerabilities.create_index([
        ("severity", 1),
        ("status", 1),
        ("department", 1)
    ])

    # Text index for search
    db.vulnerabilities.create_index([
        ("vulnerability_title", "text"),
        ("description", "text")
    ])

    # Geospatial index for location-aware queries
    db.vulnerabilities.create_index([("location", "2dsphere")])

    # User collection indexes
    db.users.create_index("email", unique=True)
    db.users.create_index("username", unique=True)

    # Token blacklist index (TTL – auto-delete after 24 h)
    db.blacklist.create_index("token")
    db.blacklist.create_index("blacklisted_at", expireAfterSeconds=86400)
