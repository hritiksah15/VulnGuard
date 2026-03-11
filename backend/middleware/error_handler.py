"""Centralised error handler for the Flask application."""

from flask import Flask, jsonify


def register_error_handlers(app: Flask) -> None:
    """Register all error handlers with the Flask app.

    Args:
        app: Flask application instance.
    """

    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({
            "status": "error",
            "message": str(e.description) if hasattr(e, 'description') else "Bad request",
            "code": 400
        }), 400

    @app.errorhandler(401)
    def unauthorized(e):
        return jsonify({
            "status": "error",
            "message": "Unauthorized",
            "code": 401
        }), 401

    @app.errorhandler(403)
    def forbidden(e):
        return jsonify({
            "status": "error",
            "message": "Forbidden",
            "code": 403
        }), 403

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({
            "status": "error",
            "message": "Resource not found",
            "code": 404
        }), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        return jsonify({
            "status": "error",
            "message": "Method not allowed",
            "code": 405
        }), 405

    @app.errorhandler(413)
    def request_entity_too_large(e):
        return jsonify({
            "status": "error",
            "message": "Request body too large",
            "code": 413
        }), 413

    @app.errorhandler(422)
    def unprocessable(e):
        return jsonify({
            "status": "error",
            "message": str(e.description) if hasattr(e, 'description') else "Unprocessable entity",
            "code": 422
        }), 422

    @app.errorhandler(429)
    def too_many_requests(e):
        return jsonify({
            "status": "error",
            "message": "Too many requests. Please try again later.",
            "code": 429
        }), 429

    @app.errorhandler(500)
    def internal_error(e):
        return jsonify({
            "status": "error",
            "message": "An internal server error occurred",
            "code": 500
        }), 500

    @app.errorhandler(Exception)
    def handle_unexpected_error(e):
        app.logger.error(f"Unexpected error: {str(e)}")
        return jsonify({
            "status": "error",
            "message": "An unexpected error occurred",
            "code": 500
        }), 500
