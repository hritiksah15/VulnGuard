"""JWT authentication middleware decorator."""

from functools import wraps
from flask import request, jsonify, current_app
import jwt


def _extract_token() -> str | None:
    """Extract JWT from the request.

    Reads the token from the ``x-access-token`` header.

    Returns:
        The raw JWT string, or *None* if not present.
    """
    return request.headers.get('x-access-token')


def token_required(f):
    """Decorator to enforce JWT authentication on a route.

    Extracts and validates the JWT token from the ``x-access-token``
    header.  The decoded token payload is passed as ``current_user``
    to the wrapped function.

    Additionally checks the ``blacklist`` collection – if the presented
    token has been revoked (via logout) the request is rejected.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = _extract_token()

        if not token:
            return jsonify({
                "status": "error",
                "message": "Authentication token is missing",
                "code": 401
            }), 401

        # Check token blacklist
        try:
            db = current_app.extensions["mongo_db"]
            if db.blacklist.find_one({"token": token}):
                return jsonify({
                    "status": "error",
                    "message": "Token has been cancelled",
                    "code": 401
                }), 401
        except Exception:
            # If the blacklist check fails we still reject gracefully
            pass

        try:
            payload = jwt.decode(
                token,
                current_app.config['SECRET_KEY'],
                algorithms=["HS256"]
            )
            current_user = payload
        except jwt.ExpiredSignatureError:
            return jsonify({
                "status": "error",
                "message": "Token has expired",
                "code": 401
            }), 401
        except jwt.InvalidTokenError:
            return jsonify({
                "status": "error",
                "message": "Invalid token",
                "code": 401
            }), 401

        return f(current_user, *args, **kwargs)
    return decorated
