"""Role-based access control middleware decorator."""

from functools import wraps
from flask import jsonify


def role_required(*roles: str):
    """Decorator to enforce role-based access control.

    Args:
        *roles: Allowed role names (e.g., 'admin', 'analyst').

    Returns:
        Decorated function that checks user role before execution.
    """
    def decorator(f):
        @wraps(f)
        def decorated(current_user: dict, *args, **kwargs):
            if current_user.get('role') not in roles:
                return jsonify({
                    "status": "error",
                    "message": "You do not have permission to access this resource",
                    "code": 403
                }), 403
            return f(current_user, *args, **kwargs)
        return decorated
    return decorator
