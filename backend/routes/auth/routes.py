"""Authentication and user management endpoints."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4
from flask import request, jsonify, current_app
from bson import ObjectId
import bcrypt
import jwt

from middleware.auth_middleware import token_required, _extract_token
from routes.auth.validation import (
    validate_registration_input,
    validate_login_input,
    validate_profile_update,
    validate_change_password,
)
from utils.helpers import get_db, serialize_doc, utcnow
from routes.auth import auth_bp


@auth_bp.route('/register', methods=['POST'])
def register():
    """Register a new user account."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "message": "Request body must be valid JSON", "code": 400}), 400

    is_valid, error_msg = validate_registration_input(data)
    if not is_valid:
        return jsonify({"status": "error", "message": error_msg, "code": 422}), 422

    db = get_db()

    # Check for duplicate email
    if db.users.find_one({"email": data['email'].lower().strip()}):
        return jsonify({"status": "error", "message": "Email already registered", "code": 400}), 400

    # Check for duplicate username
    if db.users.find_one({"username": data['username'].strip()}):
        return jsonify({"status": "error", "message": "Username already taken", "code": 400}), 400

    # Hash password
    password_hash = bcrypt.hashpw(
        data['password'].encode('utf-8'),
        bcrypt.gensalt(rounds=12)
    )

    now = utcnow()
    user_doc = {
        "username": data['username'].strip(),
        "email": data['email'].lower().strip(),
        "password_hash": password_hash.decode('utf-8'),
        "role": "analyst",  # Default role
        "is_active": True,
        "created_at": now,
        "last_login": None,
    }

    result = db.users.insert_one(user_doc)
    user_doc['_id'] = result.inserted_id

    # Remove password_hash from response
    response_data = serialize_doc(user_doc)
    response_data.pop('password_hash', None)

    return jsonify({
        "status": "success",
        "data": response_data,
        "message": "User registered successfully"
    }), 201


@auth_bp.route('/login', methods=['POST'])
def login():
    """Authenticate user and return JWT token."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "message": "Request body must be valid JSON", "code": 400}), 400

    is_valid, error_msg = validate_login_input(data)
    if not is_valid:
        return jsonify({"status": "error", "message": error_msg, "code": 400}), 400

    db = get_db()
    user = db.users.find_one({"email": data['email'].lower().strip()})

    if not user:
        return jsonify({"status": "error", "message": "Invalid email or password", "code": 401}), 401

    if not user.get('is_active', True):
        return jsonify({"status": "error", "message": "Account is deactivated. Contact an administrator.", "code": 401}), 401

    if not bcrypt.checkpw(data['password'].encode('utf-8'), user['password_hash'].encode('utf-8')):
        return jsonify({"status": "error", "message": "Invalid email or password", "code": 401}), 401

    # Update last login
    db.users.update_one({"_id": user['_id']}, {"$set": {"last_login": utcnow()}})

    expiry_hours = current_app.config.get('JWT_EXPIRY_HOURS', 1)
    payload = {
        "user_id": str(user['_id']),
        "username": user['username'],
        "role": user['role'],
        "exp": datetime.now(timezone.utc) + timedelta(hours=expiry_hours),
        "iat": datetime.now(timezone.utc),
        "jti": str(uuid4()),
    }
    token = jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm="HS256")

    return jsonify({
        "status": "success",
        "data": {
            "token": token,
            "user": {
                "_id": str(user['_id']),
                "username": user['username'],
                "email": user['email'],
                "role": user['role'],
            }
        },
        "message": "Login successful"
    }), 200


@auth_bp.route('/profile', methods=['GET'])
@token_required
def get_profile(current_user: dict):
    """Get current authenticated user's profile."""
    db = get_db()
    user = db.users.find_one({"_id": ObjectId(current_user['user_id'])})

    if not user:
        return jsonify({"status": "error", "message": "User not found", "code": 404}), 404

    user_data = serialize_doc(user)
    user_data.pop('password_hash', None)

    return jsonify({"status": "success", "data": user_data}), 200


@auth_bp.route('/profile', methods=['PUT'])
@token_required
def update_profile(current_user: dict):
    """Update current user's profile details."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "message": "Request body must be valid JSON", "code": 400}), 400

    is_valid, error_msg = validate_profile_update(data)
    if not is_valid:
        return jsonify({"status": "error", "message": error_msg, "code": 422}), 422

    db = get_db()
    update_fields = {}

    if 'username' in data:
        existing = db.users.find_one({
            "username": data['username'].strip(),
            "_id": {"$ne": ObjectId(current_user['user_id'])}
        })
        if existing:
            return jsonify({"status": "error", "message": "Username already taken", "code": 400}), 400
        update_fields['username'] = data['username'].strip()

    if 'email' in data:
        existing = db.users.find_one({
            "email": data['email'].lower().strip(),
            "_id": {"$ne": ObjectId(current_user['user_id'])}
        })
        if existing:
            return jsonify({"status": "error", "message": "Email already registered", "code": 400}), 400
        update_fields['email'] = data['email'].lower().strip()

    if not update_fields:
        return jsonify({"status": "error", "message": "No valid fields to update", "code": 400}), 400

    db.users.update_one(
        {"_id": ObjectId(current_user['user_id'])},
        {"$set": update_fields}
    )

    user = db.users.find_one({"_id": ObjectId(current_user['user_id'])})
    user_data = serialize_doc(user)
    user_data.pop('password_hash', None)

    return jsonify({"status": "success", "data": user_data, "message": "Profile updated successfully"}), 200


@auth_bp.route('/refresh', methods=['POST'])
@token_required
def refresh_token(current_user: dict):
    """Refresh JWT token before expiry."""
    expiry_hours = current_app.config.get('JWT_EXPIRY_HOURS', 1)
    payload = {
        "user_id": current_user['user_id'],
        "username": current_user['username'],
        "role": current_user['role'],
        "exp": datetime.now(timezone.utc) + timedelta(hours=expiry_hours),
        "iat": datetime.now(timezone.utc),
        "jti": str(uuid4()),
    }
    token = jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm="HS256")

    return jsonify({
        "status": "success",
        "data": {"token": token},
        "message": "Token refreshed successfully"
    }), 200


@auth_bp.route('/change-password', methods=['PUT'])
@token_required
def change_password(current_user: dict):
    """Change current user's password."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "message": "Request body must be valid JSON", "code": 400}), 400

    is_valid, error_msg = validate_change_password(data)
    if not is_valid:
        return jsonify({"status": "error", "message": error_msg, "code": 422}), 422

    db = get_db()
    user = db.users.find_one({"_id": ObjectId(current_user['user_id'])})

    if not user:
        return jsonify({"status": "error", "message": "User not found", "code": 404}), 404

    if not bcrypt.checkpw(data['current_password'].encode('utf-8'), user['password_hash'].encode('utf-8')):
        return jsonify({"status": "error", "message": "Current password is incorrect", "code": 400}), 400

    new_hash = bcrypt.hashpw(
        data['new_password'].encode('utf-8'),
        bcrypt.gensalt(rounds=12)
    )

    db.users.update_one(
        {"_id": user['_id']},
        {"$set": {"password_hash": new_hash.decode('utf-8')}}
    )

    return jsonify({"status": "success", "message": "Password changed successfully"}), 200


@auth_bp.route('/logout', methods=['POST'])
@token_required
def logout(current_user: dict):
    """Logout by adding the current token to the blacklist collection.

    Because JWTs cannot be destroyed before their expiry, the token is
    inserted into a ``blacklist`` collection.  The ``token_required``
    decorator checks this collection on every request.
    """
    token = _extract_token()

    db = get_db()

    # Avoid duplicates – only insert if not already blacklisted
    if not db.blacklist.find_one({"token": token}):
        db.blacklist.insert_one({
            "token": token,
            "user_id": current_user['user_id'],
            "blacklisted_at": utcnow(),
        })

    return jsonify({"status": "success", "message": "Logged out successfully"}), 200
