"""Admin management routes."""

import math
from flask import request, jsonify
from bson import ObjectId

from middleware.auth_middleware import token_required
from middleware.rbac_middleware import role_required
from utils.helpers import get_db, validate_object_id, serialize_doc, get_pagination_params
from utils.validators import VALID_ROLES
from routes.admin import admin_bp


@admin_bp.route('/users', methods=['GET'])
@token_required
@role_required('admin')
def list_users(current_user: dict):
    """List all registered users (Admin only)."""
    db = get_db()
    args = request.args

    page, per_page = get_pagination_params(args)

    query = {}
    if args.get('role'):
        query['role'] = args['role']
    if args.get('is_active') is not None and args.get('is_active') != '':
        query['is_active'] = args['is_active'].lower() == 'true'

    skip = (page - 1) * per_page
    total = db.users.count_documents(query)
    total_pages = math.ceil(total / per_page) if total > 0 else 1

    cursor = db.users.find(query, {"password_hash": 0}).sort("created_at", -1).skip(skip).limit(per_page)
    users = [serialize_doc(u) for u in cursor]

    return jsonify({
        "status": "success",
        "data": users,
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "pages": total_pages,
        }
    }), 200


@admin_bp.route('/users/<user_id>', methods=['GET'])
@token_required
@role_required('admin')
def get_user(current_user: dict, user_id: str):
    """Get a specific user's details (Admin only)."""
    if not validate_object_id(user_id):
        return jsonify({"status": "error", "message": "Invalid ObjectId format", "code": 422}), 422

    db = get_db()
    user = db.users.find_one({"_id": ObjectId(user_id)}, {"password_hash": 0})

    if not user:
        return jsonify({"status": "error", "message": "User not found", "code": 404}), 404

    return jsonify({"status": "success", "data": serialize_doc(user)}), 200


@admin_bp.route('/users/<user_id>/role', methods=['PUT'])
@token_required
@role_required('admin')
def update_user_role(current_user: dict, user_id: str):
    """Update a user's role (Admin only)."""
    if not validate_object_id(user_id):
        return jsonify({"status": "error", "message": "Invalid ObjectId format", "code": 422}), 422

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "message": "Request body must be valid JSON", "code": 400}), 400

    new_role = data.get('role')
    if new_role not in VALID_ROLES:
        return jsonify({
            "status": "error",
            "message": f"'role' must be one of: {', '.join(VALID_ROLES)}",
            "code": 422
        }), 422

    db = get_db()

    # Prevent self-demotion
    if user_id == current_user['user_id']:
        return jsonify({"status": "error", "message": "Cannot change your own role", "code": 400}), 400

    result = db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"role": new_role}})

    if result.matched_count == 0:
        return jsonify({"status": "error", "message": "User not found", "code": 404}), 404

    user = db.users.find_one({"_id": ObjectId(user_id)}, {"password_hash": 0})
    return jsonify({
        "status": "success",
        "data": serialize_doc(user),
        "message": f"User role updated to '{new_role}'"
    }), 200


@admin_bp.route('/users/<user_id>/status', methods=['PUT'])
@token_required
@role_required('admin')
def update_user_status(current_user: dict, user_id: str):
    """Activate or deactivate a user account (Admin only)."""
    if not validate_object_id(user_id):
        return jsonify({"status": "error", "message": "Invalid ObjectId format", "code": 422}), 422

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "message": "Request body must be valid JSON", "code": 400}), 400

    if 'is_active' not in data or not isinstance(data['is_active'], bool):
        return jsonify({
            "status": "error",
            "message": "'is_active' must be a boolean",
            "code": 422
        }), 422

    db = get_db()

    # Prevent self-deactivation
    if user_id == current_user['user_id']:
        return jsonify({"status": "error", "message": "Cannot deactivate your own account", "code": 400}), 400

    result = db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"is_active": data['is_active']}})

    if result.matched_count == 0:
        return jsonify({"status": "error", "message": "User not found", "code": 404}), 404

    user = db.users.find_one({"_id": ObjectId(user_id)}, {"password_hash": 0})
    status_text = "activated" if data['is_active'] else "deactivated"
    return jsonify({
        "status": "success",
        "data": serialize_doc(user),
        "message": f"User account {status_text}"
    }), 200


@admin_bp.route('/users/<user_id>', methods=['DELETE'])
@token_required
@role_required('admin')
def delete_user(current_user: dict, user_id: str):
    """Permanently delete a user account (Admin only)."""
    if not validate_object_id(user_id):
        return jsonify({"status": "error", "message": "Invalid ObjectId format", "code": 422}), 422

    db = get_db()

    # Prevent self-deletion
    if user_id == current_user['user_id']:
        return jsonify({"status": "error", "message": "Cannot delete your own account", "code": 400}), 400

    result = db.users.delete_one({"_id": ObjectId(user_id)})

    if result.deleted_count == 0:
        return jsonify({"status": "error", "message": "User not found", "code": 404}), 404

    return '', 204
