"""Activity log sub-document CRUD endpoints."""

from flask import request, jsonify
from bson import ObjectId

from middleware.auth_middleware import token_required
from middleware.rbac_middleware import role_required
from routes.activity_log.validation import validate_activity_log_input
from utils.helpers import get_db, validate_object_id, serialize_doc, utcnow
from routes.activity_log import activity_log_bp


@activity_log_bp.route('/<vuln_id>/activity-log', methods=['GET'])
@token_required
def get_activity_log(current_user: dict, vuln_id: str):
    """Retrieve all activity log entries for a vulnerability."""
    if not validate_object_id(vuln_id):
        return jsonify({"status": "error", "message": "Invalid ObjectId format", "code": 422}), 422

    db = get_db()
    vuln = db.vulnerabilities.find_one({"_id": ObjectId(vuln_id)})

    if not vuln:
        return jsonify({"status": "error", "message": "Vulnerability not found", "code": 404}), 404

    logs = vuln.get('activity_log', [])
    return jsonify({
        "status": "success",
        "data": [serialize_doc(log) for log in logs]
    }), 200


@activity_log_bp.route('/<vuln_id>/activity-log/<log_id>', methods=['GET'])
@token_required
def get_activity_log_entry(current_user: dict, vuln_id: str, log_id: str):
    """Retrieve a single activity log entry by ID."""
    if not validate_object_id(vuln_id) or not validate_object_id(log_id):
        return jsonify({"status": "error", "message": "Invalid ObjectId format", "code": 422}), 422

    db = get_db()

    pipeline = [
        {"$match": {"_id": ObjectId(vuln_id)}},
        {"$unwind": "$activity_log"},
        {"$match": {"activity_log._id": ObjectId(log_id)}},
        {"$replaceRoot": {"newRoot": "$activity_log"}},
    ]
    results = list(db.vulnerabilities.aggregate(pipeline))

    if not results:
        return jsonify({"status": "error", "message": "Activity log entry not found", "code": 404}), 404

    return jsonify({"status": "success", "data": serialize_doc(results[0])}), 200


@activity_log_bp.route('/<vuln_id>/activity-log', methods=['POST'])
@token_required
@role_required('admin', 'analyst')
def add_activity_log_entry(current_user: dict, vuln_id: str):
    """Add a new activity log entry to a vulnerability."""
    if not validate_object_id(vuln_id):
        return jsonify({"status": "error", "message": "Invalid ObjectId format", "code": 422}), 422

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "message": "Request body must be valid JSON", "code": 400}), 400

    is_valid, error_msg = validate_activity_log_input(data)
    if not is_valid:
        return jsonify({"status": "error", "message": error_msg, "code": 422}), 422

    db = get_db()
    vuln = db.vulnerabilities.find_one({"_id": ObjectId(vuln_id)})
    if not vuln:
        return jsonify({"status": "error", "message": "Vulnerability not found", "code": 404}), 404

    new_entry = {
        "_id": ObjectId(),
        "performed_at": utcnow(),
        "action": data['action'].strip(),
        "performed_by": current_user['username'],
        "details": data.get('details', '').strip() or None,
        "previous_value": data.get('previous_value', '').strip() or None,
        "new_value": data.get('new_value', '').strip() or None,
    }

    db.vulnerabilities.update_one(
        {"_id": ObjectId(vuln_id)},
        {
            "$push": {"activity_log": new_entry},
            "$set": {"updated_at": utcnow()},
        }
    )

    return jsonify({
        "status": "success",
        "data": serialize_doc(new_entry),
        "message": "Activity log entry added successfully"
    }), 201


@activity_log_bp.route('/<vuln_id>/activity-log/<log_id>', methods=['DELETE'])
@token_required
@role_required('admin')
def delete_activity_log_entry(current_user: dict, vuln_id: str, log_id: str):
    """Delete an activity log entry (Admin only)."""
    if not validate_object_id(vuln_id) or not validate_object_id(log_id):
        return jsonify({"status": "error", "message": "Invalid ObjectId format", "code": 422}), 422

    db = get_db()

    result = db.vulnerabilities.update_one(
        {"_id": ObjectId(vuln_id)},
        {
            "$pull": {"activity_log": {"_id": ObjectId(log_id)}},
            "$set": {"updated_at": utcnow()},
        }
    )

    if result.matched_count == 0:
        return jsonify({"status": "error", "message": "Vulnerability not found", "code": 404}), 404

    if result.modified_count == 0:
        return jsonify({"status": "error", "message": "Activity log entry not found", "code": 404}), 404

    return '', 204
