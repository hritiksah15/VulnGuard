"""Remediation steps sub-document CRUD endpoints."""

from flask import request, jsonify
from bson import ObjectId

from middleware.auth_middleware import token_required
from middleware.rbac_middleware import role_required
from routes.remediation.validation import validate_remediation_step_input
from utils.helpers import get_db, validate_object_id, serialize_doc, utcnow
from utils.validators import parse_iso_date
from routes.remediation import remediation_bp


@remediation_bp.route('/<vuln_id>/remediation-steps', methods=['GET'])
@token_required
def get_remediation_steps(current_user: dict, vuln_id: str):
    """Retrieve all remediation steps for a vulnerability."""
    if not validate_object_id(vuln_id):
        return jsonify({"status": "error", "message": "Invalid ObjectId format", "code": 422}), 422

    db = get_db()
    vuln = db.vulnerabilities.find_one({"_id": ObjectId(vuln_id)})

    if not vuln:
        return jsonify({"status": "error", "message": "Vulnerability not found", "code": 404}), 404

    steps = vuln.get('remediation_steps', [])
    return jsonify({
        "status": "success",
        "data": [serialize_doc(s) for s in steps]
    }), 200


@remediation_bp.route('/<vuln_id>/remediation-steps/<step_id>', methods=['GET'])
@token_required
def get_remediation_step(current_user: dict, vuln_id: str, step_id: str):
    """Retrieve a single remediation step by ID."""
    if not validate_object_id(vuln_id) or not validate_object_id(step_id):
        return jsonify({"status": "error", "message": "Invalid ObjectId format", "code": 422}), 422

    db = get_db()

    # Use aggregation to extract single sub-document
    pipeline = [
        {"$match": {"_id": ObjectId(vuln_id)}},
        {"$unwind": "$remediation_steps"},
        {"$match": {"remediation_steps._id": ObjectId(step_id)}},
        {"$replaceRoot": {"newRoot": "$remediation_steps"}},
    ]
    results = list(db.vulnerabilities.aggregate(pipeline))

    if not results:
        return jsonify({"status": "error", "message": "Remediation step not found", "code": 404}), 404

    return jsonify({"status": "success", "data": serialize_doc(results[0])}), 200


@remediation_bp.route('/<vuln_id>/remediation-steps', methods=['POST'])
@token_required
@role_required('admin', 'analyst')
def add_remediation_step(current_user: dict, vuln_id: str):
    """Add a new remediation step to a vulnerability."""
    if not validate_object_id(vuln_id):
        return jsonify({"status": "error", "message": "Invalid ObjectId format", "code": 422}), 422

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "message": "Request body must be valid JSON", "code": 400}), 400

    is_valid, error_msg = validate_remediation_step_input(data, is_update=False)
    if not is_valid:
        return jsonify({"status": "error", "message": error_msg, "code": 422}), 422

    db = get_db()
    vuln = db.vulnerabilities.find_one({"_id": ObjectId(vuln_id)})
    if not vuln:
        return jsonify({"status": "error", "message": "Vulnerability not found", "code": 404}), 404

    new_step = {
        "_id": ObjectId(),
        "step_number": int(data['step_number']),
        "step_description": data['step_description'].strip(),
        "recommended_by": data.get('recommended_by', '').strip() or None,
        "status": data['status'],
        "due_date": parse_iso_date(data.get('due_date')),
        "completed_date": None,
        "notes": data.get('notes', '').strip() or None,
        "added_at": utcnow(),
    }

    db.vulnerabilities.update_one(
        {"_id": ObjectId(vuln_id)},
        {
            "$push": {"remediation_steps": new_step},
            "$set": {"updated_at": utcnow()},
        }
    )

    return jsonify({
        "status": "success",
        "data": serialize_doc(new_step),
        "message": "Remediation step added successfully"
    }), 201


@remediation_bp.route('/<vuln_id>/remediation-steps/<step_id>', methods=['PUT'])
@token_required
@role_required('admin', 'analyst')
def update_remediation_step(current_user: dict, vuln_id: str, step_id: str):
    """Update a specific remediation step by ID."""
    if not validate_object_id(vuln_id) or not validate_object_id(step_id):
        return jsonify({"status": "error", "message": "Invalid ObjectId format", "code": 422}), 422

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "message": "Request body must be valid JSON", "code": 400}), 400

    is_valid, error_msg = validate_remediation_step_input(data, is_update=True)
    if not is_valid:
        return jsonify({"status": "error", "message": error_msg, "code": 422}), 422

    db = get_db()

    # Check vulnerability and step exist
    vuln = db.vulnerabilities.find_one({
        "_id": ObjectId(vuln_id),
        "remediation_steps._id": ObjectId(step_id),
    })
    if not vuln:
        return jsonify({"status": "error", "message": "Remediation step not found", "code": 404}), 404

    # Build positional update
    set_fields = {}
    if 'step_number' in data:
        set_fields['remediation_steps.$.step_number'] = int(data['step_number'])
    if 'step_description' in data:
        set_fields['remediation_steps.$.step_description'] = data['step_description'].strip()
    if 'recommended_by' in data:
        set_fields['remediation_steps.$.recommended_by'] = data['recommended_by'].strip() if data['recommended_by'] else None
    if 'status' in data:
        set_fields['remediation_steps.$.status'] = data['status']
        if data['status'] == 'Completed':
            set_fields['remediation_steps.$.completed_date'] = utcnow()
    if 'due_date' in data:
        set_fields['remediation_steps.$.due_date'] = parse_iso_date(data['due_date'])
    if 'notes' in data:
        set_fields['remediation_steps.$.notes'] = data['notes'].strip() if data['notes'] else None

    set_fields['updated_at'] = utcnow()

    db.vulnerabilities.update_one(
        {"_id": ObjectId(vuln_id), "remediation_steps._id": ObjectId(step_id)},
        {"$set": set_fields}
    )

    # Retrieve updated step
    pipeline = [
        {"$match": {"_id": ObjectId(vuln_id)}},
        {"$unwind": "$remediation_steps"},
        {"$match": {"remediation_steps._id": ObjectId(step_id)}},
        {"$replaceRoot": {"newRoot": "$remediation_steps"}},
    ]
    results = list(db.vulnerabilities.aggregate(pipeline))

    return jsonify({
        "status": "success",
        "data": serialize_doc(results[0]) if results else {},
        "message": "Remediation step updated successfully"
    }), 200


@remediation_bp.route('/<vuln_id>/remediation-steps/<step_id>', methods=['DELETE'])
@token_required
@role_required('admin', 'analyst')
def delete_remediation_step(current_user: dict, vuln_id: str, step_id: str):
    """Remove a remediation step from a vulnerability."""
    if not validate_object_id(vuln_id) or not validate_object_id(step_id):
        return jsonify({"status": "error", "message": "Invalid ObjectId format", "code": 422}), 422

    db = get_db()

    result = db.vulnerabilities.update_one(
        {"_id": ObjectId(vuln_id)},
        {
            "$pull": {"remediation_steps": {"_id": ObjectId(step_id)}},
            "$set": {"updated_at": utcnow()},
        }
    )

    if result.matched_count == 0:
        return jsonify({"status": "error", "message": "Vulnerability not found", "code": 404}), 404

    if result.modified_count == 0:
        return jsonify({"status": "error", "message": "Remediation step not found", "code": 404}), 404

    return '', 204
