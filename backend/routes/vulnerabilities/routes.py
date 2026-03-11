"""Vulnerability CRUD endpoints."""

import math
from flask import request, jsonify
from bson import ObjectId

from middleware.auth_middleware import token_required
from middleware.rbac_middleware import role_required
from routes.vulnerabilities.validation import validate_vulnerability_input
from utils.helpers import (
    get_db, validate_object_id, serialize_doc, get_pagination_params,
    utcnow, calculate_risk_score,
)
from utils.validators import parse_iso_date
from routes.vulnerabilities import vulnerabilities_bp


@vulnerabilities_bp.route('/', methods=['GET'])
def get_vulnerabilities():
    """Retrieve paginated list of vulnerabilities with optional filters.

    Supports:
    - Exact match: ``severity``, ``status``, ``asset_type``, ``department``, ``assigned_to``
    - Multi-value ($in):  ``severity_in``, ``status_in`` (comma-separated)
    - Range ($gte/$lte):  ``min_cvss``, ``max_cvss``
    - Regex search:       ``title_regex``
    - Full-text search:   ``search``
    - Boolean:            ``patch_applied``
    - $or combinators:    ``or_severity``, ``or_status``, ``or_min_cvss``, ``or_department``
    - Cursor-based pagination: ``after`` (ObjectId of last item)
    """
    db = get_db()
    args = request.args

    page, per_page = get_pagination_params(args)

    # Build query filter
    query = {}

    # --- Exact-match filters ---
    if args.get('severity'):
        query['severity'] = args['severity']
    if args.get('status'):
        query['status'] = args['status']
    if args.get('asset_type'):
        query['asset_type'] = args['asset_type']
    if args.get('department'):
        query['department'] = args['department']
    if args.get('assigned_to'):
        query['assigned_to'] = args['assigned_to']
    if args.get('patch_applied') is not None and args.get('patch_applied') != '':
        query['patch_applied'] = args['patch_applied'].lower() == 'true'

    # --- Multi-value ($in) filters ---
    if args.get('severity_in'):
        query['severity'] = {"$in": [s.strip() for s in args['severity_in'].split(',') if s.strip()]}
    if args.get('status_in'):
        query['status'] = {"$in": [s.strip() for s in args['status_in'].split(',') if s.strip()]}

    # --- Regex filter on vulnerability_title ---
    if args.get('title_regex'):
        query['vulnerability_title'] = {"$regex": args['title_regex'], "$options": "i"}

    # --- CVSS range filters ---
    if args.get('min_cvss') or args.get('max_cvss'):
        cvss_filter = {}
        if args.get('min_cvss'):
            try:
                cvss_filter['$gte'] = float(args['min_cvss'])
            except ValueError:
                pass
        if args.get('max_cvss'):
            try:
                cvss_filter['$lte'] = float(args['max_cvss'])
            except ValueError:
                pass
        if cvss_filter:
            query['cvss_score'] = cvss_filter

    # --- Full-text search ---
    if args.get('search'):
        query['$text'] = {'$search': args['search']}

    # --- $or filter (combine multiple conditions) ---
    # e.g. ?or_severity=Critical&or_status=Open  → matches severity=Critical OR status=Open
    or_clauses = []
    if args.get('or_severity'):
        or_clauses.append({"severity": args['or_severity']})
    if args.get('or_status'):
        or_clauses.append({"status": args['or_status']})
    if args.get('or_min_cvss'):
        try:
            or_clauses.append({"cvss_score": {"$gte": float(args['or_min_cvss'])}})
        except ValueError:
            pass
    if args.get('or_department'):
        or_clauses.append({"department": args['or_department']})
    if or_clauses:
        query['$or'] = or_clauses

    # Sorting
    sort_by = args.get('sort_by', 'created_at')
    sort_order_str = args.get('sort_order', 'desc')
    sort_order = -1 if sort_order_str == 'desc' else 1

    valid_sort_fields = ['cvss_score', 'patch_due_date', 'created_at', 'severity', 'status', 'vulnerability_title']
    if sort_by not in valid_sort_fields:
        sort_by = 'created_at'

    # --- Cursor-based (keyset) pagination ---
    after = args.get('after')
    if after and validate_object_id(after):
        if sort_order == -1:
            query['_id'] = {"$lt": ObjectId(after)}
        else:
            query['_id'] = {"$gt": ObjectId(after)}

        cursor = db.vulnerabilities.find(query).sort("_id", sort_order).limit(per_page)
        vulnerabilities = [serialize_doc(doc) for doc in cursor]
        total_count = db.vulnerabilities.count_documents(
            {k: v for k, v in query.items() if k != '_id'}
        )

        return jsonify({
            "status": "success",
            "data": vulnerabilities,
            "pagination": {
                "per_page": per_page,
                "total": total_count,
                "next_after": vulnerabilities[-1]['_id'] if vulnerabilities else None,
            }
        }), 200

    # --- Standard skip/limit pagination ---
    total_count = db.vulnerabilities.count_documents(query)
    total_pages = math.ceil(total_count / per_page) if total_count > 0 else 1

    skip = (page - 1) * per_page
    cursor = db.vulnerabilities.find(query).sort(sort_by, sort_order).skip(skip).limit(per_page)

    vulnerabilities = [serialize_doc(doc) for doc in cursor]

    return jsonify({
        "status": "success",
        "data": vulnerabilities,
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total_count,
            "pages": total_pages,
        }
    }), 200


@vulnerabilities_bp.route('/<vuln_id>', methods=['GET'])
def get_vulnerability(vuln_id: str):
    """Retrieve a single vulnerability by ID."""
    if not validate_object_id(vuln_id):
        return jsonify({"status": "error", "message": "Invalid ObjectId format", "code": 422}), 422

    db = get_db()
    vuln = db.vulnerabilities.find_one({"_id": ObjectId(vuln_id)})

    if not vuln:
        return jsonify({"status": "error", "message": "Vulnerability not found", "code": 404}), 404

    return jsonify({"status": "success", "data": serialize_doc(vuln)}), 200


@vulnerabilities_bp.route('/', methods=['POST'])
@token_required
@role_required('admin', 'analyst')
def create_vulnerability(current_user: dict):
    """Create a new vulnerability record."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "message": "Request body must be valid JSON", "code": 400}), 400

    is_valid, error_msg = validate_vulnerability_input(data, is_update=False)
    if not is_valid:
        return jsonify({"status": "error", "message": error_msg, "code": 422}), 422

    now = utcnow()

    vuln_doc = {
        "vulnerability_title": data['vulnerability_title'].strip(),
        "description": data['description'].strip(),
        "cve_id": data.get('cve_id', '').strip() or None,
        "severity": data['severity'],
        "status": data['status'],
        "cvss_score": float(data['cvss_score']),
        "asset_name": data['asset_name'].strip(),
        "asset_type": data['asset_type'],
        "vulnerability_type": data['vulnerability_type'],
        "discovery_method": data['discovery_method'],
        "department": data['department'].strip(),
        "affected_versions": data.get('affected_versions', []),
        "attack_vector": data.get('attack_vector'),
        "exploitability": data.get('exploitability'),
        "patch_due_date": parse_iso_date(data.get('patch_due_date')),
        "patch_applied": data.get('patch_applied', False),
        "assigned_to": data.get('assigned_to', '').strip() or None,
        "reported_by": data['reported_by'].strip(),
        "risk_score": calculate_risk_score(
            float(data['cvss_score']),
            data.get('exploitability'),
            data['severity'],
        ),
        "remediation_steps": [],
        "activity_log": [],
        "location": _build_geojson(data.get('location')),
        "created_at": now,
        "updated_at": now,
        "created_by": current_user['username'],
    }

    db = get_db()
    result = db.vulnerabilities.insert_one(vuln_doc)
    vuln_doc['_id'] = result.inserted_id

    return jsonify({
        "status": "success",
        "data": serialize_doc(vuln_doc),
        "message": "Vulnerability created successfully"
    }), 201


@vulnerabilities_bp.route('/bulk', methods=['POST'])
@token_required
@role_required('admin', 'analyst')
def bulk_create_vulnerabilities(current_user: dict):
    """Create multiple vulnerability records in a single request using insert_many.

    Expects a JSON body with a ``vulnerabilities`` array (2–50 items).
    Each item is validated individually.  If any item fails validation the
    entire batch is rejected with a 422 listing per-item errors.

    Returns 201 with the list of created documents.
    """
    data = request.get_json(silent=True)
    if not data or not isinstance(data.get('vulnerabilities'), list):
        return jsonify({
            "status": "error",
            "message": "Request body must contain a 'vulnerabilities' array",
            "code": 400
        }), 400

    items = data['vulnerabilities']

    if len(items) < 2:
        return jsonify({
            "status": "error",
            "message": "Bulk create requires at least 2 items",
            "code": 400
        }), 400

    if len(items) > 50:
        return jsonify({
            "status": "error",
            "message": "Bulk create is limited to 50 items per request",
            "code": 400
        }), 400

    # Validate every item first — fail-fast on the whole batch
    item_errors = {}
    for idx, item in enumerate(items):
        if not isinstance(item, dict):
            item_errors[idx] = "Item must be a JSON object"
            continue
        is_valid, error_msg = validate_vulnerability_input(item, is_update=False)
        if not is_valid:
            item_errors[idx] = error_msg

    if item_errors:
        return jsonify({
            "status": "error",
            "message": "Validation failed for one or more items",
            "errors": {str(k): v for k, v in item_errors.items()},
            "code": 422
        }), 422

    now = utcnow()
    docs = []
    for item in items:
        docs.append({
            "vulnerability_title": item['vulnerability_title'].strip(),
            "description": item['description'].strip(),
            "cve_id": item.get('cve_id', '').strip() or None,
            "severity": item['severity'],
            "status": item['status'],
            "cvss_score": float(item['cvss_score']),
            "asset_name": item['asset_name'].strip(),
            "asset_type": item['asset_type'],
            "vulnerability_type": item['vulnerability_type'],
            "discovery_method": item['discovery_method'],
            "department": item['department'].strip(),
            "affected_versions": item.get('affected_versions', []),
            "attack_vector": item.get('attack_vector'),
            "exploitability": item.get('exploitability'),
            "patch_due_date": parse_iso_date(item.get('patch_due_date')),
            "patch_applied": item.get('patch_applied', False),
            "assigned_to": item.get('assigned_to', '').strip() or None,
            "reported_by": item['reported_by'].strip(),
            "risk_score": calculate_risk_score(
                float(item['cvss_score']),
                item.get('exploitability'),
                item['severity'],
            ),
            "remediation_steps": [],
            "activity_log": [],
            "location": _build_geojson(item.get('location')),
            "created_at": now,
            "updated_at": now,
            "created_by": current_user['username'],
        })

    db = get_db()
    result = db.vulnerabilities.insert_many(docs)

    # Attach inserted IDs back to docs
    for doc, oid in zip(docs, result.inserted_ids):
        doc['_id'] = oid

    return jsonify({
        "status": "success",
        "data": [serialize_doc(d) for d in docs],
        "message": f"{len(docs)} vulnerabilities created successfully"
    }), 201


@vulnerabilities_bp.route('/<vuln_id>', methods=['PUT'])
@token_required
@role_required('admin', 'analyst')
def update_vulnerability(current_user: dict, vuln_id: str):
    """Update an existing vulnerability."""
    if not validate_object_id(vuln_id):
        return jsonify({"status": "error", "message": "Invalid ObjectId format", "code": 422}), 422

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "message": "Request body must be valid JSON", "code": 400}), 400

    is_valid, error_msg = validate_vulnerability_input(data, is_update=True)
    if not is_valid:
        return jsonify({"status": "error", "message": error_msg, "code": 422}), 422

    db = get_db()
    existing = db.vulnerabilities.find_one({"_id": ObjectId(vuln_id)})
    if not existing:
        return jsonify({"status": "error", "message": "Vulnerability not found", "code": 404}), 404

    # Build update dict only with provided fields
    update_fields = {}
    string_fields = ['vulnerability_title', 'description', 'cve_id', 'asset_name', 'department',
                     'assigned_to', 'reported_by']
    for field in string_fields:
        if field in data:
            update_fields[field] = data[field].strip() if isinstance(data[field], str) else data[field]

    enum_fields = ['severity', 'status', 'asset_type', 'vulnerability_type',
                   'discovery_method', 'attack_vector', 'exploitability']
    for field in enum_fields:
        if field in data:
            update_fields[field] = data[field]

    if 'cvss_score' in data:
        update_fields['cvss_score'] = float(data['cvss_score'])

    if 'patch_applied' in data:
        update_fields['patch_applied'] = data['patch_applied']

    if 'affected_versions' in data:
        update_fields['affected_versions'] = data['affected_versions']

    if 'patch_due_date' in data:
        update_fields['patch_due_date'] = parse_iso_date(data['patch_due_date'])

    if 'location' in data:
        update_fields['location'] = _build_geojson(data.get('location'))

    update_fields['updated_at'] = utcnow()

    # Recalculate risk score if relevant fields changed
    cvss = update_fields.get('cvss_score', existing.get('cvss_score', 0))
    exploit = update_fields.get('exploitability', existing.get('exploitability'))
    sev = update_fields.get('severity', existing.get('severity'))
    update_fields['risk_score'] = calculate_risk_score(cvss, exploit, sev)

    db.vulnerabilities.update_one(
        {"_id": ObjectId(vuln_id)},
        {"$set": update_fields}
    )

    updated_vuln = db.vulnerabilities.find_one({"_id": ObjectId(vuln_id)})
    return jsonify({
        "status": "success",
        "data": serialize_doc(updated_vuln),
        "message": "Vulnerability updated successfully"
    }), 200


@vulnerabilities_bp.route('/<vuln_id>', methods=['DELETE'])
@token_required
@role_required('admin')
def delete_vulnerability(current_user: dict, vuln_id: str):
    """Delete a vulnerability permanently."""
    if not validate_object_id(vuln_id):
        return jsonify({"status": "error", "message": "Invalid ObjectId format", "code": 422}), 422

    db = get_db()
    result = db.vulnerabilities.delete_one({"_id": ObjectId(vuln_id)})

    if result.deleted_count == 0:
        return jsonify({"status": "error", "message": "Vulnerability not found", "code": 404}), 404

    return '', 204


# ── Geospatial helpers & endpoint ────────────────────────────────────

def _build_geojson(loc: dict | None) -> dict | None:
    """Convert a location payload into a GeoJSON Point document.

    Accepts either ``{"type": "Point", "coordinates": [lng, lat]}``
    (raw GeoJSON) or a convenience object ``{"lng": ..., "lat": ...}``.

    Returns:
        GeoJSON Point dict or *None* if the input is invalid / absent.
    """
    if not loc or not isinstance(loc, dict):
        return None

    if loc.get('type') == 'Point' and isinstance(loc.get('coordinates'), list):
        coords = loc['coordinates']
        if len(coords) >= 2 and all(isinstance(c, (int, float)) for c in coords[:2]):
            return {"type": "Point", "coordinates": [float(coords[0]), float(coords[1])]}

    if 'lng' in loc and 'lat' in loc:
        try:
            return {
                "type": "Point",
                "coordinates": [float(loc['lng']), float(loc['lat'])]
            }
        except (ValueError, TypeError):
            return None

    return None


@vulnerabilities_bp.route('/nearby', methods=['GET'])
def nearby_vulnerabilities():
    """Find vulnerabilities with assets near a geographic point.

    Query parameters:
        lng (float): Longitude of reference point.
        lat (float): Latitude of reference point.
        radius (float): Search radius in **kilometres** (default 50).
        limit (int): Maximum results (default 10, max 100).

    Uses MongoDB ``$geoNear`` aggregation stage with a ``2dsphere`` index.
    """
    args = request.args

    try:
        lng = float(args['lng'])
        lat = float(args['lat'])
    except (KeyError, ValueError, TypeError):
        return jsonify({
            "status": "error",
            "message": "'lng' and 'lat' query parameters are required and must be numbers",
            "code": 400
        }), 400

    try:
        radius_km = float(args.get('radius', 50))
    except (ValueError, TypeError):
        radius_km = 50.0

    try:
        limit = min(int(args.get('limit', 10)), 100)
    except (ValueError, TypeError):
        limit = 10

    db = get_db()

    pipeline = [
        {"$geoNear": {
            "near": {"type": "Point", "coordinates": [lng, lat]},
            "distanceField": "distance_metres",
            "maxDistance": radius_km * 1000,  # convert km → m
            "spherical": True,
        }},
        {"$limit": limit},
        {"$project": {
            "vulnerability_title": 1,
            "severity": 1,
            "cvss_score": 1,
            "asset_name": 1,
            "department": 1,
            "location": 1,
            "distance_km": {"$round": [{"$divide": ["$distance_metres", 1000]}, 2]},
        }},
    ]

    result = list(db.vulnerabilities.aggregate(pipeline))
    return jsonify({
        "status": "success",
        "data": [serialize_doc(r) for r in result]
    }), 200
