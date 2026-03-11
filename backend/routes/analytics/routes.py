"""Analytics aggregation pipeline routes."""

from datetime import datetime, timezone
from flask import request, jsonify

from middleware.auth_middleware import token_required
from middleware.rbac_middleware import role_required
from utils.helpers import get_db, serialize_doc, utcnow
from routes.analytics import analytics_bp


@analytics_bp.route('/severity-distribution', methods=['GET'])
@token_required
def severity_distribution(current_user: dict):
    """Count of vulnerabilities grouped by severity level."""
    db = get_db()

    pipeline = [
        {"$group": {
            "_id": "$severity",
            "count": {"$sum": 1},
            "avg_cvss": {"$avg": "$cvss_score"}
        }},
        {"$project": {
            "severity": "$_id",
            "count": 1,
            "avg_cvss": {"$round": ["$avg_cvss", 2]},
            "_id": 0
        }},
        {"$sort": {"count": -1}}
    ]

    result = list(db.vulnerabilities.aggregate(pipeline))
    return jsonify({"status": "success", "data": result}), 200


@analytics_bp.route('/department-risk', methods=['GET'])
@token_required
def department_risk(current_user: dict):
    """Risk exposure analysis grouped by department."""
    db = get_db()

    pipeline = [
        {"$group": {
            "_id": "$department",
            "total_vulnerabilities": {"$sum": 1},
            "critical_count": {
                "$sum": {"$cond": [{"$eq": ["$severity", "Critical"]}, 1, 0]}
            },
            "high_count": {
                "$sum": {"$cond": [{"$eq": ["$severity", "High"]}, 1, 0]}
            },
            "avg_cvss": {"$avg": "$cvss_score"},
            "max_cvss": {"$max": "$cvss_score"}
        }},
        {"$project": {
            "department": "$_id",
            "total_vulnerabilities": 1,
            "critical_count": 1,
            "high_count": 1,
            "avg_cvss": {"$round": ["$avg_cvss", 2]},
            "max_cvss": 1,
            "risk_score": {
                "$round": [{
                    "$add": [
                        {"$multiply": ["$critical_count", 4]},
                        {"$multiply": ["$high_count", 2]},
                        "$avg_cvss"
                    ]
                }, 2]
            },
            "_id": 0
        }},
        {"$sort": {"risk_score": -1}}
    ]

    result = list(db.vulnerabilities.aggregate(pipeline))
    return jsonify({"status": "success", "data": result}), 200


@analytics_bp.route('/overdue-patches', methods=['GET'])
@token_required
def overdue_patches(current_user: dict):
    """List of vulnerabilities with overdue patch deadlines."""
    db = get_db()
    args = request.args
    now = utcnow()

    match_stage = {
        "patch_applied": False,
        "patch_due_date": {"$lt": now},
        "status": {"$nin": ["Patched", "Accepted Risk"]}
    }

    if args.get('severity'):
        match_stage['severity'] = args['severity']
    if args.get('department'):
        match_stage['department'] = args['department']

    pipeline = [
        {"$match": match_stage},
        {"$project": {
            "vulnerability_title": 1,
            "severity": 1,
            "cvss_score": 1,
            "asset_name": 1,
            "department": 1,
            "patch_due_date": 1,
            "days_overdue": {
                "$dateDiff": {
                    "startDate": "$patch_due_date",
                    "endDate": now,
                    "unit": "day"
                }
            }
        }},
        {"$sort": {"days_overdue": -1}}
    ]

    result = list(db.vulnerabilities.aggregate(pipeline))
    return jsonify({"status": "success", "data": [serialize_doc(r) for r in result]}), 200


@analytics_bp.route('/patch-compliance', methods=['GET'])
@token_required
def patch_compliance(current_user: dict):
    """Overall patch compliance rate statistics."""
    db = get_db()

    pipeline = [
        {"$group": {
            "_id": None,
            "total": {"$sum": 1},
            "patched": {
                "$sum": {"$cond": ["$patch_applied", 1, 0]}
            },
            "unpatched": {
                "$sum": {"$cond": ["$patch_applied", 0, 1]}
            }
        }},
        {"$project": {
            "_id": 0,
            "total": 1,
            "patched": 1,
            "unpatched": 1,
            "compliance_rate": {
                "$round": [
                    {"$cond": [
                        {"$eq": ["$total", 0]},
                        0,
                        {"$multiply": [
                            {"$divide": ["$patched", "$total"]},
                            100
                        ]}
                    ]},
                    2
                ]
            }
        }}
    ]

    result = list(db.vulnerabilities.aggregate(pipeline))
    data = result[0] if result else {"total": 0, "patched": 0, "unpatched": 0, "compliance_rate": 0}
    return jsonify({"status": "success", "data": data}), 200


@analytics_bp.route('/vulnerability-trends', methods=['GET'])
@token_required
def vulnerability_trends(current_user: dict):
    """Vulnerability count trend grouped by month."""
    db = get_db()
    args = request.args

    try:
        months = int(args.get('months', 12))
    except (ValueError, TypeError):
        months = 12

    # Calculate the start date as N months ago
    now = utcnow()
    start_year = now.year
    start_month = now.month - months
    while start_month <= 0:
        start_month += 12
        start_year -= 1
    from datetime import datetime
    start_date = datetime(start_year, start_month, 1)

    pipeline = [
        {"$match": {"created_at": {"$gte": start_date}}},
        {"$group": {
            "_id": {
                "year": {"$year": "$created_at"},
                "month": {"$month": "$created_at"}
            },
            "count": {"$sum": 1}
        }},
        {"$sort": {"_id.year": 1, "_id.month": 1}},
        {"$project": {
            "_id": 0,
            "year": "$_id.year",
            "month": "$_id.month",
            "count": 1
        }}
    ]

    result = list(db.vulnerabilities.aggregate(pipeline))
    return jsonify({"status": "success", "data": result}), 200


@analytics_bp.route('/top-affected-assets', methods=['GET'])
@token_required
def top_affected_assets(current_user: dict):
    """Top N assets ranked by vulnerability count."""
    db = get_db()
    args = request.args

    try:
        limit = min(int(args.get('limit', 10)), 100)
    except (ValueError, TypeError):
        limit = 10

    pipeline = [
        {"$group": {
            "_id": {
                "asset_name": "$asset_name",
                "asset_type": "$asset_type"
            },
            "count": {"$sum": 1},
            "avg_cvss": {"$avg": "$cvss_score"}
        }},
        {"$project": {
            "_id": 0,
            "asset_name": "$_id.asset_name",
            "asset_type": "$_id.asset_type",
            "count": 1,
            "avg_cvss": {"$round": ["$avg_cvss", 2]}
        }},
        {"$sort": {"count": -1}},
        {"$limit": limit}
    ]

    result = list(db.vulnerabilities.aggregate(pipeline))
    return jsonify({"status": "success", "data": result}), 200


@analytics_bp.route('/mean-time-to-remediation', methods=['GET'])
@token_required
def mean_time_to_remediation(current_user: dict):
    """Average days to resolve vulnerabilities by severity."""
    db = get_db()

    pipeline = [
        {"$match": {
            "status": {"$in": ["Patched", "Accepted Risk"]},
            "updated_at": {"$exists": True}
        }},
        {"$project": {
            "severity": 1,
            "resolution_days": {
                "$dateDiff": {
                    "startDate": "$created_at",
                    "endDate": "$updated_at",
                    "unit": "day"
                }
            }
        }},
        {"$group": {
            "_id": "$severity",
            "avg_days": {"$avg": "$resolution_days"},
            "min_days": {"$min": "$resolution_days"},
            "max_days": {"$max": "$resolution_days"},
            "count": {"$sum": 1}
        }},
        {"$project": {
            "severity": "$_id",
            "avg_days": {"$round": ["$avg_days", 1]},
            "min_days": 1,
            "max_days": 1,
            "count": 1,
            "_id": 0
        }},
        {"$sort": {"avg_days": -1}}
    ]

    result = list(db.vulnerabilities.aggregate(pipeline))
    return jsonify({"status": "success", "data": result}), 200


@analytics_bp.route('/risk-scores', methods=['GET'])
@token_required
@role_required('admin', 'analyst')
def risk_scores(current_user: dict):
    """Calculated risk scores per vulnerability."""
    db = get_db()
    args = request.args

    match_stage = {}
    if args.get('min_score'):
        try:
            match_stage['risk_score'] = {"$gte": float(args['min_score'])}
        except ValueError:
            pass
    if args.get('department'):
        match_stage['department'] = args['department']

    pipeline = [
        {"$match": match_stage} if match_stage else {"$match": {}},
        {"$project": {
            "vulnerability_title": 1,
            "severity": 1,
            "cvss_score": 1,
            "exploitability": 1,
            "asset_name": 1,
            "department": 1,
            "risk_score": 1,
            "status": 1
        }},
        {"$sort": {"risk_score": -1}}
    ]

    result = list(db.vulnerabilities.aggregate(pipeline))
    return jsonify({"status": "success", "data": [serialize_doc(r) for r in result]}), 200


@analytics_bp.route('/summary', methods=['GET'])
@token_required
def dashboard_summary(current_user: dict):
    """Dashboard summary KPIs (counts, rates, averages)."""
    db = get_db()

    pipeline = [
        {"$facet": {
            "status_counts": [
                {"$group": {
                    "_id": "$status",
                    "count": {"$sum": 1}
                }}
            ],
            "severity_counts": [
                {"$group": {
                    "_id": "$severity",
                    "count": {"$sum": 1}
                }}
            ],
            "totals": [
                {"$group": {
                    "_id": None,
                    "total_vulnerabilities": {"$sum": 1},
                    "avg_cvss": {"$avg": "$cvss_score"},
                    "patched": {
                        "$sum": {"$cond": ["$patch_applied", 1, 0]}
                    },
                    "total_with_deadline": {
                        "$sum": {"$cond": [
                            {"$and": [
                                {"$ne": ["$patch_due_date", None]},
                                {"$eq": ["$patch_applied", False]},
                                {"$lt": ["$patch_due_date", utcnow()]}
                            ]},
                            1, 0
                        ]}
                    }
                }}
            ]
        }}
    ]

    result = list(db.vulnerabilities.aggregate(pipeline))

    if not result:
        data = {
            "total_vulnerabilities": 0,
            "open_count": 0,
            "in_progress_count": 0,
            "resolved_count": 0,
            "closed_count": 0,
            "critical_count": 0,
            "high_count": 0,
            "avg_cvss": 0,
            "compliance_rate": 0,
            "overdue_count": 0,
        }
    else:
        facets = result[0]

        # Parse status counts
        status_map = {item['_id']: item['count'] for item in facets.get('status_counts', [])}
        severity_map = {item['_id']: item['count'] for item in facets.get('severity_counts', [])}
        totals = facets.get('totals', [{}])[0] if facets.get('totals') else {}

        total = totals.get('total_vulnerabilities', 0)
        patched = totals.get('patched', 0)
        compliance_rate = round((patched / total * 100), 2) if total > 0 else 0

        data = {
            "total_vulnerabilities": total,
            "open_count": status_map.get('Open', 0),
            "in_progress_count": status_map.get('In Progress', 0),
            "resolved_count": status_map.get('Patched', 0),
            "closed_count": status_map.get('Accepted Risk', 0),
            "critical_count": severity_map.get('Critical', 0),
            "high_count": severity_map.get('High', 0),
            "avg_cvss": round(totals.get('avg_cvss', 0) or 0, 2),
            "compliance_rate": compliance_rate,
            "overdue_count": totals.get('total_with_deadline', 0),
        }

    return jsonify({"status": "success", "data": data}), 200


@analytics_bp.route('/generate-report', methods=['POST'])
@token_required
@role_required('admin', 'analyst')
def generate_report(current_user: dict):
    """Run a comprehensive aggregation pipeline and persist the results
    to a ``reports`` collection using the ``$out`` stage.

    The pipeline groups vulnerabilities by department and severity,
    calculates summary statistics, and writes the output as a snapshot
    report that can be retrieved later.
    """
    db = get_db()

    pipeline = [
        {"$group": {
            "_id": {
                "department": "$department",
                "severity": "$severity"
            },
            "count": {"$sum": 1},
            "avg_cvss": {"$avg": "$cvss_score"},
            "max_cvss": {"$max": "$cvss_score"},
            "patched": {"$sum": {"$cond": ["$patch_applied", 1, 0]}},
            "unpatched": {"$sum": {"$cond": ["$patch_applied", 0, 1]}},
        }},
        {"$project": {
            "_id": 0,
            "department": "$_id.department",
            "severity": "$_id.severity",
            "count": 1,
            "avg_cvss": {"$round": ["$avg_cvss", 2]},
            "max_cvss": 1,
            "patched": 1,
            "unpatched": 1,
        }},
        {"$sort": {"department": 1, "severity": 1}},
        {"$out": "reports"},
    ]

    db.vulnerabilities.aggregate(pipeline)

    # Read back the generated report collection
    report_docs = list(db.reports.find({}))

    return jsonify({
        "status": "success",
        "data": [serialize_doc(d) for d in report_docs],
        "message": f"Report generated – {len(report_docs)} rows written to 'reports' collection"
    }), 201


@analytics_bp.route('/reports', methods=['GET'])
@token_required
def get_reports(current_user: dict):
    """Retrieve the latest generated report from the ``reports`` collection."""
    db = get_db()
    docs = list(db.reports.find({}))

    if not docs:
        return jsonify({
            "status": "success",
            "data": [],
            "message": "No reports generated yet. POST /analytics/generate-report first."
        }), 200

    return jsonify({
        "status": "success",
        "data": [serialize_doc(d) for d in docs]
    }), 200
