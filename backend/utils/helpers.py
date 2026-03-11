"""Utility helper functions for the VulnGuard application."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from bson import ObjectId
from bson.errors import InvalidId

if TYPE_CHECKING:
    from pymongo.database import Database

from flask import current_app


def get_db() -> "Database[dict]":
    """Return the MongoDB database instance attached to the current Flask app.

    This helper exists so that Pylance / Pyright can resolve the type of
    ``current_app.db`` without a ``reportAttributeAccessIssue`` warning.

    Returns:
        The PyMongo ``Database`` object.
    """
    return current_app.extensions["mongo_db"]


def validate_object_id(id_string: str) -> bool:
    """Validate that a string is a valid MongoDB ObjectId.

    Args:
        id_string: String to validate.

    Returns:
        True if valid ObjectId, False otherwise.
    """
    try:
        ObjectId(id_string)
        return True
    except (InvalidId, TypeError):
        return False


def serialize_doc(doc: dict | None) -> dict:
    """Convert a MongoDB document to a JSON-serializable dict.

    Converts ObjectId fields to strings and datetime fields to ISO format.

    Args:
        doc: MongoDB document dictionary, or None.

    Returns:
        JSON-serializable dictionary (empty dict if *doc* is None).
    """
    if doc is None:
        return {}

    result = {}
    for key, value in doc.items():
        if isinstance(value, ObjectId):
            result[key] = str(value)
        elif isinstance(value, datetime):
            result[key] = value.isoformat() + 'Z' if value.tzinfo is None else value.isoformat()
        elif isinstance(value, list):
            result[key] = [
                serialize_doc(item) if isinstance(item, dict) else
                str(item) if isinstance(item, ObjectId) else
                item.isoformat() + 'Z' if isinstance(item, datetime) and item.tzinfo is None else
                item.isoformat() if isinstance(item, datetime) else
                item
                for item in value
            ]
        elif isinstance(value, dict):
            result[key] = serialize_doc(value)
        else:
            result[key] = value
    return result


def get_pagination_params(args: dict, default_per_page: int = 10, max_per_page: int = 100) -> tuple[int, int]:
    """Extract and validate pagination parameters from request args.

    Args:
        args: Request query parameters.
        default_per_page: Default items per page.
        max_per_page: Maximum allowed items per page.

    Returns:
        Tuple of (page, per_page).
    """
    try:
        page = max(1, int(args.get('page', 1)))
    except (ValueError, TypeError):
        page = 1

    try:
        per_page = min(max(1, int(args.get('per_page', default_per_page))), max_per_page)
    except (ValueError, TypeError):
        per_page = default_per_page

    return page, per_page


def utcnow() -> datetime:
    """Return the current UTC datetime (timezone-naive for MongoDB compatibility).

    Returns:
        Current UTC datetime.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


def calculate_risk_score(cvss_score: float, exploitability: str | None = None, severity: str | None = None) -> float:
    """Calculate a weighted risk score from CVSS, exploitability and severity.

    Args:
        cvss_score: CVSS score (0-10).
        exploitability: Exploitability level string.
        severity: Severity level string.

    Returns:
        Calculated risk score rounded to 2 decimal places.
    """
    exploit_weights = {
        'Unproven': 1.0,
        'Proof-of-Concept': 2.0,
        'Functional': 3.0,
        'High': 4.0,
    }
    severity_weights = {
        'Informational': 0.5,
        'Low': 1.0,
        'Medium': 2.0,
        'High': 3.0,
        'Critical': 4.0,
    }

    exploit_factor = exploit_weights.get(exploitability, 1.0) if exploitability else 1.0
    severity_factor = severity_weights.get(severity, 1.0) if severity else 1.0

    risk_score = cvss_score * exploit_factor * severity_factor / 4.0
    return round(risk_score, 2)
