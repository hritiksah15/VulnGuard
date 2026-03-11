"""Shared validation logic for the VulnGuard application."""

import re
from datetime import datetime


# Enum constants
VALID_SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Informational']
VALID_STATUSES = ['Open', 'In Progress', 'Patched', 'Accepted Risk']
VALID_ASSET_TYPES = [
    'Server', 'Workstation', 'Network Device', 'Application',
    'Database', 'Cloud Service', 'IoT Device', 'Endpoint'
]
VALID_VULNERABILITY_TYPES = ['Software', 'Configuration', 'Access Control']
VALID_DISCOVERY_METHODS = ['Scan', 'Audit', 'Manual']
VALID_ATTACK_VECTORS = ['Network', 'Adjacent', 'Local', 'Physical']
VALID_EXPLOITABILITIES = ['Unproven', 'Proof-of-Concept', 'Functional', 'High']
VALID_REMEDIATION_STATUSES = ['Pending', 'In Progress', 'Completed', 'Skipped']
VALID_ROLES = ['admin', 'analyst', 'guest']

CVE_ID_PATTERN = re.compile(r'^CVE-\d{4}-\d{4,}$')
EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
PASSWORD_PATTERN = re.compile(
    r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#]).{8,}$'
)


def validate_string(value, field_name: str, min_len: int = 1, max_len: int = 200,
                     required: bool = True) -> list[str]:
    """Validate a string field.

    Args:
        value: Value to validate.
        field_name: Name of the field for error messages.
        min_len: Minimum string length.
        max_len: Maximum string length.
        required: Whether the field is required.

    Returns:
        List of error messages (empty if valid).
    """
    errors = []
    if value is None or value == '':
        if required:
            errors.append(f"'{field_name}' is required")
        return errors

    if not isinstance(value, str):
        errors.append(f"'{field_name}' must be a string")
        return errors

    if len(value) < min_len or len(value) > max_len:
        errors.append(f"'{field_name}' must be between {min_len} and {max_len} characters")

    return errors


def validate_enum(value, field_name: str, valid_values: list[str],
                  required: bool = True) -> list[str]:
    """Validate that a value is one of the allowed enum values.

    Args:
        value: Value to validate.
        field_name: Name of the field for error messages.
        valid_values: List of allowed values.
        required: Whether the field is required.

    Returns:
        List of error messages (empty if valid).
    """
    errors = []
    if value is None or value == '':
        if required:
            errors.append(f"'{field_name}' is required")
        return errors

    if value not in valid_values:
        errors.append(f"'{field_name}' must be one of: {', '.join(valid_values)}")

    return errors


def validate_number(value, field_name: str, min_val: float | None = None,
                    max_val: float | None = None, required: bool = True) -> list[str]:
    """Validate a numeric field.

    Args:
        value: Value to validate.
        field_name: Name of the field for error messages.
        min_val: Minimum allowed value.
        max_val: Maximum allowed value.
        required: Whether the field is required.

    Returns:
        List of error messages (empty if valid).
    """
    errors = []
    if value is None:
        if required:
            errors.append(f"'{field_name}' is required")
        return errors

    if not isinstance(value, (int, float)):
        errors.append(f"'{field_name}' must be a number")
        return errors

    if min_val is not None and value < min_val:
        errors.append(f"'{field_name}' must be at least {min_val}")
    if max_val is not None and value > max_val:
        errors.append(f"'{field_name}' must be at most {max_val}")

    return errors


def validate_date(value, field_name: str, required: bool = False) -> list[str]:
    """Validate an ISO 8601 date string.

    Args:
        value: Value to validate.
        field_name: Name of the field for error messages.
        required: Whether the field is required.

    Returns:
        List of error messages (empty if valid).
    """
    errors = []
    if value is None or value == '':
        if required:
            errors.append(f"'{field_name}' is required")
        return errors

    if not isinstance(value, str):
        errors.append(f"'{field_name}' must be a valid ISO 8601 date string")
        return errors

    try:
        datetime.fromisoformat(value.replace('Z', '+00:00'))
    except (ValueError, AttributeError):
        errors.append(f"'{field_name}' must be a valid ISO 8601 date")

    return errors


def validate_cve_id(value) -> list[str]:
    """Validate a CVE ID format (CVE-YYYY-NNNNN).

    Args:
        value: Value to validate.

    Returns:
        List of error messages (empty if valid).
    """
    if value is None or value == '':
        return []

    if not isinstance(value, str) or not CVE_ID_PATTERN.match(value):
        return ["'cve_id' must be in format CVE-YYYY-NNNNN (e.g., CVE-2025-12345)"]

    return []


def validate_email(value: str) -> list[str]:
    """Validate an email address format.

    Args:
        value: Email string to validate.

    Returns:
        List of error messages (empty if valid).
    """
    if not value or not isinstance(value, str):
        return ["'email' is required and must be a string"]

    if not EMAIL_PATTERN.match(value):
        return ["'email' must be a valid email address"]

    return []


def validate_password(value: str) -> list[str]:
    """Validate password strength.

    Password must be at least 8 characters with uppercase, lowercase,
    digit and special character.

    Args:
        value: Password string to validate.

    Returns:
        List of error messages (empty if valid).
    """
    if not value or not isinstance(value, str):
        return ["'password' is required and must be a string"]

    if len(value) < 8:
        return ["'password' must be at least 8 characters"]

    if not PASSWORD_PATTERN.match(value):
        return [
            "'password' must contain at least one uppercase letter, "
            "one lowercase letter, one digit, and one special character (@$!%*?&#)"
        ]

    return []


def parse_iso_date(value: str) -> datetime | None:
    """Parse an ISO 8601 date string to a datetime object.

    Args:
        value: ISO 8601 date string.

    Returns:
        Parsed datetime object or None if invalid.
    """
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00')).replace(tzinfo=None)
    except (ValueError, AttributeError):
        return None
