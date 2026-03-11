"""Input validation for vulnerability endpoints."""

from utils.validators import (
    validate_string, validate_enum, validate_number, validate_date,
    validate_cve_id,
    VALID_SEVERITIES, VALID_STATUSES, VALID_ASSET_TYPES,
    VALID_ATTACK_VECTORS, VALID_EXPLOITABILITIES,
    VALID_VULNERABILITY_TYPES, VALID_DISCOVERY_METHODS,
)


def validate_vulnerability_input(data: dict, is_update: bool = False) -> tuple[bool, str]:
    """Validate vulnerability creation or update input.

    Args:
        data: Request body dictionary.
        is_update: If True, fields are optional (partial update).

    Returns:
        Tuple of (is_valid, error_message).
    """
    errors = []

    required = not is_update

    # Required fields
    if 'vulnerability_title' in data or required:
        errors.extend(validate_string(data.get('vulnerability_title'), 'vulnerability_title', min_len=5, max_len=200, required=required))
    if 'description' in data or required:
        errors.extend(validate_string(data.get('description'), 'description', min_len=10, max_len=5000, required=required))
    if 'severity' in data or required:
        errors.extend(validate_enum(data.get('severity'), 'severity', VALID_SEVERITIES, required=required))
    if 'status' in data or required:
        errors.extend(validate_enum(data.get('status'), 'status', VALID_STATUSES, required=required))
    if 'cvss_score' in data or required:
        errors.extend(validate_number(data.get('cvss_score'), 'cvss_score', min_val=0, max_val=10, required=required))
    if 'asset_name' in data or required:
        errors.extend(validate_string(data.get('asset_name'), 'asset_name', min_len=1, max_len=200, required=required))
    if 'asset_type' in data or required:
        errors.extend(validate_enum(data.get('asset_type'), 'asset_type', VALID_ASSET_TYPES, required=required))
    if 'vulnerability_type' in data or required:
        errors.extend(validate_enum(data.get('vulnerability_type'), 'vulnerability_type', VALID_VULNERABILITY_TYPES, required=required))
    if 'discovery_method' in data or required:
        errors.extend(validate_enum(data.get('discovery_method'), 'discovery_method', VALID_DISCOVERY_METHODS, required=required))
    if 'department' in data or required:
        errors.extend(validate_string(data.get('department'), 'department', min_len=1, max_len=100, required=required))
    if 'reported_by' in data or required:
        errors.extend(validate_string(data.get('reported_by'), 'reported_by', min_len=1, max_len=100, required=required))

    # Optional fields with validation
    if 'cve_id' in data and data['cve_id']:
        errors.extend(validate_cve_id(data.get('cve_id')))
    if 'attack_vector' in data and data['attack_vector']:
        errors.extend(validate_enum(data.get('attack_vector'), 'attack_vector', VALID_ATTACK_VECTORS, required=False))
    if 'exploitability' in data and data['exploitability']:
        errors.extend(validate_enum(data.get('exploitability'), 'exploitability', VALID_EXPLOITABILITIES, required=False))
    if 'patch_due_date' in data and data['patch_due_date']:
        errors.extend(validate_date(data.get('patch_due_date'), 'patch_due_date'))
    if 'assigned_to' in data and data['assigned_to']:
        errors.extend(validate_string(data.get('assigned_to'), 'assigned_to', min_len=1, max_len=100, required=False))

    # Boolean validation
    if 'patch_applied' in data and not isinstance(data['patch_applied'], bool):
        errors.append("'patch_applied' must be a boolean")

    # Array validation
    if 'affected_versions' in data:
        if not isinstance(data['affected_versions'], list):
            errors.append("'affected_versions' must be an array")
        elif not all(isinstance(v, str) for v in data['affected_versions']):
            errors.append("'affected_versions' must be an array of strings")

    if errors:
        return False, "; ".join(errors)
    return True, ""
