"""Input validation for remediation step endpoints."""

from utils.validators import (
    validate_string, validate_enum, validate_number, validate_date,
    VALID_REMEDIATION_STATUSES,
)


def validate_remediation_step_input(data: dict, is_update: bool = False) -> tuple[bool, str]:
    """Validate remediation step creation or update input.

    Args:
        data: Request body dictionary.
        is_update: If True, fields are optional (partial update).

    Returns:
        Tuple of (is_valid, error_message).
    """
    errors = []
    required = not is_update

    if 'step_number' in data or required:
        errors.extend(validate_number(
            data.get('step_number'), 'step_number', min_val=1, required=required
        ))
        if data.get('step_number') is not None and isinstance(data['step_number'], (int, float)):
            if data['step_number'] != int(data['step_number']):
                errors.append("'step_number' must be a positive integer")

    if 'step_description' in data or required:
        errors.extend(validate_string(
            data.get('step_description'), 'step_description', min_len=5, max_len=1000, required=required
        ))

    if 'status' in data or required:
        errors.extend(validate_enum(
            data.get('status'), 'status', VALID_REMEDIATION_STATUSES, required=required
        ))

    if 'recommended_by' in data and data['recommended_by']:
        errors.extend(validate_string(
            data['recommended_by'], 'recommended_by', min_len=1, max_len=100, required=False
        ))

    if 'due_date' in data and data['due_date']:
        errors.extend(validate_date(data['due_date'], 'due_date'))

    if 'notes' in data and data['notes']:
        errors.extend(validate_string(
            data['notes'], 'notes', min_len=0, max_len=2000, required=False
        ))

    if errors:
        return False, "; ".join(errors)
    return True, ""
