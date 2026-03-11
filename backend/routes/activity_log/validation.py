"""Input validation for activity log endpoints."""

from utils.validators import validate_string


def validate_activity_log_input(data: dict) -> tuple[bool, str]:
    """Validate activity log entry creation input.

    Args:
        data: Request body dictionary.

    Returns:
        Tuple of (is_valid, error_message).
    """
    errors = []

    errors.extend(validate_string(data.get('action'), 'action', min_len=1, max_len=200, required=True))

    if 'details' in data and data['details']:
        errors.extend(validate_string(data['details'], 'details', min_len=0, max_len=2000, required=False))

    if 'previous_value' in data and data['previous_value']:
        errors.extend(validate_string(data['previous_value'], 'previous_value', min_len=0, max_len=500, required=False))

    if 'new_value' in data and data['new_value']:
        errors.extend(validate_string(data['new_value'], 'new_value', min_len=0, max_len=500, required=False))

    if errors:
        return False, "; ".join(errors)
    return True, ""
