"""Input validation for authentication endpoints."""

from utils.validators import (
    validate_string, validate_email, validate_password
)


def validate_registration_input(data: dict) -> tuple[bool, str]:
    """Validate user registration input.

    Args:
        data: Request body dictionary.

    Returns:
        Tuple of (is_valid, error_message).
    """
    errors = []
    errors.extend(validate_string(data.get('username'), 'username', min_len=3, max_len=50))
    errors.extend(validate_email(data.get('email', '')))
    errors.extend(validate_password(data.get('password', '')))

    if errors:
        return False, "; ".join(errors)
    return True, ""


def validate_login_input(data: dict) -> tuple[bool, str]:
    """Validate login input.

    Args:
        data: Request body dictionary.

    Returns:
        Tuple of (is_valid, error_message).
    """
    errors = []
    if not data.get('email'):
        errors.append("'email' is required")
    if not data.get('password'):
        errors.append("'password' is required")

    if errors:
        return False, "; ".join(errors)
    return True, ""


def validate_profile_update(data: dict) -> tuple[bool, str]:
    """Validate profile update input.

    Args:
        data: Request body dictionary.

    Returns:
        Tuple of (is_valid, error_message).
    """
    errors = []
    if 'username' in data:
        errors.extend(validate_string(data['username'], 'username', min_len=3, max_len=50))
    if 'email' in data:
        errors.extend(validate_email(data['email']))

    if errors:
        return False, "; ".join(errors)
    return True, ""


def validate_change_password(data: dict) -> tuple[bool, str]:
    """Validate change password input.

    Args:
        data: Request body dictionary.

    Returns:
        Tuple of (is_valid, error_message).
    """
    errors = []
    if not data.get('current_password'):
        errors.append("'current_password' is required")
    if not data.get('new_password'):
        errors.append("'new_password' is required")
    else:
        errors.extend(validate_password(data['new_password']))

    if errors:
        return False, "; ".join(errors)
    return True, ""
