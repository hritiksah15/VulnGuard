# Auth Routes

**Blueprint:** `auth_bp` — **Prefix:** `/api/v1/auth`

Handles user registration, authentication, token management, and profile operations.

## Endpoints

| Method | Path | Auth | Description |
|--------|------|:----:|-------------|
| `POST` | `/register` | — | Register a new user (username, email, password) |
| `POST` | `/login` | — | Authenticate with email + password, returns JWT |
| `GET` | `/profile` | ✅ | Get current user's profile |
| `PUT` | `/profile` | ✅ | Update profile fields |
| `POST` | `/refresh` | ✅ | Issue a new JWT token (refreshes expiry) |
| `PUT` | `/change-password` | ✅ | Change password (requires current password) |
| `POST` | `/logout` | ✅ | Blacklist current token |

## Token Details

- **Algorithm:** HS256 signed with `SECRET_KEY`
- **Claims:** `user_id`, `username`, `role`, `exp`, `iat`, `jti` (uuid4 for uniqueness)
- **Header:** Sent via `x-access-token` (no Bearer scheme)
- **Blacklisting:** Logout inserts token into `blacklist` collection (TTL auto-expires after 24h)

## Password Requirements

- Minimum 8 characters
- At least one uppercase letter, one lowercase letter, one digit, one special character
- Validated by regex pattern in `utils/validators.py`

## Files

| File | Purpose |
|------|---------|
| `routes.py` | All 7 endpoint handlers |
| `validation.py` | `validate_registration_input()`, `validate_login_input()` |
| `__init__.py` | Exports `auth_bp` Blueprint |
