# Middleware

Request processing pipeline — decorators and error handlers applied before/after route handlers.

## Files

| File | Export | Description |
|------|--------|-------------|
| `auth_middleware.py` | `@token_required`, `_extract_token()` | JWT authentication decorator. Extracts token from `x-access-token` header, decodes with HS256, checks the `blacklist` collection for revoked tokens. Injects `current_user` dict into the decorated function. |
| `rbac_middleware.py` | `@role_required(*roles)` | Role-based access control decorator. Reads `current_user['role']` (set by `@token_required`) and returns `403 Forbidden` if the role is not in the allowed list. |
| `error_handler.py` | `register_error_handlers(app)` | Registers JSON error handlers for HTTP codes 400, 401, 403, 404, 405, 413, 422, 429, 500, and a catch-all `Exception` handler. All responses use `{"status": "error", "message": "...", "code": N}`. |

## Middleware Chain

```
Incoming Request
  │
  ▼
@token_required          ← Validates JWT, checks blacklist
  │
  ▼
@role_required('admin')  ← Checks user role (optional, per-route)
  │
  ▼
Route Handler            ← Business logic
  │
  ▼
error_handler            ← Catches exceptions, returns JSON errors
```

## Token Extraction

The `_extract_token()` helper reads **only** the `x-access-token` header (no Bearer scheme). It is used by both `@token_required` and the logout endpoint.

## Roles

| Role | Level | Access |
|------|-------|--------|
| `admin` | Highest | Full access — all CRUD, user management, delete |
| `analyst` | Middle | Create/update vulnerabilities, remediation, analytics |
| `guest` | Lowest | Read-only access |
