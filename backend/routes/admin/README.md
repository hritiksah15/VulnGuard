# Admin Routes

**Blueprint:** `admin_bp` — **Prefix:** `/api/v1/admin`

User management endpoints — all require `admin` role. Includes safety checks to prevent self-demotion, self-deactivation, and self-deletion.

## Endpoints

| Method | Path | Auth | Role | Description |
|--------|------|:----:|:----:|-------------|
| `GET` | `/users` | ✅ | admin | List all users (paginated) |
| `GET` | `/users/:id` | ✅ | admin | Get user details |
| `PUT` | `/users/:id/role` | ✅ | admin | Update user role |
| `PUT` | `/users/:id/status` | ✅ | admin | Activate/deactivate user |
| `DELETE` | `/users/:id` | ✅ | admin | Delete user account |

## Safety Protections

- **No self-demotion** — Admin cannot change their own role
- **No self-deactivation** — Admin cannot deactivate their own account
- **No self-deletion** — Admin cannot delete their own account

## Valid Roles

| Role | Description |
|------|-------------|
| `admin` | Full access to all features |
| `analyst` | CRUD on vulnerabilities, remediation, activity logs, analytics |
| `guest` | Read-only access |

## Files

| File | Purpose |
|------|---------|
| `routes.py` | All 5 endpoint handlers |
| `__init__.py` | Exports `admin_bp` Blueprint |
