# Routes

API endpoint definitions organised into **6 Flask Blueprints**. All routes are registered in `__init__.py` via `register_blueprints(app)`.

## Blueprint Registry

| Blueprint | Prefix | Module | Endpoints | Description |
|-----------|--------|--------|:---------:|-------------|
| `auth_bp` | `/api/v1/auth` | `auth/` | 7 | Registration, login, logout, profile, refresh, change-password |
| `vulnerabilities_bp` | `/api/v1/vulnerabilities` | `vulnerabilities/` | 7 | Full CRUD + bulk create + geospatial + advanced filters |
| `remediation_bp` | `/api/v1/vulnerabilities` | `remediation/` | 5 | Sub-document CRUD for remediation steps ($push, $pull, positional $) |
| `activity_log_bp` | `/api/v1/vulnerabilities` | `activity_log/` | 4 | Sub-document CRUD for audit trail entries |
| `analytics_bp` | `/api/v1/analytics` | `analytics/` | 11 | Aggregation pipeline endpoints + $out report generation |
| `admin_bp` | `/api/v1/admin` | `admin/` | 5 | User management (list, details, role, status, delete) |

## Folder Structure

Each route module follows the same pattern:

```
routes/
├── __init__.py           # register_blueprints(app) — imports all blueprints
├── auth/
│   ├── __init__.py       # Exports auth_bp
│   ├── routes.py         # Endpoint handlers
│   └── validation.py     # Input validation for auth-specific fields
├── vulnerabilities/
│   ├── __init__.py
│   ├── routes.py
│   └── validation.py
├── remediation/
│   ├── __init__.py
│   ├── routes.py
│   └── validation.py
├── activity_log/
│   ├── __init__.py
│   ├── routes.py
│   └── validation.py
├── analytics/
│   ├── __init__.py
│   └── routes.py
└── admin/
    ├── __init__.py
    └── routes.py
```

## Common Patterns

- **Decorators:** `@token_required` for authentication, `@role_required('admin', 'analyst')` for authorisation
- **Database access:** `db = get_db()` from `utils.helpers`
- **Serialisation:** `serialize_doc(doc)` converts ObjectId → string, datetime → ISO string
- **Validation:** Each module's `validation.py` validates input and returns error list
- **Responses:** Consistent `{"status": "success/error", "data": ..., "message": ...}` format
