# VulnGuard – Blueprint Architecture

> **Version:** 1.0  
> **Last Updated:** 2026-03-09

---

## Overview

VulnGuard's backend is structured around **Flask Blueprints** – self-contained
modules that group related routes, validation logic, and business rules. Every
blueprint lives under `backend/routes/` and is registered centrally through
a single `register_blueprints()` helper in `backend/routes/__init__.py`.

### Key Design Principles

| Principle | Description |
|---|---|
| **Single Responsibility** | Each blueprint owns exactly one domain (auth, vulnerabilities, etc.). |
| **Package-based Blueprints** | Every blueprint is a Python package (`__init__.py` + modules). The `Blueprint` object is created in `__init__.py` and routes import it. |
| **Centralised Registration** | `routes/__init__.py` exposes `register_blueprints(app)` – the only entry-point `app.py` needs. |
| **URL Prefix on Blueprint** | `url_prefix` is declared once in the `__init__.py` of each blueprint. Route decorators use relative paths (e.g. `'/'`, `'/<id>'`). |
| **Validation Co-location** | Input validation lives alongside its blueprint in a dedicated `validation.py` module. |

---

## Directory Structure

```
backend/
├── app.py                          # Application factory – calls register_blueprints()
├── config.py                       # Environment-specific config classes
├── routes/
│   ├── __init__.py                 # register_blueprints() – central registration
│   │
│   ├── auth/                       # Authentication & user management
│   │   ├── __init__.py             # Creates auth_bp (prefix: /api/v1/auth)
│   │   ├── routes.py              # Route handlers
│   │   └── validation.py          # Input validation functions
│   │
│   ├── vulnerabilities/            # Vulnerability CRUD
│   │   ├── __init__.py             # Creates vulnerabilities_bp (prefix: /api/v1/vulnerabilities)
│   │   ├── routes.py              # Route handlers
│   │   └── validation.py          # Input validation functions
│   │
│   ├── remediation/                # Remediation steps (sub-document CRUD)
│   │   ├── __init__.py             # Creates remediation_bp (prefix: /api/v1/vulnerabilities)
│   │   ├── routes.py              # Route handlers
│   │   └── validation.py          # Input validation functions
│   │
│   ├── activity_log/               # Activity log entries (sub-document CRUD)
│   │   ├── __init__.py             # Creates activity_log_bp (prefix: /api/v1/vulnerabilities)
│   │   ├── routes.py              # Route handlers
│   │   └── validation.py          # Input validation functions
│   │
│   ├── analytics/                  # Aggregation pipelines & dashboards
│   │   ├── __init__.py             # Creates analytics_bp (prefix: /api/v1/analytics)
│   │   └── routes.py              # Route handlers
│   │
│   └── admin/                      # User administration
│       ├── __init__.py             # Creates admin_bp (prefix: /api/v1/admin)
│       └── routes.py              # Route handlers
│
├── middleware/
│   ├── __init__.py
│   ├── auth_middleware.py          # @token_required decorator
│   ├── rbac_middleware.py          # @role_required decorator
│   └── error_handler.py           # Centralised HTTP error handlers
│
└── utils/
    ├── __init__.py
    ├── helpers.py                  # Serialisation, pagination, risk scoring
    └── validators.py              # Shared validation logic & enum constants
```

---

## Blueprint Reference

### 1. Auth (`auth_bp`)

| Property | Value |
|---|---|
| **Package** | `routes.auth` |
| **URL Prefix** | `/api/v1/auth` |
| **Files** | `__init__.py`, `routes.py`, `validation.py` |

#### Endpoints

| Method | Path | Auth | Role | Description |
|---|---|---|---|---|
| `POST` | `/register` | No | — | Register a new user account |
| `POST` | `/login` | No | — | Authenticate and receive a JWT token |
| `GET` | `/profile` | Yes | Any | Get current user's profile |
| `PUT` | `/profile` | Yes | Any | Update current user's profile |
| `POST` | `/refresh` | Yes | Any | Refresh JWT token |
| `PUT` | `/change-password` | Yes | Any | Change current user's password |

#### Validation Functions (`validation.py`)

- `validate_registration_input(data)` – username, email, password
- `validate_login_input(data)` – email, password
- `validate_profile_update(data)` – optional username, email
- `validate_change_password(data)` – current_password, new_password

---

### 2. Vulnerabilities (`vulnerabilities_bp`)

| Property | Value |
|---|---|
| **Package** | `routes.vulnerabilities` |
| **URL Prefix** | `/api/v1/vulnerabilities` |
| **Files** | `__init__.py`, `routes.py`, `validation.py` |

#### Endpoints

| Method | Path | Auth | Role | Description |
|---|---|---|---|---|
| `GET` | `/` | No | — | List vulnerabilities (paginated, filterable) |
| `GET` | `/<vuln_id>` | No | — | Get single vulnerability by ID |
| `POST` | `/` | Yes | admin, analyst | Create a new vulnerability |
| `PUT` | `/<vuln_id>` | Yes | admin, analyst | Update an existing vulnerability |
| `DELETE` | `/<vuln_id>` | Yes | admin | Delete a vulnerability |

#### Validation Functions (`validation.py`)

- `validate_vulnerability_input(data, is_update)` – full create/partial update validation

#### Query Parameters (GET `/`)

| Parameter | Type | Description |
|---|---|---|
| `severity` | string | Filter by severity level |
| `status` | string | Filter by status |
| `asset_type` | string | Filter by asset type |
| `department` | string | Filter by department |
| `assigned_to` | string | Filter by assignee |
| `patch_applied` | boolean | Filter by patch status |
| `min_cvss` / `max_cvss` | float | CVSS score range filter |
| `search` | string | Full-text search |
| `sort_by` | string | Sort field (default: `created_at`) |
| `sort_order` | string | `asc` or `desc` (default: `desc`) |
| `page` / `per_page` | int | Pagination controls |

---

### 3. Remediation (`remediation_bp`)

| Property | Value |
|---|---|
| **Package** | `routes.remediation` |
| **URL Prefix** | `/api/v1/vulnerabilities` |
| **Files** | `__init__.py`, `routes.py`, `validation.py` |

> **Note:** Shares the `/api/v1/vulnerabilities` prefix because remediation
> steps are sub-documents of vulnerability records.

#### Endpoints

| Method | Path | Auth | Role | Description |
|---|---|---|---|---|
| `GET` | `/<vuln_id>/remediation-steps` | Yes | Any | List all remediation steps |
| `GET` | `/<vuln_id>/remediation-steps/<step_id>` | Yes | Any | Get a single step |
| `POST` | `/<vuln_id>/remediation-steps` | Yes | admin, analyst | Add a new step |
| `PUT` | `/<vuln_id>/remediation-steps/<step_id>` | Yes | admin, analyst | Update a step |
| `DELETE` | `/<vuln_id>/remediation-steps/<step_id>` | Yes | admin, analyst | Remove a step |

#### Validation Functions (`validation.py`)

- `validate_remediation_step_input(data, is_update)` – step_number, action, status, etc.

---

### 4. Activity Log (`activity_log_bp`)

| Property | Value |
|---|---|
| **Package** | `routes.activity_log` |
| **URL Prefix** | `/api/v1/vulnerabilities` |
| **Files** | `__init__.py`, `routes.py`, `validation.py` |

> **Note:** Shares the `/api/v1/vulnerabilities` prefix because activity log
> entries are sub-documents of vulnerability records.

#### Endpoints

| Method | Path | Auth | Role | Description |
|---|---|---|---|---|
| `GET` | `/<vuln_id>/activity-log` | Yes | Any | List all activity log entries |
| `GET` | `/<vuln_id>/activity-log/<log_id>` | Yes | Any | Get a single entry |
| `POST` | `/<vuln_id>/activity-log` | Yes | admin, analyst | Add a new entry |
| `DELETE` | `/<vuln_id>/activity-log/<log_id>` | Yes | admin | Delete an entry |

#### Validation Functions (`validation.py`)

- `validate_activity_log_input(data)` – action, details, previous_value, new_value

---

### 5. Analytics (`analytics_bp`)

| Property | Value |
|---|---|
| **Package** | `routes.analytics` |
| **URL Prefix** | `/api/v1/analytics` |
| **Files** | `__init__.py`, `routes.py` |

#### Endpoints

| Method | Path | Auth | Role | Description |
|---|---|---|---|---|
| `GET` | `/severity-distribution` | Yes | Any | Counts grouped by severity |
| `GET` | `/department-risk` | Yes | Any | Risk exposure by department |
| `GET` | `/overdue-patches` | Yes | Any | Vulnerabilities past deadline |
| `GET` | `/patch-compliance` | Yes | Any | Overall patch compliance rate |
| `GET` | `/vulnerability-trends` | Yes | Any | Monthly trend (configurable months) |
| `GET` | `/top-affected-assets` | Yes | Any | Top N assets by vuln count |
| `GET` | `/mean-time-to-remediation` | Yes | Any | Avg days to resolve by severity |
| `GET` | `/risk-scores` | Yes | admin, analyst | Risk scores per vulnerability |
| `GET` | `/summary` | Yes | Any | Dashboard summary KPIs |

---

### 6. Admin (`admin_bp`)

| Property | Value |
|---|---|
| **Package** | `routes.admin` |
| **URL Prefix** | `/api/v1/admin` |
| **Files** | `__init__.py`, `routes.py` |

#### Endpoints

| Method | Path | Auth | Role | Description |
|---|---|---|---|---|
| `GET` | `/users` | Yes | admin | List all users (paginated) |
| `GET` | `/users/<user_id>` | Yes | admin | Get a specific user |
| `PUT` | `/users/<user_id>/role` | Yes | admin | Change a user's role |
| `PUT` | `/users/<user_id>/status` | Yes | admin | Activate / deactivate user |
| `DELETE` | `/users/<user_id>` | Yes | admin | Permanently delete user |

---

## How Blueprints Are Registered

```
app.py  →  create_app()
               │
               ├── from routes import register_blueprints
               └── register_blueprints(app)
                        │
                        ├── from routes.auth import auth_bp
                        ├── from routes.vulnerabilities import vulnerabilities_bp
                        ├── from routes.remediation import remediation_bp
                        ├── from routes.activity_log import activity_log_bp
                        ├── from routes.analytics import analytics_bp
                        └── from routes.admin import admin_bp
```

Each blueprint package follows this internal pattern:

```
routes/<name>/
├── __init__.py      ← Creates Blueprint('name', __name__, url_prefix='...')
│                       Then imports routes module to register handlers
├── routes.py        ← Imports blueprint object from __init__.py
│                       Defines @bp.route(...) handlers with RELATIVE paths
└── validation.py    ← (optional) Pure input-validation functions
```

---

## Adding a New Blueprint

1. **Create the package:**

   ```bash
   mkdir -p backend/routes/my_feature
   touch backend/routes/my_feature/__init__.py
   touch backend/routes/my_feature/routes.py
   ```

2. **Define the blueprint in `__init__.py`:**

   ```python
   """My Feature blueprint – short description."""
   from flask import Blueprint

   my_feature_bp = Blueprint('my_feature', __name__, url_prefix='/api/v1/my-feature')

   from routes.my_feature import routes  # noqa: E402, F401
   ```

3. **Write routes in `routes.py`:**

   ```python
   """My Feature endpoints."""
   from flask import request, jsonify, current_app
   from routes.my_feature import my_feature_bp

   @my_feature_bp.route('/', methods=['GET'])
   def list_items():
       return jsonify({"status": "success", "data": []}), 200
   ```

4. **Register in `routes/__init__.py`:**

   ```python
   from routes.my_feature import my_feature_bp
   app.register_blueprint(my_feature_bp)
   ```

5. **(Optional)** Add a `validation.py` for input validation.

---

## Middleware & Cross-Cutting Concerns

Blueprints leverage two decorators from the `middleware/` package:

| Decorator | Module | Purpose |
|---|---|---|
| `@token_required` | `middleware.auth_middleware` | Validates JWT from `Authorization: Bearer <token>` header. Passes decoded payload as `current_user`. |
| `@role_required(*roles)` | `middleware.rbac_middleware` | Checks `current_user.role` against allowed roles. Returns 403 if unauthorized. |

Error handling is registered globally via `middleware.error_handler.register_error_handlers(app)` and covers status codes 400, 401, 403, 404, 405, 413, 422, 429, and 500.

---

## Shared Utilities

| Module | Key Exports |
|---|---|
| `utils.helpers` | `serialize_doc()`, `validate_object_id()`, `get_pagination_params()`, `utcnow()`, `calculate_risk_score()` |
| `utils.validators` | `validate_string()`, `validate_enum()`, `validate_number()`, `validate_date()`, `validate_email()`, `validate_password()`, `validate_cve_id()`, `parse_iso_date()`, enum constants (`VALID_SEVERITIES`, `VALID_STATUSES`, etc.) |
