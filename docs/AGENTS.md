# VulnGuard – AI Coding Assistant Context File (AGENTS.md)

**Version:** 1.0  
**Last Updated:** 4 March 2026  
**Module:** COM661 – Full Stack Strategies and Development  
**Purpose:** Provide AI coding assistants with full project context, coding standards, and implementation rules to ensure consistent, high-quality code generation across the VulnGuard platform.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Technology Stack & Versions](#2-technology-stack--versions)
3. [Project Structure](#3-project-structure)
4. [Python / Flask Coding Standards](#4-python--flask-coding-standards)
5. [Angular / TypeScript Coding Standards](#5-angular--typescript-coding-standards)
6. [MongoDB Standards & Best Practices](#6-mongodb-standards--best-practices)
7. [Mandatory Implementation Rules](#7-mandatory-implementation-rules)
8. [Authentication & Authorisation Rules](#8-authentication--authorisation-rules)
9. [Error Handling Contract](#9-error-handling-contract)
10. [Testing Standards](#10-testing-standards)

---

## 1. Project Overview

**VulnGuard** is an enterprise-grade vulnerability tracking and patch management platform built as a full-stack application for the COM661 coursework. It must demonstrate advanced MongoDB features, strict REST API design, robust validation, JWT-based RBAC, and a feature-rich Angular frontend exceeding the Biz Directory demonstration application.

**Key Domain Concepts:**
- **Vulnerability:** A security weakness in an IT asset (primary document)
- **Remediation Step:** An ordered action to fix a vulnerability (sub-document within vulnerability)
- **Activity Log:** An audit trail entry recording changes to a vulnerability (sub-document within vulnerability)
- **CVSS Score:** Common Vulnerability Scoring System, a numerical score from 0.0 to 10.0
- **Risk Score:** A calculated metric combining CVSS, exploitability, and exposure factors
- **Patch Compliance:** Whether a vulnerability has been remediated before its deadline

---

## 2. Technology Stack & Versions

### Backend

| Technology | Version | Purpose |
|---|---|---|
| Python | 3.11+ | Backend runtime |
| Flask | 3.0+ | Web framework |
| PyMongo | 4.6+ | MongoDB driver |
| Flask-PyMongo | 2.3+ | Flask-MongoDB integration |
| PyJWT | 2.8+ | JWT token generation and verification |
| bcrypt | 4.1+ | Password hashing |
| flask-cors | 4.0+ | Cross-Origin Resource Sharing |
| python-dotenv | 1.0+ | Environment variable management |
| marshmallow | 3.21+ | Input validation and serialisation (optional but recommended) |
| gunicorn | 21.2+ | Production WSGI server (optional) |

### Frontend

| Technology | Version | Purpose |
|---|---|---|
| Angular | 17.0+ | Frontend SPA framework |
| TypeScript | 5.2+ | Typed JavaScript |
| Angular CLI | 17.0+ | Project scaffolding and build |
| chart.js | 4.4+ | Data visualisation |
| ng2-charts | 5.0+ | Angular Chart.js wrapper |
| Bootstrap | 5.3+ | CSS framework (or Angular Material) |
| RxJS | 7.8+ | Reactive programming |

### Database

| Technology | Version | Purpose |
|---|---|---|
| MongoDB | 7.0+ | NoSQL document database |
| MongoDB Compass | Latest | GUI for database inspection |

### Testing

| Technology | Version | Purpose |
|---|---|---|
| Postman | Latest | API testing with collections |
| Newman | 6.0+ | CLI Postman collection runner |
| Karma | 6.4+ | Angular unit test runner |
| Jasmine | 5.1+ | Angular testing framework |
| Cypress | 13.0+ | End-to-end testing (optional) |

---

## 3. Project Structure

### Backend Structure

```
backend/
├── app.py                          # Application factory and entry point
├── config.py                       # Configuration classes (Dev, Test, Prod)
├── requirements.txt                # Python dependencies
├── .env                            # Environment variables (not committed)
├── .env.example                    # Environment variable template
├── routes/
│   ├── __init__.py
│   ├── vulnerabilities/
│   │   ├── __init__.py
│   │   ├── routes.py               # Vulnerability CRUD endpoints
│   │   └── validation.py           # Vulnerability input validation
│   ├── remediation/
│   │   ├── __init__.py
│   │   ├── routes.py               # Remediation step sub-document CRUD
│   │   └── validation.py           # Remediation input validation
│   ├── activity_log/
│   │   ├── __init__.py
│   │   ├── routes.py               # Activity log sub-document CRUD
│   │   └── validation.py           # Activity log input validation
│   ├── analytics/
│   │   ├── __init__.py
│   │   └── routes.py               # Aggregation pipeline analytics endpoints
│   └── auth/
│       ├── __init__.py
│       ├── routes.py               # Registration, login, user management
│       └── validation.py           # Auth input validation
├── middleware/
│   ├── __init__.py
│   ├── auth_middleware.py          # JWT verification decorator
│   ├── rbac_middleware.py          # Role-based access decorator
│   └── error_handler.py           # Centralised error handling
├── utils/
│   ├── __init__.py
│   ├── helpers.py                  # Utility functions (ObjectId conversion, etc.)
│   ├── validators.py               # Shared validation logic
│   └── seed_data.py                # Database seeding script
└── tests/
    └── postman/
        ├── VulnGuard.postman_collection.json
        └── VulnGuard.postman_environment.json
```

### Frontend Structure

```
frontend/
├── angular.json
├── tsconfig.json                    # Strict mode enabled
├── package.json
├── src/
│   ├── main.ts
│   ├── index.html
│   ├── styles.scss
│   ├── environments/
│   │   ├── environment.ts
│   │   └── environment.prod.ts
│   └── app/
│       ├── app.component.ts
│       ├── app.component.html
│       ├── app.routes.ts            # Application routing
│       ├── app.config.ts            # Application configuration
│       │
│       ├── models/
│       │   ├── vulnerability.model.ts
│       │   ├── remediation-step.model.ts
│       │   ├── activity-log.model.ts
│       │   ├── user.model.ts
│       │   └── api-response.model.ts
│       │
│       ├── services/
│       │   ├── auth.service.ts
│       │   ├── vulnerability.service.ts
│       │   ├── remediation.service.ts
│       │   ├── activity-log.service.ts
│       │   ├── analytics.service.ts
│       │   └── user.service.ts
│       │
│       ├── guards/
│       │   ├── auth.guard.ts
│       │   ├── role.guard.ts
│       │   └── guest.guard.ts
│       │
│       ├── interceptors/
│       │   ├── auth.interceptor.ts
│       │   └── error.interceptor.ts
│       │
│       ├── components/
│       │   ├── navbar/
│       │   ├── footer/
│       │   ├── loading-spinner/
│       │   └── confirm-dialog/
│       │
│       └── pages/
│           ├── login/
│           ├── register/
│           ├── dashboard/
│           ├── vulnerability-list/
│           ├── vulnerability-detail/
│           ├── vulnerability-form/
│           ├── remediation-steps/
│           ├── activity-log/
│           └── admin/
│               ├── user-management/
│               └── system-overview/
```

---

## 4. Python / Flask Coding Standards

### 4.1 PEP 8 Compliance (Mandatory)

- **Indentation:** 4 spaces (no tabs)
- **Maximum line length:** 88 characters (Black formatter standard)
- **Imports:** Grouped and ordered — stdlib, third-party, local
- **Naming conventions:**
  - Functions and variables: `snake_case`
  - Classes: `PascalCase`
  - Constants: `UPPER_SNAKE_CASE`
  - Private functions: `_leading_underscore`
- **Docstrings:** Required for all public functions and classes (Google style)
- **Type hints:** Required for all function parameters and return types

### 4.2 Flask Blueprint Pattern (Mandatory)

Every feature domain MUST be implemented as a separate Flask Blueprint:

```python
# routes/vulnerabilities/routes.py

from flask import Blueprint, request, jsonify

vulnerabilities_bp = Blueprint('vulnerabilities', __name__)

@vulnerabilities_bp.route('/api/v1/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    """Retrieve paginated list of vulnerabilities with optional filters."""
    # Implementation here
    pass
```

**Registration in app.py:**

```python
from routes.vulnerabilities.routes import vulnerabilities_bp
from routes.auth.routes import auth_bp
from routes.analytics.routes import analytics_bp
from routes.remediation.routes import remediation_bp
from routes.activity_log.routes import activity_log_bp

app.register_blueprint(vulnerabilities_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(analytics_bp)
app.register_blueprint(remediation_bp)
app.register_blueprint(activity_log_bp)
```

### 4.3 API Versioning

All API routes MUST be prefixed with `/api/v1/`:

```
/api/v1/vulnerabilities
/api/v1/vulnerabilities/<id>
/api/v1/vulnerabilities/<id>/remediation-steps
/api/v1/analytics/severity-distribution
/api/v1/auth/login
```

### 4.4 Response Format Standards

**Success responses:**

```python
# Single resource
return jsonify({"status": "success", "data": vulnerability}), 200

# Collection with pagination
return jsonify({
    "status": "success",
    "data": vulnerabilities,
    "pagination": {
        "page": page,
        "per_page": per_page,
        "total": total_count,
        "pages": total_pages
    }
}), 200

# Created
return jsonify({"status": "success", "data": new_vulnerability, "message": "Vulnerability created successfully"}), 201

# No Content (DELETE)
return '', 204
```

**Error responses (ALWAYS this format):**

```python
return jsonify({
    "status": "error",
    "message": "Descriptive error message",
    "code": 400
}), 400
```

### 4.5 Configuration Management

```python
# config.py

import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Base configuration."""
    SECRET_KEY: str = os.environ.get('SECRET_KEY', 'change-me-in-production')
    MONGO_URI: str = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/vulnguard')
    JWT_EXPIRY_HOURS: int = int(os.environ.get('JWT_EXPIRY_HOURS', '1'))
    ITEMS_PER_PAGE: int = int(os.environ.get('ITEMS_PER_PAGE', '10'))
    MAX_ITEMS_PER_PAGE: int = 100

class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG: bool = True

class TestingConfig(Config):
    """Testing configuration."""
    TESTING: bool = True
    MONGO_URI: str = os.environ.get('TEST_MONGO_URI', 'mongodb://localhost:27017/vulnguard_test')

class ProductionConfig(Config):
    """Production configuration."""
    DEBUG: bool = False
```

---

## 5. Angular / TypeScript Coding Standards

### 5.1 Strict Mode (Mandatory)

The `tsconfig.json` MUST have strict mode enabled:

```json
{
  "compilerOptions": {
    "strict": true,
    "noImplicitAny": true,
    "strictNullChecks": true,
    "strictPropertyInitialization": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true
  }
}
```

### 5.2 Naming Conventions

| Element | Convention | Example |
|---|---|---|
| Components | PascalCase | `VulnerabilityListComponent` |
| Services | PascalCase + Service | `VulnerabilityService` |
| Guards | PascalCase + Guard | `AuthGuard` |
| Interceptors | PascalCase + Interceptor | `AuthInterceptor` |
| Models/Interfaces | PascalCase | `Vulnerability`, `RemediationStep` |
| Files | kebab-case | `vulnerability-list.component.ts` |
| Variables | camelCase | `vulnerabilityList` |
| Constants | UPPER_SNAKE_CASE | `API_BASE_URL` |
| Observables | camelCase + `$` suffix | `vulnerabilities$` |
| Enums | PascalCase | `Severity`, `VulnerabilityStatus` |

### 5.3 TypeScript Interface Definitions (Mandatory)

Every data structure MUST have a TypeScript interface:

```typescript
// models/vulnerability.model.ts

export interface Vulnerability {
  _id: string;
  title: string;
  description: string;
  cve_id?: string;
  severity: Severity;
  status: VulnerabilityStatus;
  cvss_score: number;
  asset_name: string;
  asset_type: AssetType;
  department: string;
  affected_versions: string[];
  attack_vector: AttackVector;
  exploitability: Exploitability;
  patch_deadline: string;
  patch_applied: boolean;
  assigned_to?: string;
  reported_by: string;
  risk_score: number;
  remediation_steps: RemediationStep[];
  activity_log: ActivityLog[];
  created_at: string;
  updated_at: string;
  created_by: string;
}

export enum Severity {
  Critical = 'Critical',
  High = 'High',
  Medium = 'Medium',
  Low = 'Low',
  Informational = 'Informational'
}

export enum VulnerabilityStatus {
  Open = 'Open',
  InProgress = 'In Progress',
  Resolved = 'Resolved',
  Closed = 'Closed',
  Deferred = 'Deferred'
}

export enum AssetType {
  Server = 'Server',
  Workstation = 'Workstation',
  NetworkDevice = 'Network Device',
  Application = 'Application',
  Database = 'Database',
  CloudService = 'Cloud Service',
  IoTDevice = 'IoT Device'
}

export enum AttackVector {
  Network = 'Network',
  Adjacent = 'Adjacent',
  Local = 'Local',
  Physical = 'Physical'
}

export enum Exploitability {
  Unproven = 'Unproven',
  ProofOfConcept = 'Proof-of-Concept',
  Functional = 'Functional',
  High = 'High'
}
```

### 5.4 Service Pattern (Mandatory)

All HTTP calls MUST go through Angular services — NEVER call `HttpClient` directly from components:

```typescript
// services/vulnerability.service.ts

@Injectable({ providedIn: 'root' })
export class VulnerabilityService {
  private readonly apiUrl = `${environment.apiBaseUrl}/vulnerabilities`;

  constructor(private http: HttpClient) {}

  getVulnerabilities(params: VulnerabilityQueryParams): Observable<PaginatedResponse<Vulnerability>> {
    const httpParams = this.buildQueryParams(params);
    return this.http.get<PaginatedResponse<Vulnerability>>(this.apiUrl, { params: httpParams });
  }

  getVulnerabilityById(id: string): Observable<ApiResponse<Vulnerability>> {
    return this.http.get<ApiResponse<Vulnerability>>(`${this.apiUrl}/${id}`);
  }

  createVulnerability(data: CreateVulnerabilityDto): Observable<ApiResponse<Vulnerability>> {
    return this.http.post<ApiResponse<Vulnerability>>(this.apiUrl, data);
  }

  updateVulnerability(id: string, data: UpdateVulnerabilityDto): Observable<ApiResponse<Vulnerability>> {
    return this.http.put<ApiResponse<Vulnerability>>(`${this.apiUrl}/${id}`, data);
  }

  deleteVulnerability(id: string): Observable<void> {
    return this.http.delete<void>(`${this.apiUrl}/${id}`);
  }

  private buildQueryParams(params: VulnerabilityQueryParams): HttpParams {
    let httpParams = new HttpParams();
    if (params.page) httpParams = httpParams.set('page', params.page.toString());
    if (params.per_page) httpParams = httpParams.set('per_page', params.per_page.toString());
    if (params.severity) httpParams = httpParams.set('severity', params.severity);
    if (params.status) httpParams = httpParams.set('status', params.status);
    if (params.sort_by) httpParams = httpParams.set('sort_by', params.sort_by);
    if (params.sort_order) httpParams = httpParams.set('sort_order', params.sort_order);
    if (params.search) httpParams = httpParams.set('search', params.search);
    return httpParams;
  }
}
```

### 5.5 Reactive Forms Pattern (Mandatory)

All forms MUST use Angular Reactive Forms with validation:

```typescript
// pages/vulnerability-form/vulnerability-form.component.ts

export class VulnerabilityFormComponent implements OnInit {
  vulnerabilityForm!: FormGroup;

  ngOnInit(): void {
    this.vulnerabilityForm = new FormGroup({
      title: new FormControl('', [
        Validators.required,
        Validators.minLength(5),
        Validators.maxLength(200)
      ]),
      cvss_score: new FormControl(0, [
        Validators.required,
        Validators.min(0),
        Validators.max(10)
      ]),
      severity: new FormControl('', [Validators.required]),
      status: new FormControl('Open', [Validators.required]),
      // ... additional fields
    });
  }
}
```

### 5.6 Route Guard Pattern

```typescript
// guards/auth.guard.ts

export const authGuard: CanActivateFn = (route, state) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  if (authService.isAuthenticated()) {
    return true;
  }

  router.navigate(['/login'], { queryParams: { returnUrl: state.url } });
  return false;
};

// guards/role.guard.ts

export const roleGuard: CanActivateFn = (route, state) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  const requiredRoles = route.data['roles'] as string[];
  const userRole = authService.getUserRole();

  if (requiredRoles.includes(userRole)) {
    return true;
  }

  router.navigate(['/unauthorized']);
  return false;
};
```

### 5.7 HTTP Interceptor Pattern

```typescript
// interceptors/auth.interceptor.ts

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const authService = inject(AuthService);
  const token = authService.getToken();

  if (token) {
    const cloned = req.clone({
      setHeaders: { Authorization: `Bearer ${token}` }
    });
    return next(cloned);
  }

  return next(req);
};
```

---

## 6. MongoDB Standards & Best Practices

### 6.1 Document Modelling Strategy

**Embedding over referencing** for sub-documents that:
- Are always accessed with the parent document
- Have a bounded number of entries
- Are not shared across documents

This applies to:
- `remediation_steps[]` → Embedded in vulnerability document
- `activity_log[]` → Embedded in vulnerability document

**Referencing** for:
- User data (separate collection, referenced by username/ID)

### 6.2 Aggregation Pipeline Patterns

**ALWAYS use the MongoDB aggregation framework** for analytics. Never compute analytics in Python — push computation to the database.

**Severity Distribution Pattern:**

```python
pipeline = [
    {"$group": {
        "_id": "$severity",
        "count": {"$sum": 1},
        "avg_cvss": {"$avg": "$cvss_score"}
    }},
    {"$project": {
        "severity": "$_id",
        "count": 1,
        "avg_cvss": {"$round": ["$avg_cvss", 2]},
        "_id": 0
    }},
    {"$sort": {"count": -1}}
]
```

**Department Risk Exposure Pattern:**

```python
pipeline = [
    {"$group": {
        "_id": "$department",
        "total_vulnerabilities": {"$sum": 1},
        "critical_count": {
            "$sum": {"$cond": [{"$eq": ["$severity", "Critical"]}, 1, 0]}
        },
        "high_count": {
            "$sum": {"$cond": [{"$eq": ["$severity", "High"]}, 1, 0]}
        },
        "avg_cvss": {"$avg": "$cvss_score"},
        "max_cvss": {"$max": "$cvss_score"}
    }},
    {"$project": {
        "department": "$_id",
        "total_vulnerabilities": 1,
        "critical_count": 1,
        "high_count": 1,
        "avg_cvss": {"$round": ["$avg_cvss", 2]},
        "max_cvss": 1,
        "risk_score": {
            "$round": [{
                "$add": [
                    {"$multiply": ["$critical_count", 4]},
                    {"$multiply": ["$high_count", 2]},
                    "$avg_cvss"
                ]
            }, 2]
        },
        "_id": 0
    }},
    {"$sort": {"risk_score": -1}}
]
```

**Overdue Patches Pattern:**

```python
from datetime import datetime

pipeline = [
    {"$match": {
        "patch_applied": False,
        "patch_deadline": {"$lt": datetime.utcnow()},
        "status": {"$nin": ["Closed", "Resolved"]}
    }},
    {"$project": {
        "title": 1,
        "severity": 1,
        "cvss_score": 1,
        "asset_name": 1,
        "department": 1,
        "patch_deadline": 1,
        "days_overdue": {
            "$dateDiff": {
                "startDate": "$patch_deadline",
                "endDate": datetime.utcnow(),
                "unit": "day"
            }
        }
    }},
    {"$sort": {"days_overdue": -1}}
]
```

**Patch Compliance Rate Pattern:**

```python
pipeline = [
    {"$group": {
        "_id": None,
        "total": {"$sum": 1},
        "patched": {
            "$sum": {"$cond": ["$patch_applied", 1, 0]}
        },
        "unpatched": {
            "$sum": {"$cond": ["$patch_applied", 0, 1]}
        }
    }},
    {"$project": {
        "_id": 0,
        "total": 1,
        "patched": 1,
        "unpatched": 1,
        "compliance_rate": {
            "$round": [
                {"$multiply": [
                    {"$divide": ["$patched", "$total"]},
                    100
                ]},
                2
            ]
        }
    }}
]
```

**Vulnerability Trend by Month Pattern:**

```python
pipeline = [
    {"$group": {
        "_id": {
            "year": {"$year": "$created_at"},
            "month": {"$month": "$created_at"}
        },
        "count": {"$sum": 1}
    }},
    {"$sort": {"_id.year": 1, "_id.month": 1}},
    {"$project": {
        "_id": 0,
        "year": "$_id.year",
        "month": "$_id.month",
        "count": 1
    }}
]
```

**Mean Time to Remediation Pattern:**

```python
pipeline = [
    {"$match": {
        "status": {"$in": ["Resolved", "Closed"]},
        "updated_at": {"$exists": True}
    }},
    {"$project": {
        "severity": 1,
        "resolution_days": {
            "$dateDiff": {
                "startDate": "$created_at",
                "endDate": "$updated_at",
                "unit": "day"
            }
        }
    }},
    {"$group": {
        "_id": "$severity",
        "avg_days": {"$avg": "$resolution_days"},
        "min_days": {"$min": "$resolution_days"},
        "max_days": {"$max": "$resolution_days"},
        "count": {"$sum": 1}
    }},
    {"$project": {
        "severity": "$_id",
        "avg_days": {"$round": ["$avg_days", 1]},
        "min_days": 1,
        "max_days": 1,
        "count": 1,
        "_id": 0
    }},
    {"$sort": {"avg_days": -1}}
]
```

### 6.3 Indexing Strategy

**ALWAYS create indexes before querying.** Include the following in the database setup:

```python
def create_indexes(db):
    """Create all required indexes for optimal query performance."""
    # Single field indexes
    db.vulnerabilities.create_index("severity")
    db.vulnerabilities.create_index("status")
    db.vulnerabilities.create_index("cvss_score")
    db.vulnerabilities.create_index("department")
    db.vulnerabilities.create_index("patch_deadline")
    db.vulnerabilities.create_index("patch_applied")
    db.vulnerabilities.create_index("created_at")

    # Compound index for common filter combinations
    db.vulnerabilities.create_index([
        ("severity", 1),
        ("status", 1),
        ("department", 1)
    ])

    # Text index for search
    db.vulnerabilities.create_index([
        ("title", "text"),
        ("description", "text")
    ])

    # User collection indexes
    db.users.create_index("email", unique=True)
    db.users.create_index("username", unique=True)
```

### 6.4 Sub-Document Operations

**Adding a remediation step (`$push`):**

```python
db.vulnerabilities.update_one(
    {"_id": ObjectId(vuln_id)},
    {"$push": {"remediation_steps": new_step}}
)
```

**Updating a specific remediation step (positional operator):**

```python
db.vulnerabilities.update_one(
    {
        "_id": ObjectId(vuln_id),
        "remediation_steps._id": ObjectId(step_id)
    },
    {"$set": {
        "remediation_steps.$.status": "Completed",
        "remediation_steps.$.completed_date": datetime.utcnow()
    }}
)
```

**Removing a remediation step (`$pull`):**

```python
db.vulnerabilities.update_one(
    {"_id": ObjectId(vuln_id)},
    {"$pull": {"remediation_steps": {"_id": ObjectId(step_id)}}}
)
```

**Adding an activity log entry (`$push`):**

```python
db.vulnerabilities.update_one(
    {"_id": ObjectId(vuln_id)},
    {"$push": {"activity_log": {
        "_id": ObjectId(),
        "timestamp": datetime.utcnow(),
        "action": "Status changed",
        "performed_by": current_user,
        "details": "Status updated from Open to In Progress",
        "previous_value": "Open",
        "new_value": "In Progress"
    }}}
)
```

**Removing an activity log entry (`$pull`):**

```python
db.vulnerabilities.update_one(
    {"_id": ObjectId(vuln_id)},
    {"$pull": {"activity_log": {"_id": ObjectId(log_id)}}}
)
```

---

## 7. Mandatory Implementation Rules

> **These rules are NON-NEGOTIABLE. Every code generation MUST comply.**

### Rule 1: Always Validate Inputs

```python
# EVERY endpoint that accepts input MUST validate before processing
def validate_vulnerability_input(data: dict) -> tuple[bool, str]:
    """Validate vulnerability creation/update input."""
    errors = []

    if not data.get('title') or not isinstance(data['title'], str):
        errors.append("'title' is required and must be a string")
    elif len(data['title']) < 5 or len(data['title']) > 200:
        errors.append("'title' must be between 5 and 200 characters")

    if 'cvss_score' in data:
        if not isinstance(data['cvss_score'], (int, float)):
            errors.append("'cvss_score' must be a number")
        elif data['cvss_score'] < 0 or data['cvss_score'] > 10:
            errors.append("'cvss_score' must be between 0 and 10")

    valid_severities = ['Critical', 'High', 'Medium', 'Low', 'Informational']
    if data.get('severity') and data['severity'] not in valid_severities:
        errors.append(f"'severity' must be one of: {', '.join(valid_severities)}")

    valid_statuses = ['Open', 'In Progress', 'Resolved', 'Closed', 'Deferred']
    if data.get('status') and data['status'] not in valid_statuses:
        errors.append(f"'status' must be one of: {', '.join(valid_statuses)}")

    if errors:
        return False, "; ".join(errors)
    return True, ""
```

### Rule 2: Always Return Correct HTTP Status Codes

| Scenario | Status Code | When to Use |
|---|---|---|
| Successful GET | `200 OK` | Resource(s) retrieved successfully |
| Successful POST | `201 Created` | New resource created |
| Successful DELETE | `204 No Content` | Resource deleted (empty response body) |
| Invalid input | `400 Bad Request` | Malformed JSON, missing fields |
| Not authenticated | `401 Unauthorized` | Missing or invalid JWT token |
| Not authorised | `403 Forbidden` | Valid token but insufficient role |
| Resource not found | `404 Not Found` | ID does not exist in database |
| Validation failure | `422 Unprocessable Entity` | Input fails business rule validation |
| Server error | `500 Internal Server Error` | Unexpected exception |

### Rule 3: Always Return Structured JSON Errors

```python
# NEVER return plain text errors. ALWAYS use this format:
@app.errorhandler(400)
def bad_request(e):
    return jsonify({
        "status": "error",
        "message": str(e.description) if hasattr(e, 'description') else "Bad request",
        "code": 400
    }), 400

@app.errorhandler(404)
def not_found(e):
    return jsonify({
        "status": "error",
        "message": "Resource not found",
        "code": 404
    }), 404

@app.errorhandler(500)
def internal_error(e):
    return jsonify({
        "status": "error",
        "message": "An internal server error occurred",
        "code": 500
    }), 500
```

### Rule 4: Always Use Advanced MongoDB Queries

- **NEVER** fetch all documents and filter in Python
- **ALWAYS** use MongoDB query operators (`$match`, `$group`, etc.)
- **ALWAYS** use aggregation pipelines for analytics
- **ALWAYS** use `$push`, `$pull`, `$set` for sub-document operations
- **ALWAYS** use the positional operator `$` for targeted sub-document updates
- **NEVER** replace an entire document when only a field needs updating

### Rule 5: Always Protect Routes Appropriately

```python
# Public routes (no auth required)
# GET /api/v1/vulnerabilities (paginated list)
# GET /api/v1/vulnerabilities/<id> (single vulnerability)
# POST /api/v1/auth/login
# POST /api/v1/auth/register

# Authenticated routes (any valid token)
# POST /api/v1/vulnerabilities
# PUT /api/v1/vulnerabilities/<id>
# POST /api/v1/vulnerabilities/<id>/remediation-steps
# GET /api/v1/analytics/*

# Admin-only routes
# DELETE /api/v1/vulnerabilities/<id>
# DELETE /api/v1/vulnerabilities/<id>/activity-log/<log_id>
# GET /api/v1/admin/users
# PUT /api/v1/admin/users/<id>/role
```

### Rule 6: Always Generate ObjectId for Sub-Documents

```python
from bson import ObjectId

new_step = {
    "_id": ObjectId(),  # ALWAYS generate a new ObjectId
    "step_number": data['step_number'],
    "action": data['action'],
    # ...
}
```

### Rule 7: Always Validate ObjectId Format

```python
from bson import ObjectId
from bson.errors import InvalidId

def validate_object_id(id_string: str) -> bool:
    """Validate that a string is a valid MongoDB ObjectId."""
    try:
        ObjectId(id_string)
        return True
    except (InvalidId, TypeError):
        return False
```

---

## 8. Authentication & Authorisation Rules

### JWT Token Structure

```python
payload = {
    "user_id": str(user['_id']),
    "username": user['username'],
    "role": user['role'],
    "exp": datetime.utcnow() + timedelta(hours=1),
    "iat": datetime.utcnow()
}
token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
```

### Auth Middleware Decorator

```python
from functools import wraps

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')

        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]

        if not token:
            return jsonify({
                "status": "error",
                "message": "Authentication token is missing",
                "code": 401
            }), 401

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            current_user = payload
        except jwt.ExpiredSignatureError:
            return jsonify({
                "status": "error",
                "message": "Token has expired",
                "code": 401
            }), 401
        except jwt.InvalidTokenError:
            return jsonify({
                "status": "error",
                "message": "Invalid token",
                "code": 401
            }), 401

        return f(current_user, *args, **kwargs)
    return decorated
```

### RBAC Decorator

```python
def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(current_user, *args, **kwargs):
            if current_user['role'] not in roles:
                return jsonify({
                    "status": "error",
                    "message": "You do not have permission to access this resource",
                    "code": 403
                }), 403
            return f(current_user, *args, **kwargs)
        return decorated
    return decorator
```

---

## 9. Error Handling Contract

### Centralised Error Handler

```python
# middleware/error_handler.py

def register_error_handlers(app):
    """Register all error handlers with the Flask app."""

    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({"status": "error", "message": str(e.description), "code": 400}), 400

    @app.errorhandler(401)
    def unauthorized(e):
        return jsonify({"status": "error", "message": "Unauthorized", "code": 401}), 401

    @app.errorhandler(403)
    def forbidden(e):
        return jsonify({"status": "error", "message": "Forbidden", "code": 403}), 403

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"status": "error", "message": "Resource not found", "code": 404}), 404

    @app.errorhandler(422)
    def unprocessable(e):
        return jsonify({"status": "error", "message": str(e.description), "code": 422}), 422

    @app.errorhandler(500)
    def internal_error(e):
        return jsonify({"status": "error", "message": "An internal server error occurred", "code": 500}), 500

    @app.errorhandler(Exception)
    def handle_unexpected_error(e):
        return jsonify({"status": "error", "message": "An unexpected error occurred", "code": 500}), 500
```

---

## 10. Testing Standards

### Backend Testing (Postman)

- **Every endpoint** must have at least one positive test and one negative test
- **Pre-request scripts** must handle JWT token acquisition automatically
- **Test assertions** must validate: status code, response structure, data types, response time
- **Newman** must be used for automated test execution with JSON/HTML reporters

### Frontend Testing (Angular)

- **Every service** must have unit tests mocking `HttpClient`
- **Every guard** must have tests for allowed and denied scenarios
- **Every form component** must have tests for validation behaviour
- **Interceptors** must be tested for token attachment and error handling
- Test coverage target: ≥ 80%

---

*End of AI Coding Assistant Context File*
