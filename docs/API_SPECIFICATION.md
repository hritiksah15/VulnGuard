# VulnGuard – RESTful API Specification

**Version:** 1.0  
**Last Updated:** 4 March 2026  
**Module:** COM661 – Full Stack Strategies and Development  
**Base URL:** `http://localhost:5000/api/v1`  
**Content-Type:** `application/json`

---

## Table of Contents

1. [Authentication Endpoints](#1-authentication-endpoints)
2. [Vulnerability CRUD Endpoints](#2-vulnerability-crud-endpoints)
3. [Remediation Steps Sub-Document Endpoints](#3-remediation-steps-sub-document-endpoints)
4. [Activity Log Sub-Document Endpoints](#4-activity-log-sub-document-endpoints)
5. [Analytics Endpoints](#5-analytics-endpoints)
6. [Admin Management Endpoints](#6-admin-management-endpoints)
7. [Query Parameter Reference](#7-query-parameter-reference)
8. [Standard Error Response Format](#8-standard-error-response-format)
9. [Response Examples](#9-response-examples)

---

## 1. Authentication Endpoints

| Method | Endpoint | Description | Auth Required | Role Required | Request Body | Response Code(s) |
|--------|----------|-------------|:-------------:|:-------------:|:------------:|:----------------:|
| `POST` | `/auth/register` | Register a new user account | No | — | `username`, `email`, `password` | `201`, `400`, `422` |
| `POST` | `/auth/login` | Authenticate user and return JWT token | No | — | `email`, `password` | `200`, `400`, `401` |
| `GET` | `/auth/profile` | Get current authenticated user's profile | Yes | Any | — | `200`, `401` |
| `PUT` | `/auth/profile` | Update current user's profile details | Yes | Any | `username`, `email` | `200`, `400`, `401`, `422` |
| `POST` | `/auth/refresh` | Refresh JWT token before expiry | Yes | Any | — | `200`, `401` |
| `PUT` | `/auth/change-password` | Change current user's password | Yes | Any | `current_password`, `new_password` | `200`, `400`, `401`, `422` |

---

## 2. Vulnerability CRUD Endpoints

### 2.1 Core CRUD Operations

| Method | Endpoint | Description | Auth Required | Role Required | Query Parameters | Response Code(s) |
|--------|----------|-------------|:-------------:|:-------------:|:----------------:|:----------------:|
| `GET` | `/vulnerabilities` | Retrieve paginated list of vulnerabilities | No | — | `page`, `per_page`, `severity`, `status`, `asset_type`, `department`, `sort_by`, `sort_order`, `search` | `200` |
| `GET` | `/vulnerabilities/{id}` | Retrieve a single vulnerability by ID | No | — | — | `200`, `404` |
| `POST` | `/vulnerabilities` | Create a new vulnerability record | Yes | Admin, Analyst | — | `201`, `400`, `401`, `403`, `422` |
| `PUT` | `/vulnerabilities/{id}` | Update an existing vulnerability | Yes | Admin, Analyst | — | `200`, `400`, `401`, `403`, `404`, `422` |
| `DELETE` | `/vulnerabilities/{id}` | Delete a vulnerability permanently | Yes | Admin | — | `204`, `401`, `403`, `404` |

### 2.2 Vulnerability Request Body (POST / PUT)

```json
{
  "title": "SQL Injection in Login Form",
  "description": "The login form is vulnerable to SQL injection through the username field...",
  "cve_id": "CVE-2025-12345",
  "severity": "Critical",
  "status": "Open",
  "cvss_score": 9.8,
  "asset_name": "web-app-01.example.com",
  "asset_type": "Application",
  "department": "Engineering",
  "affected_versions": ["2.1.0", "2.1.1", "2.2.0"],
  "attack_vector": "Network",
  "exploitability": "Functional",
  "patch_deadline": "2026-03-15T00:00:00Z",
  "assigned_to": "j.smith",
  "reported_by": "security-scanner"
}
```

### 2.3 Vulnerability Field Validation Rules

| Field | Type | Required | Validation Rule |
|-------|------|:--------:|-----------------|
| `title` | String | Yes | 5–200 characters |
| `description` | String | Yes | 10–5000 characters |
| `cve_id` | String | No | Format: `CVE-YYYY-NNNNN` (regex: `^CVE-\d{4}-\d{4,}$`) |
| `severity` | String | Yes | Enum: `Critical`, `High`, `Medium`, `Low`, `Informational` |
| `status` | String | Yes | Enum: `Open`, `In Progress`, `Resolved`, `Closed`, `Deferred` |
| `cvss_score` | Number | Yes | Range: `0.0` – `10.0` |
| `asset_name` | String | Yes | 1–200 characters |
| `asset_type` | String | Yes | Enum: `Server`, `Workstation`, `Network Device`, `Application`, `Database`, `Cloud Service`, `IoT Device` |
| `department` | String | Yes | 1–100 characters |
| `affected_versions` | Array[String] | No | Array of version strings |
| `attack_vector` | String | No | Enum: `Network`, `Adjacent`, `Local`, `Physical` |
| `exploitability` | String | No | Enum: `Unproven`, `Proof-of-Concept`, `Functional`, `High` |
| `patch_deadline` | String (ISO 8601) | No | Valid ISO 8601 date format |
| `assigned_to` | String | No | 1–100 characters |
| `reported_by` | String | Yes | 1–100 characters |

---

## 3. Remediation Steps Sub-Document Endpoints

| Method | Endpoint | Description | Auth Required | Role Required | Request Body | Response Code(s) |
|--------|----------|-------------|:-------------:|:-------------:|:------------:|:----------------:|
| `GET` | `/vulnerabilities/{id}/remediation-steps` | Retrieve all remediation steps for a vulnerability | Yes | Any | — | `200`, `401`, `404` |
| `GET` | `/vulnerabilities/{id}/remediation-steps/{step_id}` | Retrieve a single remediation step | Yes | Any | — | `200`, `401`, `404` |
| `POST` | `/vulnerabilities/{id}/remediation-steps` | Add a new remediation step to a vulnerability | Yes | Admin, Analyst | See below | `201`, `400`, `401`, `403`, `404`, `422` |
| `PUT` | `/vulnerabilities/{id}/remediation-steps/{step_id}` | Update a specific remediation step | Yes | Admin, Analyst | See below | `200`, `400`, `401`, `403`, `404`, `422` |
| `DELETE` | `/vulnerabilities/{id}/remediation-steps/{step_id}` | Remove a remediation step from a vulnerability | Yes | Admin, Analyst | — | `204`, `401`, `403`, `404` |

### 3.1 Remediation Step Request Body (POST / PUT)

```json
{
  "step_number": 1,
  "action": "Apply vendor security patch KB5025221 to the affected server",
  "assigned_to": "j.smith",
  "status": "Pending",
  "due_date": "2026-03-10T00:00:00Z",
  "notes": "Patch available from vendor portal. Requires server restart."
}
```

### 3.2 Remediation Step Validation Rules

| Field | Type | Required | Validation Rule |
|-------|------|:--------:|-----------------|
| `step_number` | Number | Yes | Positive integer ≥ 1 |
| `action` | String | Yes | 5–1000 characters |
| `assigned_to` | String | No | 1–100 characters |
| `status` | String | Yes | Enum: `Pending`, `In Progress`, `Completed`, `Skipped` |
| `due_date` | String (ISO 8601) | No | Valid ISO 8601 date format |
| `notes` | String | No | 0–2000 characters |

### 3.3 MongoDB Operations Used

| Operation | MongoDB Operator | Description |
|-----------|:----------------:|-------------|
| Add step | `$push` | Push new step object into `remediation_steps` array |
| Update step | `$set` + positional `$` | Update specific fields of a matched sub-document |
| Remove step | `$pull` | Pull step with matching `_id` from array |
| Get single step | `$match` + `$unwind` + `$match` | Aggregation pipeline to extract single sub-document |

---

## 4. Activity Log Sub-Document Endpoints

| Method | Endpoint | Description | Auth Required | Role Required | Request Body | Response Code(s) |
|--------|----------|-------------|:-------------:|:-------------:|:------------:|:----------------:|
| `GET` | `/vulnerabilities/{id}/activity-log` | Retrieve all activity log entries for a vulnerability | Yes | Any | — | `200`, `401`, `404` |
| `GET` | `/vulnerabilities/{id}/activity-log/{log_id}` | Retrieve a single activity log entry | Yes | Any | — | `200`, `401`, `404` |
| `POST` | `/vulnerabilities/{id}/activity-log` | Add a new activity log entry | Yes | Admin, Analyst | See below | `201`, `400`, `401`, `403`, `404`, `422` |
| `DELETE` | `/vulnerabilities/{id}/activity-log/{log_id}` | Delete an activity log entry | Yes | Admin | — | `204`, `401`, `403`, `404` |

### 4.1 Activity Log Request Body (POST)

```json
{
  "action": "Status changed",
  "details": "Vulnerability status updated from Open to In Progress",
  "previous_value": "Open",
  "new_value": "In Progress"
}
```

### 4.2 Activity Log Validation Rules

| Field | Type | Required | Validation Rule |
|-------|------|:--------:|-----------------|
| `action` | String | Yes | 1–200 characters |
| `details` | String | No | 0–2000 characters |
| `previous_value` | String | No | 0–500 characters |
| `new_value` | String | No | 0–500 characters |

**Note:** `timestamp` and `performed_by` are auto-populated by the server.

### 4.3 MongoDB Operations Used

| Operation | MongoDB Operator | Description |
|-----------|:----------------:|-------------|
| Add log entry | `$push` | Push new log object into `activity_log` array |
| Remove log entry | `$pull` | Pull log with matching `_id` from array |
| Get single entry | `$match` + `$unwind` + `$match` | Aggregation pipeline to extract single sub-document |

---

## 5. Analytics Endpoints

All analytics endpoints use **MongoDB aggregation pipelines** to compute results server-side.

| Method | Endpoint | Description | Auth Required | Role Required | Query Parameters | Response Code(s) |
|--------|----------|-------------|:-------------:|:-------------:|:----------------:|:----------------:|
| `GET` | `/analytics/severity-distribution` | Count of vulnerabilities grouped by severity level | Yes | Any | — | `200`, `401` |
| `GET` | `/analytics/department-risk` | Risk exposure analysis grouped by department | Yes | Any | — | `200`, `401` |
| `GET` | `/analytics/overdue-patches` | List of vulnerabilities with overdue patch deadlines | Yes | Any | `severity`, `department` | `200`, `401` |
| `GET` | `/analytics/patch-compliance` | Overall patch compliance rate statistics | Yes | Any | — | `200`, `401` |
| `GET` | `/analytics/vulnerability-trends` | Vulnerability count trend grouped by month | Yes | Any | `months` (default: 12) | `200`, `401` |
| `GET` | `/analytics/top-affected-assets` | Top N assets ranked by vulnerability count | Yes | Any | `limit` (default: 10) | `200`, `401` |
| `GET` | `/analytics/mean-time-to-remediation` | Average days to resolve vulnerabilities by severity | Yes | Any | — | `200`, `401` |
| `GET` | `/analytics/risk-scores` | Calculated risk scores per vulnerability | Yes | Admin, Analyst | `min_score`, `department` | `200`, `401`, `403` |
| `GET` | `/analytics/summary` | Dashboard summary KPIs (counts, rates, averages) | Yes | Any | — | `200`, `401` |

### 5.1 Analytics Response Examples

**Severity Distribution Response:**

```json
{
  "status": "success",
  "data": [
    { "severity": "Critical", "count": 12, "avg_cvss": 9.45 },
    { "severity": "High", "count": 28, "avg_cvss": 7.82 },
    { "severity": "Medium", "count": 45, "avg_cvss": 5.21 },
    { "severity": "Low", "count": 18, "avg_cvss": 2.87 },
    { "severity": "Informational", "count": 7, "avg_cvss": 0.95 }
  ]
}
```

**Department Risk Exposure Response:**

```json
{
  "status": "success",
  "data": [
    {
      "department": "Engineering",
      "total_vulnerabilities": 34,
      "critical_count": 5,
      "high_count": 12,
      "avg_cvss": 6.78,
      "max_cvss": 9.8,
      "risk_score": 50.78
    },
    {
      "department": "Finance",
      "total_vulnerabilities": 18,
      "critical_count": 2,
      "high_count": 6,
      "avg_cvss": 5.92,
      "max_cvss": 8.5,
      "risk_score": 25.92
    }
  ]
}
```

**Overdue Patches Response:**

```json
{
  "status": "success",
  "data": [
    {
      "_id": "65fa123456789abcdef01234",
      "title": "SQL Injection in Login Form",
      "severity": "Critical",
      "cvss_score": 9.8,
      "asset_name": "web-app-01.example.com",
      "department": "Engineering",
      "patch_deadline": "2026-02-15T00:00:00Z",
      "days_overdue": 17
    }
  ]
}
```

**Patch Compliance Response:**

```json
{
  "status": "success",
  "data": {
    "total": 110,
    "patched": 72,
    "unpatched": 38,
    "compliance_rate": 65.45
  }
}
```

**Vulnerability Trends Response:**

```json
{
  "status": "success",
  "data": [
    { "year": 2025, "month": 10, "count": 15 },
    { "year": 2025, "month": 11, "count": 22 },
    { "year": 2025, "month": 12, "count": 18 },
    { "year": 2026, "month": 1, "count": 25 },
    { "year": 2026, "month": 2, "count": 30 }
  ]
}
```

**Top Affected Assets Response:**

```json
{
  "status": "success",
  "data": [
    { "asset_name": "web-app-01.example.com", "asset_type": "Application", "count": 12, "avg_cvss": 7.5 },
    { "asset_name": "db-server-03.internal", "asset_type": "Database", "count": 9, "avg_cvss": 6.8 },
    { "asset_name": "fw-edge-01.perimeter", "asset_type": "Network Device", "count": 7, "avg_cvss": 8.2 }
  ]
}
```

**Mean Time to Remediation Response:**

```json
{
  "status": "success",
  "data": [
    { "severity": "Critical", "avg_days": 4.2, "min_days": 1, "max_days": 12, "count": 8 },
    { "severity": "High", "avg_days": 11.5, "min_days": 3, "max_days": 28, "count": 15 },
    { "severity": "Medium", "avg_days": 21.3, "min_days": 7, "max_days": 45, "count": 22 },
    { "severity": "Low", "avg_days": 35.8, "min_days": 10, "max_days": 60, "count": 10 }
  ]
}
```

**Dashboard Summary Response:**

```json
{
  "status": "success",
  "data": {
    "total_vulnerabilities": 110,
    "open_count": 42,
    "in_progress_count": 28,
    "resolved_count": 25,
    "closed_count": 15,
    "critical_count": 12,
    "high_count": 28,
    "avg_cvss": 5.67,
    "compliance_rate": 65.45,
    "overdue_count": 8
  }
}
```

### 5.2 Aggregation Pipeline Stages Used

| Endpoint | Pipeline Stages | MongoDB Features Demonstrated |
|----------|----------------|------------------------------|
| Severity Distribution | `$group`, `$project`, `$sort` | Grouping, computed fields, sorting |
| Department Risk | `$group`, `$project`, `$sort` | Conditional sum (`$cond`), arithmetic (`$multiply`, `$add`), rounding |
| Overdue Patches | `$match`, `$project`, `$sort` | Date comparison, `$dateDiff`, date filtering |
| Patch Compliance | `$group`, `$project` | Boolean aggregation, division, percentage calculation |
| Vulnerability Trends | `$group`, `$sort`, `$project` | Date extraction (`$year`, `$month`), time-series grouping |
| Top Affected Assets | `$group`, `$sort`, `$limit`, `$project` | Limiting results, multi-field grouping |
| Mean Time to Remediation | `$match`, `$project`, `$group`, `$sort` | Date arithmetic, statistical aggregation |
| Risk Scores | `$match`, `$project`, `$sort` | Complex formula computations, weighted scoring |
| Dashboard Summary | `$facet`, `$group`, `$project` | Multi-pipeline facets for parallel aggregations |

---

## 6. Admin Management Endpoints

| Method | Endpoint | Description | Auth Required | Role Required | Query Parameters | Response Code(s) |
|--------|----------|-------------|:-------------:|:-------------:|:----------------:|:----------------:|
| `GET` | `/admin/users` | List all registered users | Yes | Admin | `page`, `per_page`, `role`, `is_active` | `200`, `401`, `403` |
| `GET` | `/admin/users/{user_id}` | Get a specific user's details | Yes | Admin | — | `200`, `401`, `403`, `404` |
| `PUT` | `/admin/users/{user_id}/role` | Update a user's role | Yes | Admin | — | `200`, `401`, `403`, `404`, `422` |
| `PUT` | `/admin/users/{user_id}/status` | Activate or deactivate a user account | Yes | Admin | — | `200`, `401`, `403`, `404`, `422` |
| `DELETE` | `/admin/users/{user_id}` | Permanently delete a user account | Yes | Admin | — | `204`, `401`, `403`, `404` |

### 6.1 Admin Request Bodies

**Update User Role:**

```json
{
  "role": "analyst"
}
```

Valid roles: `admin`, `analyst`, `guest`

**Update User Status:**

```json
{
  "is_active": false
}
```

---

## 7. Query Parameter Reference

### 7.1 Vulnerability List Parameters

| Parameter | Type | Default | Description | Example |
|-----------|------|---------|-------------|---------|
| `page` | Integer | `1` | Page number (1-indexed) | `?page=2` |
| `per_page` | Integer | `10` | Items per page (max: 100) | `?per_page=25` |
| `severity` | String | — | Filter by severity level | `?severity=Critical` |
| `status` | String | — | Filter by vulnerability status | `?status=Open` |
| `asset_type` | String | — | Filter by asset type | `?asset_type=Server` |
| `department` | String | — | Filter by department | `?department=Engineering` |
| `sort_by` | String | `created_at` | Field to sort by | `?sort_by=cvss_score` |
| `sort_order` | String | `desc` | Sort direction (`asc` or `desc`) | `?sort_order=asc` |
| `search` | String | — | Text search across title and description | `?search=SQL+injection` |
| `min_cvss` | Number | — | Minimum CVSS score filter | `?min_cvss=7.0` |
| `max_cvss` | Number | — | Maximum CVSS score filter | `?max_cvss=9.0` |
| `patch_applied` | Boolean | — | Filter by patch applied status | `?patch_applied=false` |
| `assigned_to` | String | — | Filter by assigned user | `?assigned_to=j.smith` |

### 7.2 Combined Filtering Example

```
GET /api/v1/vulnerabilities?severity=Critical&status=Open&department=Engineering&sort_by=cvss_score&sort_order=desc&page=1&per_page=10
```

This request retrieves the first page of 10 critical, open vulnerabilities in the Engineering department, sorted by CVSS score descending.

---

## 8. Standard Error Response Format

**All error responses** across every endpoint follow this exact structure:

```json
{
  "status": "error",
  "message": "Descriptive error message explaining what went wrong",
  "code": 400
}
```

### 8.1 Error Response Catalogue

| HTTP Code | `code` Value | Typical `message` | Trigger Scenario |
|:---------:|:------------:|-------------------|------------------|
| `400` | `400` | `"Request body must be valid JSON"` | Malformed JSON in request body |
| `400` | `400` | `"Missing required fields: title, severity, cvss_score"` | Required fields not provided |
| `401` | `401` | `"Authentication token is missing"` | No Authorization header present |
| `401` | `401` | `"Token has expired"` | JWT token past expiry time |
| `401` | `401` | `"Invalid token"` | JWT signature verification failed |
| `401` | `401` | `"Invalid email or password"` | Login credentials incorrect |
| `403` | `403` | `"You do not have permission to access this resource"` | User role insufficient for endpoint |
| `404` | `404` | `"Vulnerability not found"` | No document with given ID exists |
| `404` | `404` | `"Remediation step not found"` | Sub-document with given ID not found |
| `404` | `404` | `"Activity log entry not found"` | Sub-document with given ID not found |
| `404` | `404` | `"User not found"` | Admin endpoint - user ID not found |
| `422` | `422` | `"'cvss_score' must be between 0 and 10"` | CVSS score out of valid range |
| `422` | `422` | `"'severity' must be one of: Critical, High, Medium, Low, Informational"` | Invalid enum value |
| `422` | `422` | `"'patch_deadline' must be a valid ISO 8601 date"` | Date format validation failure |
| `422` | `422` | `"'title' must be between 5 and 200 characters"` | String length validation failure |
| `422` | `422` | `"Invalid ObjectId format"` | Path parameter is not valid ObjectId |
| `500` | `500` | `"An internal server error occurred"` | Unexpected exception in handler |

---

## 9. Response Examples

### 9.1 Paginated Vulnerability List (200 OK)

```
GET /api/v1/vulnerabilities?page=1&per_page=2&severity=Critical
```

```json
{
  "status": "success",
  "data": [
    {
      "_id": "65fa123456789abcdef01234",
      "title": "SQL Injection in Login Form",
      "severity": "Critical",
      "status": "Open",
      "cvss_score": 9.8,
      "asset_name": "web-app-01.example.com",
      "asset_type": "Application",
      "department": "Engineering",
      "patch_deadline": "2026-03-15T00:00:00Z",
      "patch_applied": false,
      "assigned_to": "j.smith",
      "risk_score": 47.2,
      "created_at": "2026-02-20T10:30:00Z"
    },
    {
      "_id": "65fa123456789abcdef01235",
      "title": "Remote Code Execution via Deserialization",
      "severity": "Critical",
      "status": "In Progress",
      "cvss_score": 9.5,
      "asset_name": "api-gateway-02.internal",
      "asset_type": "Application",
      "department": "Engineering",
      "patch_deadline": "2026-03-10T00:00:00Z",
      "patch_applied": false,
      "assigned_to": "a.jones",
      "risk_score": 45.0,
      "created_at": "2026-02-18T14:15:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 2,
    "total": 12,
    "pages": 6
  }
}
```

### 9.2 Single Vulnerability with Sub-Documents (200 OK)

```
GET /api/v1/vulnerabilities/65fa123456789abcdef01234
```

```json
{
  "status": "success",
  "data": {
    "_id": "65fa123456789abcdef01234",
    "title": "SQL Injection in Login Form",
    "description": "The login form is vulnerable to SQL injection through the username field. An attacker can bypass authentication by injecting SQL commands.",
    "cve_id": "CVE-2025-12345",
    "severity": "Critical",
    "status": "Open",
    "cvss_score": 9.8,
    "asset_name": "web-app-01.example.com",
    "asset_type": "Application",
    "department": "Engineering",
    "affected_versions": ["2.1.0", "2.1.1", "2.2.0"],
    "attack_vector": "Network",
    "exploitability": "Functional",
    "patch_deadline": "2026-03-15T00:00:00Z",
    "patch_applied": false,
    "assigned_to": "j.smith",
    "reported_by": "security-scanner",
    "risk_score": 47.2,
    "remediation_steps": [
      {
        "_id": "65fb234567890abcdef12345",
        "step_number": 1,
        "action": "Apply parameterised queries to all database interactions in the login module",
        "assigned_to": "j.smith",
        "status": "In Progress",
        "due_date": "2026-03-08T00:00:00Z",
        "completed_date": null,
        "notes": "Requires code review after implementation"
      },
      {
        "_id": "65fb234567890abcdef12346",
        "step_number": 2,
        "action": "Deploy updated module to staging environment for penetration testing",
        "assigned_to": "a.jones",
        "status": "Pending",
        "due_date": "2026-03-12T00:00:00Z",
        "completed_date": null,
        "notes": "Schedule with QA team"
      }
    ],
    "activity_log": [
      {
        "_id": "65fc345678901abcdef23456",
        "timestamp": "2026-02-20T10:30:00Z",
        "action": "Vulnerability created",
        "performed_by": "security-scanner",
        "details": "Vulnerability discovered during scheduled security scan",
        "previous_value": null,
        "new_value": null
      },
      {
        "_id": "65fc345678901abcdef23457",
        "timestamp": "2026-02-21T09:15:00Z",
        "action": "Assigned to analyst",
        "performed_by": "admin",
        "details": "Assigned to j.smith for remediation",
        "previous_value": null,
        "new_value": "j.smith"
      }
    ],
    "created_at": "2026-02-20T10:30:00Z",
    "updated_at": "2026-02-21T09:15:00Z",
    "created_by": "security-scanner"
  }
}
```

### 9.3 Successful Creation (201 Created)

```
POST /api/v1/vulnerabilities
Authorization: Bearer <jwt_token>
```

```json
{
  "status": "success",
  "data": {
    "_id": "65fd456789012abcdef34567",
    "title": "Cross-Site Scripting in Comment Field",
    "severity": "High",
    "status": "Open",
    "cvss_score": 7.5,
    "created_at": "2026-03-04T12:00:00Z"
  },
  "message": "Vulnerability created successfully"
}
```

### 9.4 Successful Deletion (204 No Content)

```
DELETE /api/v1/vulnerabilities/65fa123456789abcdef01234
Authorization: Bearer <jwt_token>
```

*Empty response body — HTTP status 204*

### 9.5 Validation Error (422 Unprocessable Entity)

```
POST /api/v1/vulnerabilities
Authorization: Bearer <jwt_token>
Content-Type: application/json
Body: { "title": "Hi", "cvss_score": 15.5, "severity": "Ultra" }
```

```json
{
  "status": "error",
  "message": "'title' must be between 5 and 200 characters; 'cvss_score' must be between 0 and 10; 'severity' must be one of: Critical, High, Medium, Low, Informational",
  "code": 422
}
```

### 9.6 Authentication Error (401 Unauthorized)

```json
{
  "status": "error",
  "message": "Authentication token is missing",
  "code": 401
}
```

### 9.7 Authorisation Error (403 Forbidden)

```json
{
  "status": "error",
  "message": "You do not have permission to access this resource",
  "code": 403
}
```

---

## Complete Endpoint Summary Table

| # | Method | Endpoint | Auth | Role | Description |
|:-:|--------|----------|:----:|:----:|-------------|
| 1 | `POST` | `/auth/register` | No | — | Register new user |
| 2 | `POST` | `/auth/login` | No | — | Login and get JWT |
| 3 | `GET` | `/auth/profile` | Yes | Any | Get current user profile |
| 4 | `PUT` | `/auth/profile` | Yes | Any | Update current user profile |
| 5 | `POST` | `/auth/refresh` | Yes | Any | Refresh JWT token |
| 6 | `PUT` | `/auth/change-password` | Yes | Any | Change password |
| 7 | `GET` | `/vulnerabilities` | No | — | List vulnerabilities (paginated, filterable) |
| 8 | `GET` | `/vulnerabilities/{id}` | No | — | Get single vulnerability |
| 9 | `POST` | `/vulnerabilities` | Yes | Admin, Analyst | Create vulnerability |
| 10 | `PUT` | `/vulnerabilities/{id}` | Yes | Admin, Analyst | Update vulnerability |
| 11 | `DELETE` | `/vulnerabilities/{id}` | Yes | Admin | Delete vulnerability |
| 12 | `GET` | `/vulnerabilities/{id}/remediation-steps` | Yes | Any | List remediation steps |
| 13 | `GET` | `/vulnerabilities/{id}/remediation-steps/{step_id}` | Yes | Any | Get single remediation step |
| 14 | `POST` | `/vulnerabilities/{id}/remediation-steps` | Yes | Admin, Analyst | Add remediation step |
| 15 | `PUT` | `/vulnerabilities/{id}/remediation-steps/{step_id}` | Yes | Admin, Analyst | Update remediation step |
| 16 | `DELETE` | `/vulnerabilities/{id}/remediation-steps/{step_id}` | Yes | Admin, Analyst | Remove remediation step |
| 17 | `GET` | `/vulnerabilities/{id}/activity-log` | Yes | Any | List activity log entries |
| 18 | `GET` | `/vulnerabilities/{id}/activity-log/{log_id}` | Yes | Any | Get single log entry |
| 19 | `POST` | `/vulnerabilities/{id}/activity-log` | Yes | Admin, Analyst | Add activity log entry |
| 20 | `DELETE` | `/vulnerabilities/{id}/activity-log/{log_id}` | Yes | Admin | Delete activity log entry |
| 21 | `GET` | `/analytics/severity-distribution` | Yes | Any | Severity distribution stats |
| 22 | `GET` | `/analytics/department-risk` | Yes | Any | Department risk analysis |
| 23 | `GET` | `/analytics/overdue-patches` | Yes | Any | Overdue patch report |
| 24 | `GET` | `/analytics/patch-compliance` | Yes | Any | Patch compliance rate |
| 25 | `GET` | `/analytics/vulnerability-trends` | Yes | Any | Monthly vulnerability trends |
| 26 | `GET` | `/analytics/top-affected-assets` | Yes | Any | Top affected assets |
| 27 | `GET` | `/analytics/mean-time-to-remediation` | Yes | Any | Avg remediation time |
| 28 | `GET` | `/analytics/risk-scores` | Yes | Admin, Analyst | Calculated risk scores |
| 29 | `GET` | `/analytics/summary` | Yes | Any | Dashboard KPI summary |
| 30 | `GET` | `/admin/users` | Yes | Admin | List all users |
| 31 | `GET` | `/admin/users/{user_id}` | Yes | Admin | Get user details |
| 32 | `PUT` | `/admin/users/{user_id}/role` | Yes | Admin | Update user role |
| 33 | `PUT` | `/admin/users/{user_id}/status` | Yes | Admin | Activate/deactivate user |
| 34 | `DELETE` | `/admin/users/{user_id}` | Yes | Admin | Delete user account |

**Total: 34 endpoints** covering full CRUD, sub-document CRUD, analytics aggregations, authentication, and admin management.

---

*End of RESTful API Specification*
