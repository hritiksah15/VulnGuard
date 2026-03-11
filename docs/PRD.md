# VulnGuard – Product Requirements Document (PRD)

**Version:** 1.0  
**Last Updated:** 4 March 2026  
**Module:** COM661 – Full Stack Strategies and Development  
**Author:** Hritik Sah  
**Status:** Approved for Development  

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement](#2-problem-statement)
3. [Application Purpose](#3-application-purpose)
4. [Target Users & Personas](#4-target-users--personas)
5. [Core Features – Backend Epics](#5-core-features--backend-epics)
6. [Core Features – Frontend Epics](#6-core-features--frontend-epics)
7. [Data Model & MongoDB Design](#7-data-model--mongodb-design)
8. [Non-Functional Requirements](#8-non-functional-requirements)
9. [COM661 High 1st Criteria Alignment](#9-com661-high-1st-criteria-alignment)
10. [Release Strategy](#10-release-strategy)

---

## 1. Executive Summary

**VulnGuard** is an enterprise-grade, full-stack cybersecurity platform designed for tracking, managing, and analysing security vulnerabilities across organisational IT infrastructure. The platform provides security teams with comprehensive tools to record discovered vulnerabilities, monitor remediation workflows, enforce patch compliance deadlines, and generate risk analytics dashboards.

The system is built using a **Python Flask RESTful API** backend connected to **MongoDB** with advanced aggregation pipelines, and an **Angular 17+** single-page application frontend featuring interactive Chart.js analytics dashboards, reactive forms, and role-based access control.

VulnGuard significantly exceeds the complexity of the Biz Directory demonstration application by implementing:

- Nested sub-document CRUD operations (remediation steps, activity logs)
- Multi-stage aggregation pipelines for risk scoring and compliance reporting
- Three-tier RBAC (Admin, Security Analyst, Guest)
- Real-time analytics dashboards with severity distribution, patch compliance trends, and department-based risk exposure
- Enterprise-grade input validation, error handling, and security controls

---

## 2. Problem Statement

Modern organisations face an ever-increasing volume of cybersecurity vulnerabilities across their IT assets. Without a centralised tracking and management platform, security teams encounter:

- **Fragmented vulnerability data** scattered across spreadsheets, emails, and disparate tools
- **Missed patch deadlines** leading to exploitation of known vulnerabilities
- **Lack of risk visibility** preventing informed prioritisation of remediation efforts
- **No audit trail** of remediation activities, making compliance reporting difficult
- **Inability to measure** patch compliance rates and mean time to remediation across departments

These challenges lead to increased cyber risk exposure, regulatory non-compliance, and potential data breaches that cost organisations millions in damages and reputational harm.

---

## 3. Application Purpose

VulnGuard addresses these challenges by providing:

| Capability | Description |
|---|---|
| **Centralised Vulnerability Register** | Single source of truth for all discovered vulnerabilities with CVSS scoring |
| **Remediation Workflow Management** | Step-by-step remediation tracking with ownership and deadline enforcement |
| **Activity Audit Trail** | Immutable activity logs recording every action taken on a vulnerability |
| **Risk Analytics Engine** | Aggregation-powered analytics calculating risk scores, severity distributions, and compliance metrics |
| **Role-Based Access Control** | Three-tier access model ensuring data integrity and least-privilege access |
| **Patch Compliance Reporting** | Dashboard highlighting overdue patches, compliance rates by department, and trend analysis |
| **Multi-Dimensional Filtering** | Advanced search and filtering by severity, status, asset type, department, and CVSS score range |

---

## 4. Target Users & Personas

### 4.1 Admin

| Attribute | Detail |
|---|---|
| **Role Name** | Administrator |
| **Access Level** | Full system access |
| **Capabilities** | Create, read, update, and delete all vulnerabilities and sub-documents; manage user accounts; access all analytics; configure system settings; promote/demote user roles |
| **Typical User** | IT Security Manager, CISO, System Administrator |

### 4.2 Security Analyst (Authenticated)

| Attribute | Detail |
|---|---|
| **Role Name** | Security Analyst |
| **Access Level** | Read/Write access to vulnerabilities; Read-only analytics |
| **Capabilities** | Create new vulnerability reports; update vulnerability status and details; add remediation steps and activity log entries; view analytics dashboards; filter and search vulnerabilities |
| **Typical User** | Penetration Tester, SOC Analyst, Vulnerability Analyst |

### 4.3 Guest (Unauthenticated / Limited)

| Attribute | Detail |
|---|---|
| **Role Name** | Guest |
| **Access Level** | Read-only access to public vulnerability data |
| **Capabilities** | View published vulnerability listings (paginated); view severity distribution summary; cannot access detailed remediation data, activity logs, or admin functions |
| **Typical User** | External auditor, compliance reviewer, stakeholder |

---

## 5. Core Features – Backend Epics

### Epic B1: RESTful Vulnerability Management API

| Feature | Description | Priority |
|---|---|---|
| B1.1 | Full CRUD operations on vulnerability documents | **Must Have** |
| B1.2 | Noun-based URI design following strict REST conventions | **Must Have** |
| B1.3 | Correct HTTP status codes (200, 201, 204, 400, 401, 403, 404, 422, 500) | **Must Have** |
| B1.4 | Standardised JSON error response format across all endpoints | **Must Have** |
| B1.5 | Pagination support with configurable page size and page number | **Must Have** |
| B1.6 | Multi-field query string filtering (severity, status, asset_type, department) | **Must Have** |
| B1.7 | Sorting by CVSS score, patch deadline, or creation date | **Must Have** |
| B1.8 | Text search across vulnerability title and description fields | **Should Have** |

### Epic B2: Sub-Document CRUD Operations

| Feature | Description | Priority |
|---|---|---|
| B2.1 | Add remediation step to a vulnerability (`$push`) | **Must Have** |
| B2.2 | Retrieve all remediation steps for a vulnerability | **Must Have** |
| B2.3 | Update a specific remediation step by ID (positional operator `$set`) | **Must Have** |
| B2.4 | Remove a specific remediation step (`$pull`) | **Must Have** |
| B2.5 | Add activity log entry to a vulnerability (`$push`) | **Must Have** |
| B2.6 | Retrieve all activity log entries for a vulnerability | **Must Have** |
| B2.7 | Delete a specific activity log entry (`$pull`) | **Must Have** |

### Epic B3: Advanced MongoDB Aggregation & Analytics

| Feature | Description | Priority |
|---|---|---|
| B3.1 | Severity distribution aggregation (`$group`, `$sort`) | **Must Have** |
| B3.2 | Department-based risk exposure analysis (`$unwind`, `$group`, `$project`) | **Must Have** |
| B3.3 | Average CVSS score per severity level (`$group`, `$project`) | **Must Have** |
| B3.4 | Overdue patch report (`$match` with date comparison, `$project`) | **Must Have** |
| B3.5 | Patch compliance rate calculation (`$group`, `$project`) | **Must Have** |
| B3.6 | Vulnerability trend analysis by creation month (`$group`, `$sort`) | **Should Have** |
| B3.7 | Top affected assets ranking (`$group`, `$sort`, `$limit`) | **Should Have** |
| B3.8 | Mean time to remediation calculation (`$match`, `$group`, `$project`) | **Should Have** |
| B3.9 | Risk score calculation using weighted CVSS and exploitability data | **Must Have** |

### Epic B4: Authentication & Authorisation

| Feature | Description | Priority |
|---|---|---|
| B4.1 | User registration with password hashing (bcrypt) | **Must Have** |
| B4.2 | Login endpoint returning JWT access token | **Must Have** |
| B4.3 | Token-protected routes using decorator pattern | **Must Have** |
| B4.4 | Role-Based Access Control (Admin, Security Analyst, Guest) | **Must Have** |
| B4.5 | Token refresh mechanism | **Should Have** |
| B4.6 | Admin user management (list users, change roles, deactivate accounts) | **Must Have** |
| B4.7 | Password strength validation on registration | **Should Have** |

### Epic B5: Input Validation & Error Handling

| Feature | Description | Priority |
|---|---|---|
| B5.1 | Type checking on all input fields | **Must Have** |
| B5.2 | CVSS score range validation (0.0–10.0) | **Must Have** |
| B5.3 | Enum validation for severity (Critical, High, Medium, Low, Informational) | **Must Have** |
| B5.4 | Enum validation for status (Open, In Progress, Resolved, Closed, Deferred) | **Must Have** |
| B5.5 | Date format validation for patch deadlines (ISO 8601) | **Must Have** |
| B5.6 | Required field enforcement on creation | **Must Have** |
| B5.7 | ObjectId format validation for path parameters | **Must Have** |
| B5.8 | Centralised error handler returning structured JSON | **Must Have** |
| B5.9 | Request body size limiting | **Should Have** |

---

## 6. Core Features – Frontend Epics

### Epic F1: Authentication & Access Control UI

| Feature | Description | Priority |
|---|---|---|
| F1.1 | Login page with reactive form validation | **Must Have** |
| F1.2 | Registration page with password strength indicator | **Must Have** |
| F1.3 | JWT token storage and management via AuthService | **Must Have** |
| F1.4 | HTTP Interceptor for automatic token attachment | **Must Have** |
| F1.5 | Route Guards enforcing role-based page access | **Must Have** |
| F1.6 | Automatic redirect on 401/403 responses | **Must Have** |
| F1.7 | Logout functionality with token cleanup | **Must Have** |

### Epic F2: Vulnerability Management Interface

| Feature | Description | Priority |
|---|---|---|
| F2.1 | Vulnerability list view with server-side pagination | **Must Have** |
| F2.2 | Filter panel: severity, status, asset type, department | **Must Have** |
| F2.3 | Sort controls: CVSS score, patch deadline, created date | **Must Have** |
| F2.4 | Search bar with debounced input | **Must Have** |
| F2.5 | Vulnerability detail view showing all fields and sub-documents | **Must Have** |
| F2.6 | Create vulnerability form with reactive validation | **Must Have** |
| F2.7 | Edit vulnerability form pre-populated with existing data | **Must Have** |
| F2.8 | Delete vulnerability with confirmation dialog | **Must Have** |
| F2.9 | Severity badge colour coding (Critical=Red, High=Orange, Medium=Yellow, Low=Green, Info=Blue) | **Should Have** |
| F2.10 | Status timeline visualisation | **Could Have** |

### Epic F3: Sub-Document Management UI

| Feature | Description | Priority |
|---|---|---|
| F3.1 | Remediation steps list within vulnerability detail | **Must Have** |
| F3.2 | Add remediation step form (inline or modal) | **Must Have** |
| F3.3 | Edit remediation step (inline editing) | **Must Have** |
| F3.4 | Delete remediation step with confirmation | **Must Have** |
| F3.5 | Activity log timeline display | **Must Have** |
| F3.6 | Add activity log entry form | **Must Have** |
| F3.7 | Delete activity log entry (Admin only) | **Must Have** |

### Epic F4: Analytics Dashboard

| Feature | Description | Priority |
|---|---|---|
| F4.1 | Dashboard home page with summary KPI cards | **Must Have** |
| F4.2 | Severity distribution pie/doughnut chart (Chart.js) | **Must Have** |
| F4.3 | Vulnerability trend line chart by month | **Must Have** |
| F4.4 | Department risk exposure bar chart | **Must Have** |
| F4.5 | Patch compliance rate gauge or progress indicator | **Must Have** |
| F4.6 | Overdue patches data table with severity indicators | **Must Have** |
| F4.7 | Top affected assets horizontal bar chart | **Should Have** |
| F4.8 | Dashboard auto-refresh capability | **Could Have** |
| F4.9 | Export chart data as CSV | **Could Have** |

### Epic F5: Admin Panel

| Feature | Description | Priority |
|---|---|---|
| F5.1 | User management table (list all users) | **Must Have** |
| F5.2 | Change user role functionality | **Must Have** |
| F5.3 | Deactivate/activate user accounts | **Must Have** |
| F5.4 | System health overview | **Could Have** |

---

## 7. Data Model & MongoDB Design

### 7.1 Vulnerability Document Schema

```json
{
  "_id": "ObjectId",
  "title": "String (required, 5-200 chars)",
  "description": "String (required, 10-5000 chars)",
  "cve_id": "String (optional, format: CVE-YYYY-NNNNN)",
  "severity": "String (enum: Critical | High | Medium | Low | Informational)",
  "status": "String (enum: Open | In Progress | Resolved | Closed | Deferred)",
  "cvss_score": "Number (required, range: 0.0–10.0)",
  "asset_name": "String (required)",
  "asset_type": "String (enum: Server | Workstation | Network Device | Application | Database | Cloud Service | IoT Device)",
  "department": "String (required)",
  "affected_versions": ["String"],
  "attack_vector": "String (enum: Network | Adjacent | Local | Physical)",
  "exploitability": "String (enum: Unproven | Proof-of-Concept | Functional | High)",
  "patch_deadline": "Date (ISO 8601)",
  "patch_applied": "Boolean (default: false)",
  "assigned_to": "String",
  "reported_by": "String (required)",
  "risk_score": "Number (calculated field)",
  "remediation_steps": [
    {
      "_id": "ObjectId",
      "step_number": "Number (required)",
      "action": "String (required, 5-1000 chars)",
      "assigned_to": "String",
      "status": "String (enum: Pending | In Progress | Completed | Skipped)",
      "due_date": "Date",
      "completed_date": "Date | null",
      "notes": "String"
    }
  ],
  "activity_log": [
    {
      "_id": "ObjectId",
      "timestamp": "Date (auto-generated)",
      "action": "String (required)",
      "performed_by": "String (required)",
      "details": "String",
      "previous_value": "String | null",
      "new_value": "String | null"
    }
  ],
  "created_at": "Date (auto-generated)",
  "updated_at": "Date (auto-updated)",
  "created_by": "String"
}
```

### 7.2 User Document Schema

```json
{
  "_id": "ObjectId",
  "username": "String (required, unique, 3-50 chars)",
  "email": "String (required, unique, valid email format)",
  "password_hash": "String (bcrypt hashed)",
  "role": "String (enum: admin | analyst | guest)",
  "is_active": "Boolean (default: true)",
  "created_at": "Date (auto-generated)",
  "last_login": "Date"
}
```

### 7.3 Indexing Strategy

| Index | Fields | Type | Purpose |
|---|---|---|---|
| severity_idx | `severity` | Single | Fast filtering by severity level |
| status_idx | `status` | Single | Fast filtering by vulnerability status |
| cvss_idx | `cvss_score` | Single | Sorting by CVSS score |
| department_idx | `department` | Single | Department-based aggregation queries |
| patch_deadline_idx | `patch_deadline` | Single | Overdue patch queries |
| compound_filter_idx | `severity`, `status`, `department` | Compound | Multi-field filter optimisation |
| text_search_idx | `title`, `description` | Text | Full-text search support |
| user_email_idx | `email` | Unique | User lookup by email |
| user_username_idx | `username` | Unique | User lookup by username |

---

## 8. Non-Functional Requirements

### 8.1 Security

| Requirement | Implementation |
|---|---|
| Password storage | bcrypt hashing with salt rounds ≥ 12 |
| Authentication | JWT tokens with configurable expiry (1 hour default) |
| Authorisation | Role-based middleware on all protected endpoints |
| Input sanitisation | Strip dangerous characters; prevent NoSQL injection |
| CORS policy | Restrict origins to Angular frontend domain |
| Rate limiting | Maximum 100 requests per minute per IP (configurable) |
| Token security | Tokens stored in memory/session storage; no local storage for sensitive data |

### 8.2 Performance

| Requirement | Target |
|---|---|
| API response time (simple queries) | < 200ms |
| API response time (aggregation queries) | < 500ms |
| Page load time (Angular SPA) | < 2 seconds (initial), < 500ms (subsequent) |
| Database indexes | Covering indexes for all frequent query patterns |
| Pagination | Server-side, default 10 items per page, max 100 |

### 8.3 Scalability

| Requirement | Implementation |
|---|---|
| Modular backend | Flask Blueprints for separation of concerns |
| Stateless API | JWT-based auth enables horizontal scaling |
| Database design | Document model optimised for read-heavy vulnerability lookups |
| Configuration management | Environment variables for all configurable values |

### 8.4 Usability

| Requirement | Implementation |
|---|---|
| Responsive design | Mobile-first layout using Bootstrap 5 or Angular Material |
| Accessibility | ARIA labels, keyboard navigation, colour contrast compliance |
| Loading states | Skeleton loaders and spinners during API calls |
| Error feedback | Toast notifications for success/error operations |
| Form UX | Real-time validation feedback, clear error messages |

---

## 9. COM661 High 1st Criteria Alignment

### CW1 – Backend & Database (Target: 90%+)

| Rubric Criterion | VulnGuard Implementation | Evidence |
|---|---|---|
| **Complex MongoDB dataset** | Vulnerability documents with nested `remediation_steps[]` and `activity_log[]` sub-documents; 15+ fields per document including enums, dates, arrays, booleans, and calculated fields | Schema definition with rich data types |
| **Aggregation pipelines** | 8+ analytics endpoints using `$match`, `$group`, `$project`, `$unwind`, `$sort`, `$lookup`; risk scoring, severity distribution, compliance rates, trend analysis | Dedicated analytics Blueprint with pipeline implementations |
| **Strict RESTful API** | Noun-based URIs, correct HTTP verbs (GET/POST/PUT/DELETE), proper status codes (200/201/204/400/401/403/404/422/500) | API specification table + Postman collection |
| **Full CRUD + sub-document CRUD** | Top-level vulnerability CRUD + `remediation_steps` CRUD + `activity_log` CRUD using `$push`, `$pull`, `$set`, positional operators | 20+ API endpoints demonstrated |
| **Robust validation** | Type checking, range validation (CVSS 0–10), enum validation, date validation, required field enforcement, ObjectId validation | Centralised validation module |
| **JWT + RBAC** | bcrypt registration, JWT login, token-protected routes, Admin/Analyst/Guest roles with granular permissions | Auth Blueprint + decorator middleware |
| **Automated testing** | Postman collection with pre-request scripts, test assertions for status codes/schemas/response times, Newman CLI execution | Collection runner screenshots + Newman output |

### CW2 – Frontend (Target: 90%+)

| Rubric Criterion | VulnGuard Implementation | Evidence |
|---|---|---|
| **Angular 17+ strict mode** | `strict: true` in tsconfig; strongly typed models, services, and components | tsconfig.json + TypeScript interfaces |
| **Reactive Forms** | All create/edit forms using `FormGroup`, `FormControl`, `Validators`; real-time validation feedback | Vulnerability form, remediation step form, login/register forms |
| **Route Guards** | `AuthGuard` (requires login), `RoleGuard` (requires specific role), `GuestGuard` (redirects if logged in) | Guard implementations + routing module |
| **HTTP Interceptors** | `AuthInterceptor` attaching JWT to requests; `ErrorInterceptor` handling 401/403 globally | Interceptor source code |
| **Chart.js dashboards** | 4+ chart types: doughnut (severity), line (trends), bar (departments), gauge (compliance) | Dashboard component screenshots |
| **Pagination, filtering, sorting, search** | Server-side pagination; severity/status/department filters; CVSS/date sorting; debounced text search | Vulnerability list component |
| **Exceeds demonstration application** | Sub-document inline editing, analytics dashboard, admin panel, real-time form validation, severity colour coding, activity timeline | Comprehensive UI feature comparison |

---

## 10. Release Strategy

### Phase 1: Backend Foundation (Week 1–2)
- MongoDB schema design and seed data
- Flask project scaffolding with Blueprints
- Vulnerability CRUD endpoints
- Input validation framework
- Centralised error handling

### Phase 2: Advanced Backend (Week 3–4)
- Sub-document CRUD operations
- JWT authentication and RBAC
- Aggregation pipeline analytics endpoints
- Postman collection creation and testing

### Phase 3: Angular Foundation (Week 5–6)
- Angular 17 project setup with strict mode
- Authentication UI (login, register)
- AuthService, HTTP Interceptor, Route Guards
- Vulnerability list with pagination and filtering

### Phase 4: Angular Advanced (Week 7–8)
- Vulnerability create/edit forms (reactive forms)
- Sub-document management UI
- Chart.js analytics dashboard
- Admin panel

### Phase 5: Polish & Submission (Week 9–10)
- End-to-end testing
- Newman automated test execution
- UI/UX refinement
- Documentation completion
- Submission preparation

---

*End of Product Requirements Document*
