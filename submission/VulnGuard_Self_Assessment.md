# VulnGuard — CW1 Self-Assessment

> **Student:** Hritik Kumar Sah | **ID:** B00923557 | **Module:** COM661 Full Stack Strategies and Development
> **Submission:** CW1 — Backend & Database

---

## Assessment Summary

| # | Criterion | Weight | Score (%) | Weighted Mark |
|---|---|---|---|---|
| 1 | Choice of Dataset | 15 | **72%** | 10.8 / 15 |
| 2 | Database Functionality | 25 | **74%** | 18.5 / 25 |
| 3 | API Structure | 25 | **72%** | 18.0 / 25 |
| 4 | Usability | 25 | **70%** | 17.5 / 25 |
| 5 | Submission Package | 10 | **68%** | 6.8 / 10 |
| | **Total** | **100** | | **71.6 / 100** |

**Overall Estimated Mark: ~72%**

---

## Criterion 1 — Choice of Dataset

**Weight: 15 | Score: 72%**

### Evidence

| Feature | Detail | File(s) |
|---|---|---|
| Domain | Enterprise vulnerability management — cybersecurity dataset tracking CVEs, remediation, and risk | `seeds/seed_data.py` |
| Document count | 109 vulnerability documents seeded into the `vulnerabilities` collection | `seeds/seed_data.py` |
| Document complexity | 15+ fields per document: strings, numbers (CVSS 0–10), dates, booleans, enums (severity, status, asset_type), nested arrays (`remediation_steps[]`, `activity_log[]`), GeoJSON `location` | `seeds/seed_data.py` |
| Additional collections | `users` (3 seeded accounts), `blacklist` (token invalidation), `reports` (generated via `$out`) | `app.py`, `routes/auth/routes.py`, `routes/analytics/routes.py` |
| Dataset modification | 10 GeoJSON Point locations added to enable geospatial queries; sub-document arrays added for remediation tracking and audit logging | `seeds/seed_data.py` |
| Seed script | Supports `--reseed` (drop and re-insert) and `--reset` flags; creates indexes on run | `seeds/seed_data.py` |

### Explanation
The vulnerability management dataset is a reasonable choice that supports the required application standard. The 109 documents exceed the minimum collection size and include multiple data types with nested sub-documents. The dataset has been modified with GeoJSON locations and sub-document arrays to enable geospatial and sub-document CRUD functionality.

### Why not higher
- The dataset is **template-based with random generation** rather than sourced from a real-world dataset (e.g. NIST NVD). While an import script for real CVE data exists (`scripts/import_cve_data.py`), the seeded data used in the application is synthetically generated
- 109 documents is adequate but not particularly large — a larger dataset would better demonstrate scalability and pagination
- The choice of cybersecurity/vulnerability management is not highly original — it is a common domain for CRUD applications
- Only 3 user documents seeded — limited user data variety
- Sub-document arrays are added structurally but individual remediation steps and activity logs are sparse in the seed data

---

## Criterion 2 — Database Functionality

**Weight: 25 | Score: 74%**

### Evidence

| Feature | Implementation | File(s) |
|---|---|---|
| **Create** | `insert_one` (single vuln, user, remediation step, log entry), `insert_many` (bulk create 2–50 vulns) | `routes/vulnerabilities/routes.py`, `routes/auth/routes.py` |
| **Read** | `find` with filters, `find_one` by ObjectId, pagination (skip/limit and cursor-based) | `routes/vulnerabilities/routes.py`, `utils/helpers.py` |
| **Update** | `update_one` with `$set` for top-level docs, positional `$` for sub-documents | `routes/vulnerabilities/routes.py`, `routes/remediation/routes.py` |
| **Delete** | `delete_one` for vulnerabilities, users; `$pull` for sub-document removal | `routes/vulnerabilities/routes.py`, `routes/admin/routes.py` |
| Field value search | Filter by `severity`, `status`, `department`, `asset_type`, `assigned_to` | `routes/vulnerabilities/routes.py` |
| Distinct / `$in` | `severity_in`, `status_in` query params using `{"$in": [...]}` | `routes/vulnerabilities/routes.py` |
| Regex search | `title_regex` param using `{"$regex": "...", "$options": "i"}` | `routes/vulnerabilities/routes.py` |
| `$or` queries | Combined `or_severity`, `or_status`, `or_min_cvss`, `or_department` filters | `routes/vulnerabilities/routes.py` |
| Text search | `$text` operator with text index on `title` + `description` | `routes/vulnerabilities/routes.py` |
| Range queries | `$gte`, `$lte` on `cvss_score` and date fields | `routes/vulnerabilities/routes.py` |
| Aggregation pipelines | `$match`, `$group`, `$project`, `$unwind`, `$sort`, `$limit`, `$facet`, `$geoNear`, `$out`, `$cond`, `$round`, `$dateDiff` | `routes/analytics/routes.py` |
| Geolocation | 2dsphere index + `$geoNear` aggregation returning `distance_km` | `routes/vulnerabilities/routes.py` (nearby endpoint) |
| `$out` stage | Pipeline writes to `reports` collection | `routes/analytics/routes.py` |
| Sub-document CRUD | `$push`, `$pull`, positional `$` operator for `remediation_steps[]` and `activity_log[]` | `routes/remediation/routes.py`, `routes/activity_log/routes.py` |
| Projections | `$project` used in aggregation pipelines to shape output | `routes/analytics/routes.py` |
| Indexing | Single-field, compound, text, 2dsphere, TTL, unique indexes | `app.py` |

### Explanation
The full range of CRUD operations is demonstrated across top-level documents and sub-documents. There is good evidence of complex queries including `$in`, `$regex`, `$or`, text search, range queries, and geolocation. Aggregation pipelines use multiple stages across 11 analytics endpoints. Indexing covers several types including 2dsphere and TTL.

### Why not higher
- **No `$lookup`** — cross-collection joins are not demonstrated in any aggregation pipeline
- No use of `distinct()` method directly — only `$in` for filtering
- No projections in standard `find()` queries — projections only appear inside aggregation `$project` stages
- No MongoDB `$jsonSchema` validation — all validation is Python-side only
- No multi-document transactions
- Some aggregation pipelines are relatively simple (single `$group` + `$sort`) rather than complex multi-stage transformations
- No `explain()` usage or evidence of query performance analysis
- No use of `$arrayFilters` for conditional sub-document updates

---

## Criterion 3 — API Structure

**Weight: 25 | Score: 72%**

### Evidence

| Feature | Implementation | Evidence |
|---|---|---|
| GET requests | List all, get by ID, filtered lists, nearby, analytics endpoints | All 6 route modules |
| POST requests | Create vulnerability, bulk create, register, login, logout, refresh, generate report, add remediation step, add log entry | `routes/vulnerabilities/routes.py`, `routes/auth/routes.py`, `routes/analytics/routes.py` |
| PUT requests | Update vulnerability, update remediation step, update log entry, update user role/status | `routes/vulnerabilities/routes.py`, `routes/remediation/routes.py`, `routes/admin/routes.py` |
| DELETE requests | Delete vulnerability, delete user, remove remediation step, remove log entry | `routes/vulnerabilities/routes.py`, `routes/admin/routes.py` |
| RESTful URL design | `/api/v1/vulnerabilities`, `/api/v1/vulnerabilities/<id>/remediation-steps/<step_id>` | Blueprint URL prefixes |
| HTTP status codes | 200 (OK), 201 (Created), 204 (No Content), 400 (Bad Request), 401 (Unauthorized), 403 (Forbidden), 404 (Not Found), 422 (Unprocessable Entity), 500 (Server Error) | `middleware/error_handler.py` + route handlers |
| API versioning | All routes prefixed with `/api/v1/` | Blueprint declarations |
| Consistent JSON format | `{"status": "success"/"error", "data": ..., "message": ...}` | Every endpoint |
| Pagination | `?page=1&per_page=20` (skip/limit) and `?after=<id>` (cursor-based) | `routes/vulnerabilities/routes.py` |
| Filtering/sorting | `?severity=Critical&sort_by=cvss_score&sort_dir=desc` | `routes/vulnerabilities/routes.py` |
| Total endpoints | **40 endpoints** across 6 Blueprints | `routes/__init__.py` |

### Explanation
GET, POST, PUT, and DELETE requests are all provided in a RESTful style with appropriate noun-based URL design and hierarchical nesting for sub-resources. HTTP status codes are used correctly — 201 for creation, 204 for deletion, 422 for validation failures. The API includes versioning (`/api/v1/`), consistent JSON response format, and both pagination approaches. There are significant enhancements beyond a basic directory example including sub-document CRUD, analytics aggregation, geospatial queries, and bulk operations.

### Why not higher
- **No PATCH method** — partial updates use PUT, which is semantically incorrect for partial modification
- No HATEOAS or hypermedia links in responses — no discoverability
- No content negotiation (Accept/Content-Type header verification)
- No ETag or caching headers on GET responses
- No API rate limiting despite 429 handler being registered
- Error responses lack structured error codes or documentation links
- Some inconsistency in pagination metadata format between different endpoints
- No OpenAPI/Swagger specification file for machine-readable API documentation

---

## Criterion 4 — Usability

**Weight: 25 | Score: 70%**

### Evidence

| Feature | Implementation | File(s) |
|---|---|---|
| **Core functionality** | Full vulnerability management lifecycle: create, read, update, delete vulnerabilities with rich metadata | `routes/vulnerabilities/routes.py` |
| **Sub-document management** | Remediation steps and activity log CRUD on each vulnerability | `routes/remediation/routes.py`, `routes/activity_log/routes.py` |
| **Analytics** | 11 analytics endpoints: severity distribution, department risk, overdue patches, compliance, trends, top affected assets, mean time to remediation, risk scores, summary, report generation | `routes/analytics/routes.py` |
| **Error trapping** | Centralised error handler for 400, 401, 403, 404, 405, 413, 422, 429, 500, plus catch-all Exception handler | `middleware/error_handler.py` |
| **Input validation** | Type checking, range validation, enum validation, date/CVE/email/password format validation; per-blueprint validation modules | `utils/validators.py`, `routes/*/validation.py` |
| **User authentication** | JWT-based auth with bcrypt password hashing (`rounds=12`), `x-access-token` header, token blacklisting on logout, TTL auto-expiry | `routes/auth/routes.py`, `middleware/auth_middleware.py` |
| **RBAC** | Three roles (admin, analyst, guest) with `@role_required()` decorator; admin-only delete/user management; analyst create/update; guest read-only | `middleware/rbac_middleware.py` |
| **Admin panel** | User listing, role updates, status toggle (activate/deactivate), user deletion with self-protection | `routes/admin/routes.py` |
| **Search capabilities** | Full-text search, regex search, field filters, geospatial nearby, combined `$or` queries | `routes/vulnerabilities/routes.py` |
| **Bulk operations** | Batch create with per-item validation (2–50 items) | `routes/vulnerabilities/routes.py` |

### Explanation
The application provides the core functionality appropriate for a vulnerability management system — CRUD for vulnerabilities, remediation tracking, activity logging, analytics dashboards, and admin user management. Error trapping is implemented via a centralised handler that catches all HTTP error codes and unhandled exceptions. User authentication is implemented with JWT tokens, bcrypt hashing, and a three-tier RBAC model.

### Why not higher
- **No rate limiting** — the 429 handler exists but no actual middleware enforces request limits, leaving the API unprotected against abuse
- No CORS origin whitelisting — `CORS(app)` is called with default settings allowing all origins
- No security headers (HSTS, X-Content-Type-Options, X-Frame-Options, CSP)
- SECRET_KEY has a hardcoded fallback in `config.py` rather than failing if the environment variable is missing
- No account lockout after failed login attempts
- No password reset flow
- No refresh token rotation — issuing a new token does not invalidate the old one
- No input sanitisation against XSS — relies on MongoDB parameterised queries only
- No schema-based validation library (Marshmallow, Pydantic) — all validation is manual
- No frontend or UI — backend-only submission, so usability is assessed purely through API behaviour

---

## Criterion 5 — Submission Package

**Weight: 10 | Score: 68%**

### Evidence

| Component | Status | File(s) |
|---|---|---|
| Backend source code | Submitted — complete Flask application | `backend/` directory |
| Postman collection | Submitted — 81 requests with test scripts | `tests/postman/VulnGuard.postman_collection.json` |
| Postman environment | Submitted | `tests/postman/VulnGuard.postman_environment.json` |
| MongoDB exports | Submitted — 4 collections | `submission/mongodb_exports/` (blacklist.json, reports.json, users.json, vulnerabilities.json) |
| Export script | Submitted — `mongoexport` shell script | `submission/export_mongodb.sh` |
| API endpoints doc | Submitted — 402-line endpoint summary | `submission/VulnGuard_API_Endpoints.md` |
| Code listing | Submitted — 2,938-line code listing | `submission/VulnGuard_Code_Listing.md` |
| API specification | Detailed endpoint documentation with examples | `docs/API_SPECIFICATION.md` |
| README files | Multiple READMEs at different directory levels | `README.md`, `backend/README.md`, etc. |
| Seed data script | Included with `--reseed` and `--reset` flags | `seeds/seed_data.py` |

### Explanation
The required components are mostly present — source code, Postman collection, MongoDB exports, and API documentation have been submitted. The code listing and API endpoints documents are well-formatted. Multiple README files provide context at different levels of the project.

### Why not higher
- **No video demonstration** — the rubric asks "Does the video demonstrate the complete functionality provided?" and no video file is included in the submission
- **No Newman HTML report** — only the raw Postman JSON is provided; no exported test execution report
- **No Postman Collection Runner screenshots** showing test pass/fail results
- **No testing summary document** — the rubric asks "Are the API documentation and testing summary complete?" and there is no dedicated testing summary beyond bash test output pasted in docs
- Code documents are present but some (AGENTS.md, QA_STRATEGY.md, PRD.md) are long template-style documents that may not all reflect the actual implementation precisely
- No deployment instructions or setup guide beyond the README

---

## Strengths

1. **Solid MongoDB coverage** — Aggregation pipelines, geospatial queries, text search, sub-document CRUD, bulk operations, and multiple index types demonstrate competent use of MongoDB
2. **RESTful API design** — 40 endpoints across 6 Blueprints with correct HTTP verbs, status codes, API versioning, and consistent JSON response structure
3. **Working authentication** — JWT with bcrypt hashing, token blacklisting on logout with TTL cleanup, and three-tier RBAC (admin, analyst, guest)
4. **Error trapping** — Centralised error handler covering all standard HTTP error codes with consistent JSON responses, plus per-blueprint input validation
5. **Adequate documentation** — API specification, endpoint summary, code listing, and MongoDB exports are present in the submission

## Weaknesses

1. **No video demonstration** — Required by the submission rubric but not included
2. **No Newman report or test screenshots** — Postman collection exists but no evidence of test execution results
3. **No Python unit tests** — Zero pytest/unittest coverage; all testing is via bash scripts and Postman
4. **No rate limiting** — 429 handler registered but no middleware to enforce it
5. **No security hardening** — Default CORS, no security headers, hardcoded SECRET_KEY fallback
6. **No `$lookup` or transactions** — Advanced MongoDB features not demonstrated
7. **Synthetic dataset** — Template-generated rather than real-world sourced
8. **No schema validation library** — Manual validation without Marshmallow/Pydantic

## Recommended Improvements

| Improvement | Estimated Impact |
|---|---|
| Record and submit a video demonstration | +5–8% on Submission Package |
| Generate and include Newman HTML test report | +3–5% on Submission Package |
| Add pytest unit tests for core functions | +3–5% on Usability |
| Implement `$lookup` in at least one aggregation | +2–3% on Database Functionality |
| Add rate limiting (Flask-Limiter) | +1–2% on Usability |
| Add security headers middleware | +1–2% on Usability |
| Import real CVE data instead of synthetic | +2–3% on Choice of Dataset |
| Include Postman runner screenshots | +1–2% on Submission Package |

---

## Final Summary

| Metric | Value |
|---|---|
| **Estimated Overall Mark** | **~72%** |
| **Grade Band** | **First (70–79)** |
| **Strongest Area** | Database Functionality (74%) |
| **Weakest Area** | Submission Package (68%) |
| **Total Endpoints** | 40 |
| **Total Postman Requests** | 81 |
| **Total Bash Tests** | 37 |
| **Unit Test Coverage** | 0% |

> **Assessor Notes:** This is a competent backend submission that demonstrates a working Flask REST API with MongoDB. The database layer shows good breadth of MongoDB features including aggregation, geospatial, and sub-document operations. The API follows RESTful conventions with proper authentication and role-based access control. However, the submission is weakened by the absence of a video demonstration, Newman test report, and unit tests. Security hardening (rate limiting, headers, CORS configuration) is also missing. With these additions, the submission could move into the upper-first class range.
