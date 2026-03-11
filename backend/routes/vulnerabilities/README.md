# Vulnerability Routes

**Blueprint:** `vulnerabilities_bp` — **Prefix:** `/api/v1/vulnerabilities`

Full CRUD operations on vulnerability documents, plus bulk create, geospatial queries, and advanced filtering.

## Endpoints

| Method | Path | Auth | Role | Description |
|--------|------|:----:|:----:|-------------|
| `GET` | `/` | — | — | List vulnerabilities (filters, pagination, search) |
| `GET` | `/:id` | — | — | Get single vulnerability by ID |
| `POST` | `/` | ✅ | admin, analyst | Create a new vulnerability |
| `POST` | `/bulk` | ✅ | admin, analyst | Bulk create 2–50 vulnerabilities (`insert_many`) |
| `PUT` | `/:id` | ✅ | admin, analyst | Update a vulnerability |
| `DELETE` | `/:id` | ✅ | admin | Delete a vulnerability |
| `GET` | `/nearby` | — | — | Find nearby vulnerabilities (`$geoNear`) |

## Required Fields (Create)

| Field | Type | Constraint |
|-------|------|-----------|
| `cve_id` | string | Format: `CVE-YYYY-NNNNN` |
| `vulnerability_title` | string | 5–200 characters |
| `description` | string | 10–5000 characters |
| `severity` | enum | Critical, High, Medium, Low |
| `cvss_score` | float | 0.0–10.0 |
| `status` | enum | Open, In Progress, Patched, Accepted Risk |
| `vulnerability_type` | enum | Software, Configuration, Access Control |
| `discovery_method` | enum | Scan, Audit, Manual |
| `affected_product` | string | Required |
| `department` | string | Required |
| `asset_type` | enum | Server, Workstation, Network Device, Application, Database, Cloud Service, IoT Device, Endpoint |

## Advanced Query Parameters

| Parameter | MongoDB Operator | Example |
|-----------|-----------------|---------|
| `severity_in` | `$in` | `?severity_in=Critical,High` |
| `status_in` | `$in` | `?status_in=Open,In Progress` |
| `title_regex` | `$regex` (case-insensitive) | `?title_regex=SQL.*Injection` |
| `search` | `$text` | `?search=buffer overflow` |
| `min_cvss` / `max_cvss` | `$gte` / `$lte` | `?min_cvss=7.0&max_cvss=10.0` |
| `or_severity` | `$or` | `?or_severity=Critical&or_status=Open` |
| `or_status` | `$or` | Combined with other `or_*` params |
| `or_min_cvss` | `$or` | `?or_min_cvss=9.0` |
| `or_department` | `$or` | `?or_department=Engineering` |

## Pagination

Two modes supported:

1. **Skip/Limit** — `?page=2&per_page=20` (traditional offset)
2. **Cursor-based (keyset)** — `?after=<objectid>` (efficient for large datasets, no duplicates)

## Geospatial — `/nearby`

| Parameter | Required | Description |
|-----------|:--------:|-------------|
| `lng` | ✅ | Longitude |
| `lat` | ✅ | Latitude |
| `radius` | — | Search radius in km (default: 50) |
| `limit` | — | Max results (default: 10) |

Uses `$geoNear` aggregation with `2dsphere` index on `location` field. Returns results with `distance_km`.

## MongoDB Patterns

- `find`, `find_one`, `insert_one`, `insert_many`, `update_one`, `delete_one`
- `$in`, `$regex`, `$or`, `$gte`, `$lte`, `$text`
- `$geoNear` aggregation with `2dsphere` index
- Cursor-based keyset pagination on `_id`
- Automatic `risk_score` calculation on create/update

## Files

| File | Purpose |
|------|---------|
| `routes.py` | All 7 endpoint handlers + `_build_geojson()` helper |
| `validation.py` | `validate_vulnerability_input()` — field-level validation |
| `__init__.py` | Exports `vulnerabilities_bp` Blueprint |
