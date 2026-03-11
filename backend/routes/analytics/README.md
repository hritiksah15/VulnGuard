# Analytics Routes

**Blueprint:** `analytics_bp` — **Prefix:** `/api/v1/analytics`

11 endpoints powered by MongoDB aggregation pipelines. Demonstrates `$match`, `$group`, `$project`, `$unwind`, `$sort`, `$facet`, `$dateDiff`, `$cond`, `$round`, and `$out` stages.

## Endpoints

| Method | Path | Auth | Role | Description | Key Pipeline Stages |
|--------|------|:----:|:----:|-------------|-------------------|
| `GET` | `/severity-distribution` | ✅ | — | Count by severity | `$group` |
| `GET` | `/department-risk` | ✅ | — | Risk by department | `$group` + `$sort` |
| `GET` | `/overdue-patches` | ✅ | — | Overdue items | `$match` + `$dateDiff` |
| `GET` | `/patch-compliance` | ✅ | — | Patched vs unpatched | `$facet` |
| `GET` | `/vulnerability-trends` | ✅ | — | Monthly trends | `$group` by date parts |
| `GET` | `/top-affected-assets` | ✅ | — | Most-hit assets | `$unwind` + `$group` + `$sort` |
| `GET` | `/mean-time-to-remediation` | ✅ | — | Average fix time | `$dateDiff` + `$avg` |
| `GET` | `/risk-scores` | ✅ | admin, analyst | Weighted risk ranking | `$project` + `$sort` |
| `GET` | `/summary` | ✅ | — | Dashboard KPIs | `$facet` (multiple sub-pipelines) |
| `POST` | `/generate-report` | ✅ | admin, analyst | Persist report | `$group` → `$out` to `reports` |
| `GET` | `/reports` | ✅ | — | Read saved reports | Direct collection read |

## `$out` Aggregation

`POST /generate-report` runs a `$group` pipeline (by department + severity) and writes results to a separate `reports` collection using the `$out` stage. This demonstrates MongoDB's ability to persist aggregation results.

## Pipeline Features Used

| Feature | Endpoints |
|---------|-----------|
| `$group` with `$sum`, `$avg`, `$max` | severity-distribution, department-risk, trends |
| `$facet` (multiple sub-pipelines) | patch-compliance, summary dashboard |
| `$dateDiff` | overdue-patches, mean-time-to-remediation |
| `$unwind` | top-affected-assets |
| `$project` with `$cond`, `$round` | risk-scores |
| `$out` | generate-report |

## Files

| File | Purpose |
|------|---------|
| `routes.py` | All 11 endpoint handlers |
| `__init__.py` | Exports `analytics_bp` Blueprint |
