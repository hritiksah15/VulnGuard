# Activity Log Routes

**Blueprint:** `activity_log_bp` — **Prefix:** `/api/v1/vulnerabilities`

Sub-document CRUD for activity log entries embedded within vulnerability documents. Provides an audit trail of actions taken on each vulnerability.

## Endpoints

| Method | Path | Auth | Role | Description |
|--------|------|:----:|:----:|-------------|
| `GET` | `/:vuln_id/activity-log` | ✅ | — | List all log entries |
| `GET` | `/:vuln_id/activity-log/:log_id` | ✅ | — | Get a single entry |
| `POST` | `/:vuln_id/activity-log` | ✅ | admin, analyst | Add a log entry (`$push`) |
| `DELETE` | `/:vuln_id/activity-log/:log_id` | ✅ | admin | Delete a log entry (`$pull`) |

## MongoDB Sub-Document Operations

| Operation | MongoDB Operator |
|-----------|-----------------|
| Create | `$push` into `activity_log` array |
| Delete | `$pull` from `activity_log` array by `_id` |

## Log Entry Fields

| Field | Type | Required | Description |
|-------|------|:--------:|-------------|
| `step_description` | string | ✅ | What was done (e.g., "Status changed to In Progress") |
| `performed_by` | string | ✅ | Username of the person |
| `performed_at` | datetime | Auto | Set to current UTC time |
| `details` | string | — | Additional context |

## Files

| File | Purpose |
|------|---------|
| `routes.py` | All 4 endpoint handlers |
| `validation.py` | `validate_activity_log_input()` |
| `__init__.py` | Exports `activity_log_bp` Blueprint |
