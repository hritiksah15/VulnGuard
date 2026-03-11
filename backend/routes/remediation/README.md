# Remediation Steps Routes

**Blueprint:** `remediation_bp` — **Prefix:** `/api/v1/vulnerabilities`

Sub-document CRUD for remediation steps embedded within vulnerability documents. Demonstrates MongoDB sub-document operations (`$push`, `$pull`, positional `$` operator).

## Endpoints

| Method | Path | Auth | Role | Description |
|--------|------|:----:|:----:|-------------|
| `GET` | `/:vuln_id/remediation-steps` | ✅ | — | List all remediation steps |
| `GET` | `/:vuln_id/remediation-steps/:step_id` | ✅ | — | Get a single step |
| `POST` | `/:vuln_id/remediation-steps` | ✅ | admin, analyst | Add a new step (`$push`) |
| `PUT` | `/:vuln_id/remediation-steps/:step_id` | ✅ | admin, analyst | Update step fields (positional `$`) |
| `DELETE` | `/:vuln_id/remediation-steps/:step_id` | ✅ | admin, analyst | Remove a step (`$pull`) |

## MongoDB Sub-Document Operations

| Operation | MongoDB Operator | Description |
|-----------|-----------------|-------------|
| Create | `$push` | Appends a new step to `remediation_steps` array |
| Update | `$set` with `remediation_steps.$` | Updates matching sub-document by positional operator |
| Delete | `$pull` | Removes matching sub-document from array by `_id` |

## Step Fields

| Field | Type | Required | Description |
|-------|------|:--------:|-------------|
| `step_number` | int | ✅ | Step sequence number (≥ 1) |
| `step_description` | string | ✅ | Description of the remediation action |
| `recommended_by` | string | ✅ | Person who recommended the step |
| `status` | enum | ✅ | Pending, In Progress, Completed, Verified |
| `added_at` | datetime | — | Auto-set on creation (UTC) |
| `due_date` | ISO date | — | Target completion date |
| `completed_date` | ISO date | — | Actual completion date |
| `notes` | string | — | Additional notes |

## Files

| File | Purpose |
|------|---------|
| `routes.py` | All 5 endpoint handlers |
| `validation.py` | `validate_remediation_step_input()` |
| `__init__.py` | Exports `remediation_bp` Blueprint |
