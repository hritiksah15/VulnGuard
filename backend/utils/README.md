# Utilities

Shared helper functions and validation logic used across all route modules.

## Files

### `helpers.py`

Common utility functions for database access, serialisation, and pagination.

| Function | Description |
|----------|-------------|
| `get_db()` | Returns the MongoDB database instance from `current_app.extensions["mongo_db"]` |
| `validate_object_id(id_string)` | Validates a 24-char hex string as a valid `ObjectId`. Returns `(ObjectId, None)` on success or `(None, error_response)` on failure (422). |
| `serialize_doc(doc)` | Recursively converts MongoDB documents to JSON-safe format — `ObjectId` → `str`, `datetime` → ISO 8601 string. Handles nested dicts and lists. |
| `get_pagination_params(args)` | Extracts and validates `page` and `per_page` from query args. Enforces `MAX_ITEMS_PER_PAGE` (100). Returns `(page, per_page, skip)`. |
| `utcnow()` | Returns current UTC datetime (timezone-naive) for consistent timestamps. |
| `calculate_risk_score(cvss, exploitability, severity)` | Weighted risk scoring formula: `(CVSS × 0.4) + (exploitability × 0.3) + (severity × 0.3)`. Returns float 0–10. |

### `validators.py`

Input validation functions and constant definitions.

#### Constants

| Constant | Values |
|----------|--------|
| `VALID_SEVERITIES` | Critical, High, Medium, Low, Informational |
| `VALID_STATUSES` | Open, In Progress, Patched, Accepted Risk, Accepted Risk |
| `VALID_ASSET_TYPES` | Server, Workstation, Network Device, Application, Database, Cloud Service, IoT Device |
| `VALID_ATTACK_VECTORS` | Network, Adjacent, Local, Physical |
| `VALID_EXPLOITABILITIES` | Unproven, Proof-of-Concept, Functional, High |
| `VALID_REMEDIATION_STATUSES` | Pending, In Progress, Completed, Skipped |
| `VALID_ROLES` | admin, analyst, guest |

#### Validation Patterns

| Pattern | Validates |
|---------|-----------|
| `CVE_ID_PATTERN` | `CVE-YYYY-NNNNN` format |
| `EMAIL_PATTERN` | Standard email regex |
| `PASSWORD_PATTERN` | 8+ chars, uppercase, lowercase, digit, special character |

#### Validation Functions

| Function | Description |
|----------|-------------|
| `validate_string(value, field, min_len, max_len)` | Type + length check |
| `validate_enum(value, field, valid_values)` | Value must be in allowed list |
| `validate_number(value, field, min_val, max_val)` | Numeric range check |
| `validate_date(value, field)` | ISO 8601 date/datetime parsing |
| `validate_cve_id(value)` | CVE ID format validation |
| `parse_iso_date(date_string)` | Parse ISO date string to datetime |
