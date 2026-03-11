# Tests

Automated test suites for the VulnGuard API — both bash scripts and Postman collections.

## Test Suites

### 1. Bash Test Suite — `test_new_features.sh`

37 automated tests covering all implemented features. Uses `curl` + JSON parsing with `python3`.

```bash
cd backend && bash tests/test_new_features.sh
```

| Test Group | Tests | Covers |
|-----------|:-----:|--------|
| Login & tokens | 2 | Admin + analyst login via seeded credentials |
| x-access-token | 2 | Profile retrieval via `x-access-token` header |
| Logout & blacklist | 4 | Token blacklisting + rejection |
| Advanced filters | 4 | `$in` (`severity_in`), `$regex` (`title_regex`), `$text` |
| Cursor pagination | 3 | Keyset pagination, no duplicate IDs |
| Geospatial | 4 | `/nearby` endpoint, missing parameter handling |
| `$or` filter | 3 | Combined OR queries |
| Bulk create | 5 | `insert_many`, validation errors, auth checks |
| `$out` report | 4 | Generate report + retrieve from `reports` collection |
| Regression | 4 | Existing CRUD + analytics still work |
| **Total** | **37** | |

**Requirements:** Server running on `http://localhost:5001/api/v1`, seeded database.

### 2. Endpoint Verification — `verify_endpoints.sh`

Basic smoke test for all endpoints. Lighter than the full suite.

```bash
bash tests/verify_endpoints.sh
```

### 3. Postman Collection — `postman/`

81 automated requests with test scripts and Markdown descriptions.

```
postman/
├── VulnGuard.postman_collection.json   # 81 requests, 8 folders
└── VulnGuard.postman_environment.json  # Environment variables
```

**Import into Postman**, then run the collection using the Collection Runner.

| Folder | Requests | Description |
|--------|:--------:|-------------|
| Environment Setup | 4 | Health check + login all 3 users |
| Authentication | 10 | Login, profile, refresh, logout, blacklist |
| Vulnerability CRUD | 29 | Create, read, update, delete, filters, pagination, geo, bulk, $or |
| Remediation Steps | 8 | Sub-document CRUD ($push, $pull, positional $) |
| Activity Log | 7 | Sub-document CRUD for audit trail |
| Analytics | 13 | All aggregation endpoints + $out report |
| Admin Management | 8 | User list, role update, deactivate, delete |
| Cleanup | 2 | Delete test-created data |

**Key features:**
- **Seeded-data only** — starts from login, no registration needed
- Collection-level pre-request script auto-refreshes expired tokens
- Dynamic variable chaining (`pm.environment.set/get`)
- Body assertions with `pm.expect()`
- Every request has a Markdown description

## Environment Variables (Postman)

| Variable | Value |
|----------|-------|
| `base_url` | `http://localhost:5000/api/v1` |
| `admin_email` | `admin@vulnguard.test` |
| `admin_password` | `Admin@Secure123!` |
| `analyst_email` | `analyst@vulnguard.test` |
| `analyst_password` | `Analyst@Secure123!` |
| `guest_email` | `guest@vulnguard.test` |
| `guest_password` | `Guest@Secure123!` |
