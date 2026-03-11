# Seeds

Database seeding script that populates MongoDB with realistic vulnerability data for development and testing.

## Usage

```bash
cd backend
python -m seeds.seed_data
```

## What Gets Created

| Collection | Count | Description |
|-----------|:-----:|-------------|
| `users` | 3 | Admin, analyst, guest (bcrypt-hashed passwords) |
| `vulnerabilities` | 109 | Realistic vulnerability records with full field coverage |
| Remediation steps | ~0–4 per vuln | Embedded sub-documents in `remediation_steps` array |
| Activity log entries | ~0–5 per vuln | Embedded sub-documents in `activity_log` array |

## Seeded Users

| Username | Email | Password | Role |
|----------|-------|----------|------|
| admin | admin@vulnguard.test | Admin@Secure123! | admin |
| analyst | analyst@vulnguard.test | Analyst@Secure123! | analyst |
| guest | guest@vulnguard.test | Guest@Secure123! | guest |

## Data Features

- **26 vulnerability templates** covering real-world CVE types (SQL injection, XSS, IDOR, SSRF, RCE, etc.)
- **10 GeoJSON Point locations** — Belfast, Dublin, London, New York, San Francisco, Singapore, Sydney, Birmingham, Manchester, Edinburgh
- Every vulnerability includes: title, description, CVE ID, severity, CVSS score, department, asset, attack vector, exploitability, risk score, dates, and a random `location`
- **Indexes created** — single-field, compound, text, 2dsphere, unique (email, username), TTL (blacklist)

## File

| File | Purpose |
|------|---------|
| `seed_data.py` | Main seeding script (787 lines) — drops existing data and recreates everything |
| `__init__.py` | Package marker |
