# Scripts

Data import utilities for populating the VulnGuard database with real-world vulnerability data from public sources.

## Available Scripts

### `download_dataset.py` — Download CISA KEV Catalog

Downloads the [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog (public domain JSON) to `data/`.

```bash
python -m scripts.download_dataset
```

### `import_kev_data.py` — Import KEV Data

Imports the downloaded CISA KEV JSON into VulnGuard vulnerability format.

```bash
python -m scripts.import_kev_data [--limit N] [--skip-existing]
```

| Flag | Description |
|------|-------------|
| `--limit N` | Import only N records |
| `--skip-existing` | Skip CVE IDs already in the database |

Features CWE-based severity boost weights for realistic risk scoring.

### `import_cve_data.py` — Import NIST NVD CVE Data

Downloads and imports NIST National Vulnerability Database CVE data (JSON 1.1 gzip feed). Falls back to GitHub CVEProject mirror if NIST is unavailable.

```bash
python -m scripts.import_cve_data [--year YYYY] [--limit N]
```

## Data Flow

```
CISA / NIST (Public APIs)
  │
  ▼
download_dataset.py → data/cisa_kev_catalog.json
  │
  ▼
import_kev_data.py → MongoDB vulnguard.vulnerabilities
import_cve_data.py → MongoDB vulnguard.vulnerabilities
```

## Files

| File | Purpose |
|------|---------|
| `download_dataset.py` | Downloads CISA KEV catalog JSON (190 lines) |
| `import_kev_data.py` | KEV → VulnGuard format importer (294 lines) |
| `import_cve_data.py` | NVD CVE → VulnGuard format importer (364 lines) |
| `__init__.py` | Package marker |
