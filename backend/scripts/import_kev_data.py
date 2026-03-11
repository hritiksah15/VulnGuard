"""Import CISA Known Exploited Vulnerabilities (KEV) catalog into VulnGuard.

Reads the downloaded CISA KEV JSON file and transforms each entry into a
VulnGuard vulnerability document with realistic enrichment data.

Usage:
    python -m scripts.import_kev_data [--limit N] [--skip-existing]
"""

import json
import os
import sys
import random
from datetime import datetime, timezone, timedelta
from bson import ObjectId
from pymongo import MongoClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import DevelopmentConfig
from utils.helpers import calculate_risk_score

KEV_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data', 'cisa_kev_catalog.json')

DEPARTMENTS = [
    "Engineering", "Finance", "Operations", "IT", "HR",
    "Marketing", "Security", "Legal", "Customer Support", "Research",
]

ASSET_TYPES = ["Server", "Workstation", "Network Device", "Application", "Database", "Cloud Service", "IoT Device", "Endpoint"]
STATUSES = ["Open", "In Progress", "Patched", "Accepted Risk"]
ATTACK_VECTORS = ["Network", "Adjacent", "Local", "Physical"]
EXPLOITABILITIES = ["Proof-of-Concept", "Functional", "High"]
VULNERABILITY_TYPES = ["Software", "Configuration", "Access Control"]
DISCOVERY_METHODS = ["Scan", "Audit", "Manual"]
USERNAMES = ["j.smith", "a.jones", "m.williams", "s.brown", "k.davis", "r.taylor"]

CWE_SEVERITY_BOOST = {
    "CWE-78": 1.5,   # OS Command Injection
    "CWE-77": 1.4,   # Command Injection
    "CWE-94": 1.4,   # Code Injection
    "CWE-502": 1.3,  # Deserialization
    "CWE-287": 1.3,  # Improper Authentication
    "CWE-798": 1.2,  # Hard-coded Credentials
    "CWE-89": 1.2,   # SQL Injection
    "CWE-79": 0.9,   # XSS
    "CWE-22": 1.1,   # Path Traversal
    "CWE-20": 1.0,   # Improper Input Validation
}


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def parse_date(date_str: str) -> datetime:
    """Parse a YYYY-MM-DD date string into a datetime object."""
    try:
        return datetime.strptime(date_str, "%Y-%m-%d")
    except (ValueError, TypeError):
        return utcnow()


def infer_cvss_score(kev_entry: dict) -> float:
    """Infer a CVSS score from KEV metadata (CWE, ransomware, description)."""
    base = 7.5
    desc = kev_entry.get("shortDescription", "").lower()
    ransomware = kev_entry.get("knownRansomwareCampaignUse", "Unknown")
    cwes = kev_entry.get("cwes", [])

    if ransomware == "Known":
        base = max(base, 9.0)
    elif ransomware == "Unknown":
        base += 0.3

    high_impact_terms = [
        ("remote code execution", 1.5), ("arbitrary code", 1.3),
        ("command injection", 1.2), ("authentication bypass", 1.1),
        ("privilege escalation", 1.0), ("memory corruption", 1.0),
        ("deserialization", 1.0), ("root access", 1.2),
        ("arbitrary file", 0.8), ("denial of service", 0.5),
    ]
    for term, boost in high_impact_terms:
        if term in desc:
            base += boost
            break

    for cwe in cwes:
        boost = CWE_SEVERITY_BOOST.get(cwe, 0)
        base += boost

    base += random.uniform(-0.5, 0.5)
    return round(min(max(base, 1.0), 10.0), 1)


def cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score >= 0.1:
        return "Low"
    return "Informational"


def infer_asset_name(vendor: str, product: str) -> str:
    """Generate a plausible asset name from vendor + product."""
    slug = product.lower().replace(" ", "-")[:20]
    num = random.randint(1, 5)
    domain = random.choice(["internal", "example.com", "corp.local", "prod.net"])
    return f"{slug}-{num:02d}.{domain}"


def infer_attack_vector(description: str) -> str:
    desc = description.lower()
    if any(k in desc for k in ["remote", "network", "unauthenticated", "internet"]):
        return "Network"
    if any(k in desc for k in ["adjacent", "local network"]):
        return "Adjacent"
    if any(k in desc for k in ["local", "physical access"]):
        return "Local"
    return random.choice(["Network", "Adjacent", "Local"])


def transform_kev_entry(entry: dict) -> dict:
    """Transform a single CISA KEV entry into a VulnGuard vulnerability document."""
    cve_id = entry["cveID"]
    vendor = entry.get("vendorProject", "Unknown")
    product = entry.get("product", "Unknown")
    vuln_name = entry.get("vulnerabilityName", f"Vulnerability in {vendor} {product}")
    description = entry.get("shortDescription", "No description available.")
    date_added = parse_date(entry.get("dateAdded", ""))
    due_date = parse_date(entry.get("dueDate", ""))
    ransomware = entry.get("knownRansomwareCampaignUse", "Unknown")
    notes = entry.get("notes", "")
    cwes = entry.get("cwes", [])

    cvss_score = infer_cvss_score(entry)
    severity = cvss_to_severity(cvss_score)
    attack_vector = infer_attack_vector(description)
    exploitability = random.choice(EXPLOITABILITIES)

    # Determine status based on how old the entry is
    days_since_added = (utcnow() - date_added).days
    if days_since_added > 365:
        status = random.choices(STATUSES, weights=[5, 10, 40, 45], k=1)[0]
    elif days_since_added > 90:
        status = random.choices(STATUSES, weights=[10, 25, 30, 35], k=1)[0]
    else:
        status = random.choices(STATUSES, weights=[35, 30, 15, 20], k=1)[0]

    patch_applied = status in ("Patched", "Accepted Risk")
    created_at = date_added
    updated_at = created_at + timedelta(days=random.randint(0, min(days_since_added, 60))) if days_since_added > 0 else created_at

    # Build references from notes
    references = [url.strip() for url in notes.split(";") if url.strip().startswith("http")]

    vuln = {
        "vulnerability_title": vuln_name,
        "description": description,
        "cve_id": cve_id,
        "severity": severity,
        "status": status,
        "cvss_score": cvss_score,
        "asset_name": infer_asset_name(vendor, product),
        "asset_type": random.choice(ASSET_TYPES),
        "vulnerability_type": random.choice(VULNERABILITY_TYPES),
        "discovery_method": random.choice(DISCOVERY_METHODS),
        "department": random.choice(DEPARTMENTS),
        "affected_versions": [],
        "attack_vector": attack_vector,
        "exploitability": exploitability,
        "patch_due_date": due_date,
        "patch_applied": patch_applied,
        "assigned_to": random.choice(USERNAMES),
        "reported_by": "cisa-kev-import",
        "vendor": vendor,
        "product": product,
        "cwes": cwes,
        "references": references[:5],
        "known_ransomware": ransomware,
        "risk_score": calculate_risk_score(cvss_score, exploitability, severity),
        "remediation_steps": [{
            "_id": ObjectId(),
            "step_number": 1,
            "step_description": entry.get("requiredAction", "Apply vendor patches and mitigations."),
            "recommended_by": random.choice(USERNAMES),
            "status": "Completed" if patch_applied else "Pending",
            "due_date": due_date,
            "completed_date": updated_at if patch_applied else None,
            "notes": f"CISA required action for {cve_id}",
            "created_at": created_at,
        }],
        "activity_log": [{
            "_id": ObjectId(),
            "performed_at": created_at,
            "action": "Imported from CISA KEV",
            "performed_by": "system",
            "details": f"Automatically imported from CISA Known Exploited Vulnerabilities catalog ({cve_id})",
            "previous_value": None,
            "new_value": None,
        }],
        "created_at": created_at,
        "updated_at": updated_at,
        "created_by": "cisa-kev-import",
    }

    return vuln


def import_kev_data(limit: int = 0, skip_existing: bool = True):
    """Import CISA KEV catalog into VulnGuard MongoDB.

    Args:
        limit: Max entries to import (0 = all).
        skip_existing: Skip CVEs already in the database.
    """
    print("\n🛡️  VulnGuard CISA KEV Importer")
    print("=" * 50)

    if not os.path.exists(KEV_FILE):
        print(f"  ❌ KEV file not found: {KEV_FILE}")
        print("  ℹ️  Run 'python -m scripts.download_dataset' first.")
        sys.exit(1)

    with open(KEV_FILE, 'r') as f:
        catalog = json.load(f)

    entries = catalog.get("vulnerabilities", [])
    catalog_version = catalog.get("catalogVersion", "unknown")
    print(f"  📋 Catalog version: {catalog_version}")
    print(f"  📊 Total KEV entries: {len(entries)}")

    if limit > 0:
        entries = entries[:limit]
        print(f"  🔢 Limiting to: {limit} entries")

    mongo_uri = os.environ.get('MONGO_URI', DevelopmentConfig.MONGO_URI)
    client = MongoClient(mongo_uri)
    db_name = mongo_uri.rsplit('/', 1)[-1].split('?')[0]
    db = client[db_name]
    print(f"  📦 Database: {db_name}")

    existing_cves = set()
    if skip_existing:
        cursor = db.vulnerabilities.find({"cve_id": {"$regex": "^CVE-"}}, {"cve_id": 1})
        existing_cves = {doc["cve_id"] for doc in cursor}
        print(f"  📌 Existing CVEs in DB: {len(existing_cves)}")

    vulnerabilities = []
    skipped = 0
    for entry in entries:
        cve_id = entry.get("cveID", "")
        if skip_existing and cve_id in existing_cves:
            skipped += 1
            continue
        vuln = transform_kev_entry(entry)
        vulnerabilities.append(vuln)

    print(f"\n  🔄 Transformed: {len(vulnerabilities)} new entries")
    if skipped:
        print(f"  ⏭️  Skipped (already exist): {skipped}")

    if vulnerabilities:
        batch_size = 500
        inserted = 0
        for i in range(0, len(vulnerabilities), batch_size):
            batch = vulnerabilities[i:i + batch_size]
            db.vulnerabilities.insert_many(batch)
            inserted += len(batch)
            print(f"  📥 Inserted batch: {inserted}/{len(vulnerabilities)}")

        print(f"\n  ✅ Successfully imported {len(vulnerabilities)} CISA KEV vulnerabilities")
    else:
        print("\n  ℹ️  No new vulnerabilities to import")

    total = db.vulnerabilities.count_documents({})
    kev_total = db.vulnerabilities.count_documents({"created_by": "cisa-kev-import"})
    print(f"\n{'=' * 50}")
    print(f"  📊 Total vulnerabilities: {total}")
    print(f"  🛡️  From CISA KEV: {kev_total}")
    print(f"  ✅ Import complete!\n")


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="Import CISA KEV catalog into VulnGuard")
    parser.add_argument("--limit", type=int, default=0, help="Max entries to import (0 = all)")
    parser.add_argument("--skip-existing", action="store_true", default=True, help="Skip CVEs already in DB")
    parser.add_argument("--no-skip", action="store_true", help="Import all, even duplicates")
    args = parser.parse_args()

    skip = not args.no_skip
    import_kev_data(limit=args.limit, skip_existing=skip)
