"""Download and import open source CVE data from NIST NVD into VulnGuard format.

This script downloads a recent CVE dataset from the NIST National Vulnerability
Database (NVD) feed and transforms it into VulnGuard vulnerability documents.

Usage:
    python -m scripts.import_cve_data
"""

import json
import os
import sys
import gzip
import random
import urllib.request
from datetime import datetime, timezone, timedelta
from io import BytesIO
from bson import ObjectId
from pymongo import MongoClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import DevelopmentConfig
from utils.helpers import calculate_risk_score

# NVD CVE data feed (JSON 1.1 format) – 2024 recent feed
NVD_FEED_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2024.json.gz"
# Fallback: use the CVE List from cvelistV5 on GitHub (smaller, more accessible)
GITHUB_CVE_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2024/0xxx/CVE-2024-0001.json"

DEPARTMENTS = [
    "Engineering", "Finance", "Operations", "IT", "HR",
    "Marketing", "Security", "Legal", "Customer Support", "Research"
]

ASSET_NAMES = [
    "web-app-01.example.com", "web-app-02.example.com",
    "api-gateway-01.internal", "db-server-01.internal",
    "db-server-02.internal", "mail-server-01.example.com",
    "fw-edge-01.perimeter", "vpn-gateway-01.internal",
    "docker-host-01.internal", "k8s-node-01.internal",
    "cloud-compute-01.aws", "erp-system.internal",
    "ci-cd-pipeline.internal", "file-server-01.internal",
]

ASSET_TYPES = ["Server", "Workstation", "Network Device", "Application", "Database", "Cloud Service", "IoT Device", "Endpoint"]
STATUSES = ["Open", "In Progress", "Patched", "Accepted Risk"]
ATTACK_VECTORS = ["Network", "Adjacent", "Local", "Physical"]
EXPLOITABILITIES = ["Unproven", "Proof-of-Concept", "Functional", "High"]
VULNERABILITY_TYPES = ["Software", "Configuration", "Access Control"]
DISCOVERY_METHODS = ["Scan", "Audit", "Manual"]
USERNAMES = ["j.smith", "a.jones", "m.williams", "s.brown", "k.davis"]


def utcnow() -> datetime:
    """Return current UTC datetime (timezone-naive)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def cvss_to_severity(score: float) -> str:
    """Map CVSS score to severity label."""
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score >= 0.1:
        return "Low"
    return "Informational"


def download_nvd_feed(max_cves: int = 200) -> list[dict]:
    """Download and parse NVD CVE JSON feed.

    Args:
        max_cves: Maximum number of CVEs to import.

    Returns:
        List of parsed CVE items.
    """
    print(f"  📥 Downloading NVD CVE feed from: {NVD_FEED_URL}")

    try:
        req = urllib.request.Request(
            NVD_FEED_URL,
            headers={"User-Agent": "VulnGuard/1.0 (COM661 Coursework)"}
        )
        response = urllib.request.urlopen(req, timeout=60)
        compressed = BytesIO(response.read())

        print("  📦 Decompressing data...")
        with gzip.open(compressed, 'rb') as f:
            data = json.loads(f.read())

        cve_items = data.get('CVE_Items', [])
        print(f"  ✅ Downloaded {len(cve_items)} CVEs from NVD feed")
        return cve_items[:max_cves]

    except Exception as e:
        print(f"  ⚠️  NVD feed download failed: {e}")
        print("  ℹ️  Generating synthetic CVE dataset instead...")
        return []


def generate_synthetic_cve_data(count: int = 200) -> list[dict]:
    """Generate synthetic CVE data when NVD feed is unavailable.

    Args:
        count: Number of CVE entries to generate.

    Returns:
        List of synthetic CVE item dicts.
    """
    products = [
        ("Apache HTTP Server", "Apache Software Foundation"),
        ("nginx", "Nginx Inc"),
        ("OpenSSL", "OpenSSL Project"),
        ("WordPress", "WordPress Foundation"),
        ("PostgreSQL", "PostgreSQL Global Development Group"),
        ("MySQL", "Oracle Corporation"),
        ("Redis", "Redis Ltd"),
        ("Docker Engine", "Docker Inc"),
        ("Kubernetes", "Cloud Native Computing Foundation"),
        ("Jenkins", "Jenkins Project"),
        ("Grafana", "Grafana Labs"),
        ("Elasticsearch", "Elastic"),
        ("MongoDB Server", "MongoDB Inc"),
        ("Node.js", "OpenJS Foundation"),
        ("Django", "Django Software Foundation"),
        ("Flask", "Pallets Projects"),
        ("Spring Framework", "VMware"),
        ("React", "Meta Platforms"),
        ("Linux Kernel", "Linux Foundation"),
        ("Windows Server", "Microsoft Corporation"),
    ]

    vuln_types = [
        ("Buffer Overflow", "A buffer overflow vulnerability allows remote attackers to execute arbitrary code via crafted input."),
        ("SQL Injection", "An SQL injection vulnerability in the query parameter allows attackers to execute arbitrary SQL commands."),
        ("Cross-Site Scripting", "A stored XSS vulnerability allows attackers to inject malicious scripts through user-supplied input."),
        ("Remote Code Execution", "A deserialization vulnerability allows unauthenticated remote code execution."),
        ("Path Traversal", "A path traversal vulnerability allows attackers to access arbitrary files on the system."),
        ("Denial of Service", "A resource exhaustion vulnerability allows attackers to cause denial of service via crafted requests."),
        ("Authentication Bypass", "An authentication bypass vulnerability allows unauthenticated access to protected resources."),
        ("Information Disclosure", "An information disclosure vulnerability exposes sensitive data through error messages."),
        ("Privilege Escalation", "A privilege escalation vulnerability allows low-privileged users to gain administrator access."),
        ("CSRF", "A cross-site request forgery vulnerability allows attackers to perform actions on behalf of authenticated users."),
        ("XML External Entity", "An XXE vulnerability allows attackers to read arbitrary files and perform SSRF attacks."),
        ("Server-Side Request Forgery", "An SSRF vulnerability allows attackers to make requests to internal services."),
        ("Insecure Deserialization", "An insecure deserialization vulnerability allows arbitrary object injection leading to RCE."),
        ("Improper Access Control", "An improper access control vulnerability allows unauthorized access to administrative functions."),
        ("Use After Free", "A use-after-free vulnerability in memory management allows arbitrary code execution."),
    ]

    items = []
    for i in range(count):
        product_name, vendor = random.choice(products)
        vuln_type, description_template = random.choice(vuln_types)
        year = random.choice([2024, 2025, 2026])
        cve_id = f"CVE-{year}-{random.randint(10000, 99999)}"
        cvss_score = round(random.uniform(0.1, 10.0), 1)
        version = f"{random.randint(1,15)}.{random.randint(0,20)}.{random.randint(0,50)}"

        item = {
            "cve_id": cve_id,
            "vulnerability_title": f"{vuln_type} in {product_name} {version}",
            "description": f"{description_template} This affects {product_name} version {version} and earlier. {vendor} has been notified.",
            "cvss_score": cvss_score,
            "severity": cvss_to_severity(cvss_score),
            "attack_vector": random.choice(ATTACK_VECTORS),
            "published_date": (utcnow() - timedelta(days=random.randint(1, 365))).isoformat(),
            "affected_versions": [version, f"{random.randint(1,10)}.{random.randint(0,15)}.{random.randint(0,30)}"],
        }
        items.append(item)

    print(f"  ✅ Generated {len(items)} synthetic CVE entries")
    return items


def transform_nvd_to_vulnguard(cve_items: list[dict]) -> list[dict]:
    """Transform NVD CVE items to VulnGuard vulnerability documents.

    Args:
        cve_items: List of NVD CVE item dicts.

    Returns:
        List of VulnGuard vulnerability documents.
    """
    vulnerabilities = []

    for item in cve_items:
        # NVD JSON 1.1 format
        cve_data = item.get('cve', {})
        cve_id = cve_data.get('CVE_data_meta', {}).get('ID', '')

        # Get description
        desc_data = cve_data.get('description', {}).get('description_data', [])
        description = desc_data[0].get('value', 'No description available') if desc_data else 'No description available'

        if description.startswith('** RESERVED **') or description.startswith('** REJECT **'):
            continue

        # Get CVSS score
        impact = item.get('impact', {})
        cvss_v3 = impact.get('baseMetricV3', {}).get('cvssV3', {})
        cvss_v2 = impact.get('baseMetricV2', {}).get('cvssV2', {})

        if cvss_v3:
            cvss_score = cvss_v3.get('baseScore', 5.0)
            attack_vector_map = {
                "NETWORK": "Network",
                "ADJACENT_NETWORK": "Adjacent",
                "LOCAL": "Local",
                "PHYSICAL": "Physical",
            }
            attack_vector = attack_vector_map.get(cvss_v3.get('attackVector', ''), 'Network')
        elif cvss_v2:
            cvss_score = cvss_v2.get('baseScore', 5.0)
            attack_vector = "Network"
        else:
            cvss_score = round(random.uniform(1.0, 8.0), 1)
            attack_vector = random.choice(ATTACK_VECTORS)

        severity = cvss_to_severity(cvss_score)
        exploitability = random.choice(EXPLOITABILITIES)
        status = random.choice(STATUSES)
        created_at = utcnow() - timedelta(days=random.randint(5, 180))
        patch_applied = status in ["Patched", "Accepted Risk"] and random.random() > 0.3

        title = description[:150].strip()
        if len(title) < 5:
            title = f"Vulnerability {cve_id}"

        vuln = {
            "vulnerability_title": title,
            "description": description[:5000],
            "cve_id": cve_id,
            "severity": severity,
            "status": status,
            "cvss_score": cvss_score,
            "asset_name": random.choice(ASSET_NAMES),
            "asset_type": random.choice(ASSET_TYPES),
            "vulnerability_type": random.choice(VULNERABILITY_TYPES),
            "discovery_method": random.choice(DISCOVERY_METHODS),
            "department": random.choice(DEPARTMENTS),
            "affected_versions": [f"{random.randint(1,10)}.{random.randint(0,20)}.{random.randint(0,50)}"],
            "attack_vector": attack_vector,
            "exploitability": exploitability,
            "patch_due_date": (utcnow() + timedelta(days=random.randint(-30, 60))),
            "patch_applied": patch_applied,
            "assigned_to": random.choice(USERNAMES),
            "reported_by": "nvd-import",
            "risk_score": calculate_risk_score(cvss_score, exploitability, severity),
            "remediation_steps": [],
            "activity_log": [{
                "_id": ObjectId(),
                "performed_at": created_at,
                "action": "Imported from NVD",
                "performed_by": "system",
                "details": f"Automatically imported from National Vulnerability Database ({cve_id})",
                "previous_value": None,
                "new_value": None,
            }],
            "created_at": created_at,
            "updated_at": created_at,
            "created_by": "nvd-import",
        }
        vulnerabilities.append(vuln)

    return vulnerabilities


def transform_synthetic_to_vulnguard(items: list[dict]) -> list[dict]:
    """Transform synthetic CVE data to VulnGuard documents.

    Args:
        items: List of synthetic CVE dicts.

    Returns:
        List of VulnGuard vulnerability documents.
    """
    vulnerabilities = []

    for item in items:
        status = random.choice(STATUSES)
        created_at = utcnow() - timedelta(days=random.randint(5, 180))
        patch_applied = status in ["Patched", "Accepted Risk"] and random.random() > 0.3
        exploitability = random.choice(EXPLOITABILITIES)

        vuln = {
            "vulnerability_title": item["vulnerability_title"],
            "description": item["description"],
            "cve_id": item["cve_id"],
            "severity": item["severity"],
            "status": status,
            "cvss_score": item["cvss_score"],
            "asset_name": random.choice(ASSET_NAMES),
            "asset_type": random.choice(ASSET_TYPES),
            "vulnerability_type": random.choice(VULNERABILITY_TYPES),
            "discovery_method": random.choice(DISCOVERY_METHODS),
            "department": random.choice(DEPARTMENTS),
            "affected_versions": item.get("affected_versions", []),
            "attack_vector": item.get("attack_vector", random.choice(ATTACK_VECTORS)),
            "exploitability": exploitability,
            "patch_due_date": (utcnow() + timedelta(days=random.randint(-30, 60))),
            "patch_applied": patch_applied,
            "assigned_to": random.choice(USERNAMES),
            "reported_by": "cve-import",
            "risk_score": calculate_risk_score(item["cvss_score"], exploitability, item["severity"]),
            "remediation_steps": [],
            "activity_log": [{
                "_id": ObjectId(),
                "performed_at": created_at,
                "action": "Imported from CVE database",
                "performed_by": "system",
                "details": f"Automatically imported ({item['cve_id']})",
                "previous_value": None,
                "new_value": None,
            }],
            "created_at": created_at,
            "updated_at": created_at,
            "created_by": "cve-import",
        }
        vulnerabilities.append(vuln)

    return vulnerabilities


def import_cve_data():
    """Main import function."""
    print("\n🌐 VulnGuard CVE Data Importer")
    print("=" * 50)

    mongo_uri = os.environ.get('MONGO_URI', DevelopmentConfig.MONGO_URI)
    client = MongoClient(mongo_uri)
    db_name = mongo_uri.rsplit('/', 1)[-1].split('?')[0]
    db = client[db_name]

    print(f"\n📦 Connected to: {db_name}")

    # Try to download NVD feed
    cve_items = download_nvd_feed(max_cves=200)

    if cve_items:
        print("\n🔄 Transforming NVD data to VulnGuard format...")
        vulnerabilities = transform_nvd_to_vulnguard(cve_items)
    else:
        print("\n🔄 Generating and transforming synthetic CVE data...")
        synthetic = generate_synthetic_cve_data(200)
        vulnerabilities = transform_synthetic_to_vulnguard(synthetic)

    if vulnerabilities:
        print(f"\n📥 Inserting {len(vulnerabilities)} vulnerabilities into database...")
        db.vulnerabilities.insert_many(vulnerabilities)
        print(f"  ✅ Inserted {len(vulnerabilities)} CVE-based vulnerabilities")
    else:
        print("  ⚠️  No vulnerabilities to insert")

    # Print summary
    total = db.vulnerabilities.count_documents({})
    print(f"\n{'=' * 50}")
    print(f"✅ Import complete!")
    print(f"   Total vulnerabilities in database: {total}")
    print()


if __name__ == '__main__':
    import_cve_data()
