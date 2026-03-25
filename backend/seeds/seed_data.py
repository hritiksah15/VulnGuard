"""Database seeding script with comprehensive vulnerability data.

Usage:
    python -m seeds.seed_data

This script populates the VulnGuard database with realistic vulnerability
data including users, vulnerabilities with sub-documents (remediation steps
and activity logs).
"""

import os
import sys
import random
from datetime import datetime, timedelta, timezone
from bson import ObjectId
from pymongo import MongoClient
import bcrypt

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import DevelopmentConfig
from utils.helpers import calculate_risk_score


def utcnow() -> datetime:
    """Return current UTC datetime (timezone-naive)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def random_date(start_days_ago: int = 180, end_days_ago: int = 0) -> datetime:
    """Generate a random datetime within a range of days ago."""
    days = random.randint(end_days_ago, start_days_ago)
    return utcnow() - timedelta(days=days, hours=random.randint(0, 23), minutes=random.randint(0, 59))


def random_future_date(min_days: int = 1, max_days: int = 90) -> datetime:
    """Generate a random future datetime."""
    days = random.randint(min_days, max_days)
    return utcnow() + timedelta(days=days)


def random_past_date_or_future(past_probability: float = 0.3) -> datetime:
    """Generate a date that may be in the past (overdue) or future."""
    if random.random() < past_probability:
        return random_date(60, 1)  # Overdue
    return random_future_date(1, 90)


DEPARTMENTS = [
    "Engineering", "Finance", "Operations", "IT", "HR",
    "Marketing", "Security", "Legal", "Customer Support", "Research"
]

ASSET_NAMES = [
    "web-app-01.example.com", "web-app-02.example.com",
    "api-gateway-01.internal", "api-gateway-02.internal",
    "db-server-01.internal", "db-server-02.internal", "db-server-03.internal",
    "mail-server-01.example.com", "fw-edge-01.perimeter", "fw-edge-02.perimeter",
    "vpn-gateway-01.internal", "dns-server-01.internal",
    "file-server-01.internal", "backup-server-01.internal",
    "ci-cd-pipeline.internal", "docker-host-01.internal",
    "k8s-node-01.internal", "k8s-node-02.internal",
    "workstation-finance-01", "workstation-hr-01",
    "iot-sensor-01.factory", "iot-sensor-02.factory",
    "cloud-storage-01.aws", "cloud-compute-01.aws",
    "erp-system.internal", "crm-system.internal",
]

ASSET_TYPES = ["Server", "Workstation", "Network Device", "Application", "Database", "Cloud Service", "IoT Device"]

# Geo-coordinates for asset locations (longitude, latitude).
# Covers Belfast, Dublin, London, New York, San Francisco, Singapore, Sydney.
ASSET_LOCATIONS = [
    {"type": "Point", "coordinates": [-5.9301, 54.5973]},   # Belfast
    {"type": "Point", "coordinates": [-6.2603, 53.3498]},   # Dublin
    {"type": "Point", "coordinates": [-0.1276, 51.5074]},   # London
    {"type": "Point", "coordinates": [-73.9857, 40.7484]},  # New York
    {"type": "Point", "coordinates": [-122.4194, 37.7749]}, # San Francisco
    {"type": "Point", "coordinates": [103.8198, 1.3521]},   # Singapore
    {"type": "Point", "coordinates": [151.2093, -33.8688]}, # Sydney
    {"type": "Point", "coordinates": [-1.8904, 52.4862]},   # Birmingham
    {"type": "Point", "coordinates": [-2.2426, 53.4808]},   # Manchester
    {"type": "Point", "coordinates": [-3.1883, 55.9533]},   # Edinburgh
]
SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"]
STATUSES = ["Open", "In Progress", "Patched", "Accepted Risk"]
ATTACK_VECTORS = ["Network", "Adjacent", "Local", "Physical"]
EXPLOITABILITIES = ["Unproven", "Proof-of-Concept", "Functional", "High"]
REMEDIATION_STATUSES = ["Pending", "In Progress", "Completed", "Skipped"]
VULNERABILITY_TYPES = ["Software", "Configuration", "Access Control"]
DISCOVERY_METHODS = ["Scan", "Audit", "Manual"]

VULNERABILITY_TEMPLATES = [
    {
        "vulnerability_title": "SQL Injection in Login Form",
        "description": "The login form is vulnerable to SQL injection through the username field. An attacker can bypass authentication by injecting SQL commands into the login parameters.",
        "cve_id": "CVE-2025-12345",
        "severity": "Critical",
        "cvss_score": 9.8,
        "attack_vector": "Network",
        "exploitability": "Functional",
    },
    {
        "vulnerability_title": "Remote Code Execution via Deserialization",
        "description": "The application deserializes untrusted data from user input allowing an attacker to execute arbitrary code on the server through crafted serialized objects.",
        "cve_id": "CVE-2025-23456",
        "severity": "Critical",
        "cvss_score": 9.5,
        "attack_vector": "Network",
        "exploitability": "High",
    },
    {
        "vulnerability_title": "Cross-Site Scripting in Comment Field",
        "description": "Stored XSS vulnerability in the comment field of the blog module allows attackers to inject malicious scripts that execute in other users' browsers.",
        "cve_id": "CVE-2025-34567",
        "severity": "High",
        "cvss_score": 7.5,
        "attack_vector": "Network",
        "exploitability": "Functional",
    },
    {
        "vulnerability_title": "Privilege Escalation through IDOR",
        "description": "Insecure Direct Object Reference vulnerability allows authenticated users to access and modify other users' data by manipulating resource identifiers in API requests.",
        "cve_id": "CVE-2025-45678",
        "severity": "High",
        "cvss_score": 8.1,
        "attack_vector": "Network",
        "exploitability": "Proof-of-Concept",
    },
    {
        "vulnerability_title": "Server-Side Request Forgery in URL Preview",
        "description": "The URL preview feature allows SSRF attacks enabling an attacker to make requests to internal services and potentially access sensitive metadata endpoints.",
        "cve_id": "CVE-2025-56789",
        "severity": "High",
        "cvss_score": 7.8,
        "attack_vector": "Network",
        "exploitability": "Functional",
    },
    {
        "vulnerability_title": "Outdated TLS Configuration",
        "description": "The web server supports TLS 1.0 and weak cipher suites that are vulnerable to known attacks such as BEAST and POODLE.",
        "severity": "Medium",
        "cvss_score": 5.3,
        "attack_vector": "Network",
        "exploitability": "Proof-of-Concept",
    },
    {
        "vulnerability_title": "Missing HTTP Security Headers",
        "description": "Several security headers are missing from HTTP responses including Content-Security-Policy, X-Frame-Options, and Strict-Transport-Security.",
        "severity": "Medium",
        "cvss_score": 4.7,
        "attack_vector": "Network",
        "exploitability": "Unproven",
    },
    {
        "vulnerability_title": "Unpatched OpenSSL Vulnerability",
        "description": "The server is running an outdated version of OpenSSL with known vulnerabilities that could allow man-in-the-middle attacks or information disclosure.",
        "cve_id": "CVE-2025-67890",
        "severity": "High",
        "cvss_score": 7.4,
        "attack_vector": "Network",
        "exploitability": "Proof-of-Concept",
    },
    {
        "vulnerability_title": "Default Credentials on Admin Panel",
        "description": "The administrative panel is accessible with default credentials. An attacker could gain full administrative control of the system.",
        "severity": "Critical",
        "cvss_score": 9.1,
        "attack_vector": "Network",
        "exploitability": "High",
    },
    {
        "vulnerability_title": "Directory Traversal in File Upload",
        "description": "The file upload functionality does not properly sanitise file paths, allowing an attacker to upload files to arbitrary locations on the server.",
        "cve_id": "CVE-2025-78901",
        "severity": "High",
        "cvss_score": 7.2,
        "attack_vector": "Network",
        "exploitability": "Functional",
    },
    {
        "vulnerability_title": "Weak Password Policy Enforcement",
        "description": "The application allows users to set weak passwords without enforcing minimum complexity requirements, increasing the risk of brute force attacks.",
        "severity": "Medium",
        "cvss_score": 5.0,
        "attack_vector": "Network",
        "exploitability": "Unproven",
    },
    {
        "vulnerability_title": "Information Disclosure in Error Messages",
        "description": "Detailed stack traces and internal system information are exposed in error messages when the application encounters unhandled exceptions.",
        "severity": "Medium",
        "cvss_score": 4.3,
        "attack_vector": "Network",
        "exploitability": "Unproven",
    },
    {
        "vulnerability_title": "Insecure Session Management",
        "description": "Session tokens are not properly invalidated upon logout and session IDs are predictable, allowing session hijacking attacks.",
        "severity": "High",
        "cvss_score": 7.6,
        "attack_vector": "Network",
        "exploitability": "Proof-of-Concept",
    },
    {
        "vulnerability_title": "CSV Injection in Export Feature",
        "description": "User-supplied data is included in CSV exports without sanitisation, allowing formula injection that could lead to code execution when opened in spreadsheet applications.",
        "severity": "Medium",
        "cvss_score": 5.5,
        "attack_vector": "Local",
        "exploitability": "Proof-of-Concept",
    },
    {
        "vulnerability_title": "Unencrypted Database Connection",
        "description": "The application connects to the database without TLS encryption, exposing sensitive data and credentials to potential network sniffing attacks.",
        "severity": "High",
        "cvss_score": 6.8,
        "attack_vector": "Adjacent",
        "exploitability": "Proof-of-Concept",
    },
    {
        "vulnerability_title": "Exposed Kubernetes Dashboard",
        "description": "The Kubernetes dashboard is exposed to the internet without authentication, allowing potential access to cluster management functions.",
        "severity": "Critical",
        "cvss_score": 9.3,
        "attack_vector": "Network",
        "exploitability": "Functional",
    },
    {
        "vulnerability_title": "XML External Entity Processing",
        "description": "The XML parser in the document upload feature is configured to process external entities, enabling XXE attacks that could lead to sensitive file disclosure.",
        "cve_id": "CVE-2025-89012",
        "severity": "High",
        "cvss_score": 7.9,
        "attack_vector": "Network",
        "exploitability": "Functional",
    },
    {
        "vulnerability_title": "Insufficient Logging and Monitoring",
        "description": "The application does not adequately log security-relevant events such as failed login attempts, making it difficult to detect and respond to attacks.",
        "severity": "Low",
        "cvss_score": 3.2,
        "attack_vector": "Network",
        "exploitability": "Unproven",
    },
    {
        "vulnerability_title": "CORS Misconfiguration",
        "description": "The Cross-Origin Resource Sharing policy is misconfigured with wildcard origins, potentially allowing malicious websites to make authenticated requests.",
        "severity": "Medium",
        "cvss_score": 5.8,
        "attack_vector": "Network",
        "exploitability": "Proof-of-Concept",
    },
    {
        "vulnerability_title": "Unvalidated Redirect in OAuth Flow",
        "description": "The OAuth redirect URI parameter is not validated against a whitelist, allowing an attacker to redirect users to malicious sites after authentication.",
        "severity": "Medium",
        "cvss_score": 4.9,
        "attack_vector": "Network",
        "exploitability": "Proof-of-Concept",
    },
    {
        "vulnerability_title": "Hardcoded API Keys in Source Code",
        "description": "API keys and secret tokens for third-party services are hardcoded in the application source code and visible in the version control repository.",
        "severity": "High",
        "cvss_score": 7.0,
        "attack_vector": "Network",
        "exploitability": "Functional",
    },
    {
        "vulnerability_title": "Denial of Service via ReDoS",
        "description": "Regular expression denial of service vulnerability in the input validation logic. A crafted input string can cause catastrophic backtracking in the regex engine.",
        "severity": "Medium",
        "cvss_score": 5.9,
        "attack_vector": "Network",
        "exploitability": "Proof-of-Concept",
    },
    {
        "vulnerability_title": "Broken Object Level Authorization",
        "description": "API endpoints do not properly verify that the authenticated user has permission to access the requested resource object.",
        "severity": "High",
        "cvss_score": 7.3,
        "attack_vector": "Network",
        "exploitability": "Functional",
    },
    {
        "vulnerability_title": "Sensitive Data in Local Storage",
        "description": "The frontend application stores sensitive authentication tokens and user data in browser localStorage, which is accessible to XSS attacks.",
        "severity": "Low",
        "cvss_score": 3.7,
        "attack_vector": "Local",
        "exploitability": "Unproven",
    },
    {
        "vulnerability_title": "Mass Assignment Vulnerability",
        "description": "API endpoints accept and process all user-supplied fields without proper filtering, allowing attackers to modify protected fields such as role and permissions.",
        "severity": "High",
        "cvss_score": 7.1,
        "attack_vector": "Network",
        "exploitability": "Functional",
    },
    {
        "vulnerability_title": "Outdated WordPress Installation",
        "description": "The marketing website runs WordPress version 5.8.2 with multiple known vulnerabilities. Several plugins are also outdated and vulnerable.",
        "cve_id": "CVE-2025-90123",
        "severity": "High",
        "cvss_score": 6.5,
        "attack_vector": "Network",
        "exploitability": "Proof-of-Concept",
    },
    {
        "vulnerability_title": "SSH Key Authentication Disabled",
        "description": "SSH server is configured to allow password-based authentication only, without key-based authentication enforcement, increasing brute force risk.",
        "severity": "Medium",
        "cvss_score": 4.5,
        "attack_vector": "Network",
        "exploitability": "Unproven",
    },
    {
        "vulnerability_title": "IoT Device Firmware Vulnerability",
        "description": "Factory floor IoT sensors are running firmware with a known buffer overflow vulnerability that could allow remote code execution.",
        "cve_id": "CVE-2025-01234",
        "severity": "Critical",
        "cvss_score": 9.0,
        "attack_vector": "Adjacent",
        "exploitability": "Proof-of-Concept",
    },
    {
        "vulnerability_title": "Clickjacking on Login Page",
        "description": "The login page can be embedded in an iframe on a malicious website, allowing clickjacking attacks that could trick users into performing unintended actions.",
        "severity": "Low",
        "cvss_score": 3.5,
        "attack_vector": "Network",
        "exploitability": "Unproven",
    },
    {
        "vulnerability_title": "Plaintext Password in Configuration File",
        "description": "Database passwords are stored in plaintext in the application configuration file rather than being managed through a secrets vault or environment variables.",
        "severity": "Medium",
        "cvss_score": 5.1,
        "attack_vector": "Local",
        "exploitability": "Unproven",
    },
]

REMEDIATION_ACTIONS = [
    "Apply vendor security patch to the affected component",
    "Update library to the latest stable version",
    "Implement input validation and sanitisation",
    "Configure TLS 1.2+ with strong cipher suites",
    "Add Content-Security-Policy and other security headers",
    "Implement parameterised queries across all DB interactions",
    "Rotate exposed credentials and API keys",
    "Enable multi-factor authentication",
    "Deploy web application firewall rules",
    "Conduct code review focusing on the affected module",
    "Implement rate limiting on authentication endpoints",
    "Configure proper CORS policy with explicit origins",
    "Deploy updated firmware to affected devices",
    "Add CSRF token validation to all state-changing forms",
    "Implement proper session invalidation on logout",
    "Move secrets to vault or environment variables",
    "Restrict network access using firewall rules",
    "Enable comprehensive logging and alerting",
    "Schedule penetration testing for the affected component",
    "Update access control checks in API middleware",
]

ACTIVITY_ACTIONS = [
    "Vulnerability created",
    "Vulnerability assigned",
    "Status changed",
    "Severity updated",
    "Remediation step added",
    "Remediation step completed",
    "Comment added",
    "Patch deadline extended",
    "Risk score recalculated",
    "Assigned to new analyst",
]

USERNAMES = [
    "j.smith", "a.jones", "m.williams", "s.brown", "k.davis",
    "r.wilson", "l.anderson", "d.taylor", "p.thomas", "n.garcia",
]


def create_users(db) -> list[dict]:
    """Create test user accounts."""
    db.users.delete_many({})

    users = []

    # Admin user
    admin = {
        "username": "admin",
        "email": "admin@vulnguard.test",
        "password_hash": bcrypt.hashpw("Admin@Secure123!".encode(), bcrypt.gensalt(12)).decode(),
        "role": "admin",
        "is_active": True,
        "created_at": utcnow() - timedelta(days=90),
        "last_login": utcnow() - timedelta(hours=2),
    }
    result = db.users.insert_one(admin)
    admin['_id'] = result.inserted_id
    users.append(admin)

    # Analyst user
    analyst = {
        "username": "analyst",
        "email": "analyst@vulnguard.test",
        "password_hash": bcrypt.hashpw("Analyst@Secure123!".encode(), bcrypt.gensalt(12)).decode(),
        "role": "analyst",
        "is_active": True,
        "created_at": utcnow() - timedelta(days=60),
        "last_login": utcnow() - timedelta(hours=5),
    }
    result = db.users.insert_one(analyst)
    analyst['_id'] = result.inserted_id
    users.append(analyst)

    # Guest user
    guest = {
        "username": "guest",
        "email": "guest@vulnguard.test",
        "password_hash": bcrypt.hashpw("Guest@Secure123!".encode(), bcrypt.gensalt(12)).decode(),
        "role": "guest",
        "is_active": True,
        "created_at": utcnow() - timedelta(days=30),
        "last_login": utcnow() - timedelta(days=1),
    }
    result = db.users.insert_one(guest)
    guest['_id'] = result.inserted_id
    users.append(guest)

    print(f"  ✅ Created {len(users)} users")
    return users


def generate_remediation_steps(created_at: datetime) -> list[dict]:
    """Generate random remediation steps for a vulnerability."""
    num_steps = random.randint(0, 4)
    steps = []

    for i in range(num_steps):
        status = random.choice(REMEDIATION_STATUSES)
        step = {
            "_id": ObjectId(),
            "step_number": i + 1,
            "step_description": random.choice(REMEDIATION_ACTIONS),
            "recommended_by": random.choice(USERNAMES),
            "status": status,
            "due_date": created_at + timedelta(days=random.randint(3, 30)),
            "completed_date": (created_at + timedelta(days=random.randint(1, 20))) if status == "Completed" else None,
            "notes": random.choice([
                "Requires server restart after patch application",
                "Coordinate with development team for deployment window",
                "Verify fix with regression testing",
                "Document changes in the change management system",
                None,
            ]),
            "added_at": created_at + timedelta(days=random.randint(0, 3)),
        }
        steps.append(step)

    return steps


def generate_activity_log(created_at: datetime, username: str) -> list[dict]:
    """Generate random activity log entries for a vulnerability."""
    entries = []

    # Always add a creation log entry
    entries.append({
        "_id": ObjectId(),
        "performed_at": created_at,
        "action": "Vulnerability created",
        "performed_by": username,
        "details": "Vulnerability discovered during security assessment",
        "previous_value": None,
        "new_value": None,
    })

    num_additional = random.randint(0, 5)
    for i in range(num_additional):
        action = random.choice(ACTIVITY_ACTIONS[1:])
        entry = {
            "_id": ObjectId(),
            "performed_at": created_at + timedelta(days=random.randint(1, 30), hours=random.randint(0, 23)),
            "action": action,
            "performed_by": random.choice(USERNAMES),
            "details": f"{action} - automated log entry",
            "previous_value": random.choice(["Open", "Medium", None]),
            "new_value": random.choice(["In Progress", "High", "j.smith", None]),
        }
        entries.append(entry)

    return sorted(entries, key=lambda x: x['performed_at'])


def create_vulnerabilities(db) -> int:
    """Create vulnerability documents from templates with variations."""
    db.vulnerabilities.delete_many({})

    vulnerabilities = []

    for template in VULNERABILITY_TEMPLATES:
        created_at = random_date(180, 5)
        status = random.choice(STATUSES)
        patch_applied = status in ["Patched", "Accepted Risk"] and random.random() > 0.3
        reporter = random.choice(USERNAMES + ["security-scanner", "penetration-test", "bug-bounty"])

        vuln = {
            "vulnerability_title": template["vulnerability_title"],
            "description": template["description"],
            "cve_id": template.get("cve_id"),
            "severity": template["severity"],
            "status": status,
            "cvss_score": template["cvss_score"],
            "asset_name": random.choice(ASSET_NAMES),
            "asset_type": random.choice(ASSET_TYPES),
            "vulnerability_type": random.choice(VULNERABILITY_TYPES),
            "discovery_method": random.choice(DISCOVERY_METHODS),
            "department": random.choice(DEPARTMENTS),
            "affected_versions": [f"{random.randint(1,5)}.{random.randint(0,9)}.{random.randint(0,9)}" for _ in range(random.randint(1, 3))],
            "attack_vector": template.get("attack_vector", random.choice(ATTACK_VECTORS)),
            "exploitability": template.get("exploitability", random.choice(EXPLOITABILITIES)),
            "patch_due_date": random_past_date_or_future(0.3),
            "patch_applied": patch_applied,
            "assigned_to": random.choice(USERNAMES),
            "reported_by": reporter,
            "risk_score": calculate_risk_score(
                template["cvss_score"],
                template.get("exploitability"),
                template["severity"],
            ),
            "remediation_steps": generate_remediation_steps(created_at),
            "activity_log": generate_activity_log(created_at, reporter),
            "created_at": created_at,
            "updated_at": created_at + timedelta(days=random.randint(0, 30)),
            "created_by": reporter,
            "location": random.choice(ASSET_LOCATIONS),
        }
        vulnerabilities.append(vuln)

    # Add additional generated vulnerabilities to reach 110+ total
    extra_titles = [
        "Buffer Overflow in Legacy Service",
        "Insecure API Key Management",
        "Missing Rate Limiting on Login",
        "Exposed Debug Endpoint in Production",
        "Unsanitised File Download Path",
        "Broken Authentication in Mobile API",
        "Excessive Data Exposure in API Response",
        "Missing Function Level Access Control",
        "Security Misconfiguration in Cloud Storage",
        "Using Components with Known Vulnerabilities",
        "Insufficient Transport Layer Protection",
        "Unvalidated Forwarded Headers",
        "Improper Certificate Validation",
        "Insecure Cryptographic Storage",
        "Missing Account Lockout Mechanism",
        "Unrestricted File Upload",
        "HTTP Request Smuggling",
        "Server-Side Template Injection",
        "Subdomain Takeover Possibility",
        "Exposed Git Repository",
        "DNS Zone Transfer Allowed",
        "SNMP Community String Default",
        "Expired SSL Certificate",
        "Open Mail Relay Configuration",
        "FTP Anonymous Access Enabled",
        "Unpatched Java Runtime Environment",
        "Container Escape Vulnerability",
        "AWS S3 Bucket Public Access",
        "Cross-Site Request Forgery in Admin Panel",
        "JWT Algorithm Confusion Attack",
        "GraphQL Introspection Enabled",
        "WebSocket Hijacking Vulnerability",
        "Prototype Pollution in Node.js Module",
        "LDAP Injection in Search Filter",
        "Path Traversal in API Endpoint",
        "Race Condition in Transaction Processing",
        "Memory Leak in Connection Pool",
        "Insecure Direct Object Reference in Reports",
        "Missing Encryption at Rest for PII Data",
        "Improper Error Handling Revealing Stack Trace",
        "Vulnerable Docker Base Image",
        "Misconfigured Network Segmentation",
        "Weak SSH Key Length (1024-bit)",
        "Exposed Prometheus Metrics Endpoint",
        "Insecure gRPC Reflection Enabled",
        "Python Pickle Deserialization Vulnerability",
        "Unprotected Redis Instance",
        "MongoDB Without Authentication",
        "Elasticsearch Exposed to Internet",
        "Jenkins Script Console Accessible",
        "Grafana Default Admin Credentials",
        "Kubernetes RBAC Misconfiguration",
        "Terraform State File Exposing Secrets",
        "CI/CD Pipeline Injection Risk",
        "Supply Chain Attack Vector in Dependencies",
        "Insufficient Backup Encryption",
        "Stale DNS Records Pointing to Decommissioned IP",
        "Cross-Tenant Data Leakage in SaaS",
        "Privilege Escalation via sudo Misconfiguration",
        "Insecure NFS Export Configuration",
        "802.1X Bypass on Network Switches",
        "Bluetooth Stack Vulnerability on Workstation",
        "Physical Access Control Bypass",
        "Social Engineering Vector - Phishing Susceptibility",
        "Unmonitored Shadow IT Applications",
        "Data Exfiltration via DNS Tunneling",
        "Inadequate Network Intrusion Detection",
        "Missing DLP Controls on Email Gateway",
        "Insecure VPN Split Tunneling Configuration",
        "Wireless Network Evil Twin Susceptibility",
        "Incomplete Patch Deployment on Endpoints",
        "Outdated Antivirus Signatures",
        "Missing Endpoint Detection and Response Agent",
        "Insecure Remote Desktop Protocol Configuration",
        "Print Spooler Vulnerability on Domain Controller",
        "Active Directory Kerberoasting Risk",
        "NTLM Relay Attack Surface",
        "Exposed IPMI Interface",
        "BMC Firmware Vulnerability",
]

    for title in extra_titles:
        severity = random.choice(SEVERITIES)
        cvss_weights = {
            "Critical": (8.5, 10.0),
            "High": (6.5, 8.4),
            "Medium": (3.5, 6.4),
            "Low": (1.0, 3.4),
            "Informational": (0.0, 0.9),
        }
        min_cvss, max_cvss = cvss_weights[severity]
        cvss = round(random.uniform(min_cvss, max_cvss), 1)
        exploitability = random.choice(EXPLOITABILITIES)
        status = random.choice(STATUSES)
        created_at = random_date(180, 5)
        patch_applied = status in ["Patched", "Accepted Risk"] and random.random() > 0.3
        reporter = random.choice(USERNAMES + ["security-scanner", "penetration-test"])

        vuln = {
            "vulnerability_title": title,
            "description": f"Security assessment identified: {title.lower()}. This vulnerability affects the targeted asset and requires remediation to reduce organisational risk exposure.",
            "cve_id": f"CVE-2025-{random.randint(10000, 99999)}" if random.random() > 0.5 else None,
            "severity": severity,
            "status": status,
            "cvss_score": cvss,
            "asset_name": random.choice(ASSET_NAMES),
            "asset_type": random.choice(ASSET_TYPES),
            "vulnerability_type": random.choice(VULNERABILITY_TYPES),
            "discovery_method": random.choice(DISCOVERY_METHODS),
            "department": random.choice(DEPARTMENTS),
            "affected_versions": [f"{random.randint(1,5)}.{random.randint(0,9)}.{random.randint(0,9)}" for _ in range(random.randint(1, 3))],
            "attack_vector": random.choice(ATTACK_VECTORS),
            "exploitability": exploitability,
            "patch_due_date": random_past_date_or_future(0.3),
            "patch_applied": patch_applied,
            "assigned_to": random.choice(USERNAMES),
            "reported_by": reporter,
            "risk_score": calculate_risk_score(cvss, exploitability, severity),
            "remediation_steps": generate_remediation_steps(created_at),
            "activity_log": generate_activity_log(created_at, reporter),
            "created_at": created_at,
            "updated_at": created_at + timedelta(days=random.randint(0, 30)),
            "created_by": reporter,
            "location": random.choice(ASSET_LOCATIONS),
        }
        vulnerabilities.append(vuln)

    if vulnerabilities:
        db.vulnerabilities.insert_many(vulnerabilities)

    print(f"  ✅ Created {len(vulnerabilities)} vulnerabilities")
    return len(vulnerabilities)


# CVSS ranges per severity (min, max)
_CVSS_RANGE = {
    "Critical":      (9.0, 10.0),
    "High":          (7.0, 8.9),
    "Medium":        (4.0, 6.9),
    "Low":           (0.1, 3.9),
    "Informational": (0.0, 0.0),
}


def create_reports(db) -> int:
    """Seed the ``reports`` collection with pre-computed summary rows.

    Each document mirrors what the ``POST /api/v1/analytics/generate-report``
    aggregation pipeline produces: one row per (department × severity)
    combination with patch counts and CVSS statistics.

    Args:
        db: PyMongo database instance.

    Returns:
        Number of report rows inserted.
    """
    db.reports.drop()          # start fresh (matches $out behaviour)

    rows = []
    for dept in DEPARTMENTS:
        for severity in SEVERITIES:
            cvss_min, cvss_max = _CVSS_RANGE[severity]
            count       = random.randint(2, 20)
            patched     = random.randint(0, count)
            unpatched   = count - patched

            if cvss_max == 0.0:
                avg_cvss = 0.0
                max_cvss = 0.0
            else:
                avg_cvss = round(random.uniform(cvss_min, cvss_max), 2)
                max_cvss = round(min(avg_cvss + random.uniform(0, cvss_max - avg_cvss), cvss_max), 2)

            rows.append({
                "department": dept,
                "severity":   severity,
                "count":      count,
                "avg_cvss":   avg_cvss,
                "max_cvss":   max_cvss,
                "patched":    patched,
                "unpatched":  unpatched,
            })

    db.reports.insert_many(rows)
    return len(rows)


def create_indexes(db) -> None:
    """Create database indexes."""
    db.vulnerabilities.create_index("severity")
    db.vulnerabilities.create_index("status")
    db.vulnerabilities.create_index("cvss_score")
    db.vulnerabilities.create_index("department")
    db.vulnerabilities.create_index("patch_due_date")
    db.vulnerabilities.create_index("patch_applied")
    db.vulnerabilities.create_index("created_at")
    db.vulnerabilities.create_index("vulnerability_type")
    db.vulnerabilities.create_index("discovery_method")
    db.vulnerabilities.create_index([("severity", 1), ("status", 1), ("department", 1)])
    db.vulnerabilities.create_index([("vulnerability_title", "text"), ("description", "text")])
    db.users.create_index("email", unique=True)
    db.users.create_index("username", unique=True)
    db.vulnerabilities.create_index([("location", "2dsphere")])
    db.blacklist.create_index("token")
    db.blacklist.create_index("blacklisted_at", expireAfterSeconds=86400)
    print("  ✅ Created database indexes")


def _get_db():
    """Create and return (client, db) from environment / config."""
    mongo_uri = os.environ.get('MONGO_URI', DevelopmentConfig.MONGO_URI)
    client = MongoClient(mongo_uri)
    db_name = mongo_uri.rsplit('/', 1)[-1].split('?')[0]
    return client, client[db_name], mongo_uri, db_name


def reset_database():
    """Drop the entire database so the next seed starts fresh.

    Use this before re-seeding to guarantee a clean state – e.g. after
    running Postman / Newman tests that mutate data.
    """
    client, db, mongo_uri, db_name = _get_db()

    print("\n🗑️  VulnGuard Database Reset")
    print("=" * 50)
    print(f"📦 Connected to: {mongo_uri}")
    print(f"📁 Database: {db_name}\n")

    # Show what will be dropped
    collections = db.list_collection_names()
    if collections:
        print(f"  Dropping {len(collections)} collection(s): {', '.join(collections)}")
    else:
        print("  Database is already empty.")

    client.drop_database(db_name)
    print("  ✅ Database dropped.\n")


def seed_database():
    """Main seeding function – inserts users, vulnerabilities & indexes."""
    print("\n🚀 VulnGuard Database Seeding")
    print("=" * 50)

    _client, db, mongo_uri, db_name = _get_db()

    print(f"\n📦 Connected to: {mongo_uri}")
    print(f"📁 Database: {db_name}\n")

    print("👤 Creating users...")
    create_users(db)

    print("🔒 Creating vulnerabilities...")
    count = create_vulnerabilities(db)

    print("� Creating reports...")
    report_count = create_reports(db)

    print("📋 Creating indexes...")
    create_indexes(db)

    print(f"\n{'=' * 50}")
    print(f"✅ Seeding complete!")
    print(f"   Users: 3 (admin, analyst, guest)")
    print(f"   Vulnerabilities: {count}")
    print(f"   Reports: {report_count}")
    print(f"\n🔑 Test Credentials:")
    print(f"   Admin:   admin@vulnguard.test / Admin@Secure123!")
    print(f"   Analyst: analyst@vulnguard.test / Analyst@Secure123!")
    print(f"   Guest:   guest@vulnguard.test / Guest@Secure123!")
    print()


def reseed_database():
    """Full pipeline: drop ➜ seed ➜ indexes.

    Designed to be called after Postman / Newman test runs so the
    database returns to a known-good state.
    """
    print("\n♻️  VulnGuard Full Re-seed Pipeline")
    print("=" * 50)
    reset_database()
    seed_database()
    print("♻️  Re-seed pipeline complete – database is back to a clean state.\n")


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description="VulnGuard Database Seeder")
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--reset', action='store_true',
                       help='Drop the database only (no seeding)')
    group.add_argument('--reseed', action='store_true',
                       help='Drop the database then seed from scratch (use after Postman tests)')
    args = parser.parse_args()

    if args.reset:
        reset_database()
    elif args.reseed:
        reseed_database()
    else:
        seed_database()
