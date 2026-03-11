"""Download CISA Known Exploited Vulnerabilities (KEV) catalog.

This script downloads the CISA KEV catalog (public domain JSON) and saves it
to the data/ directory, then optionally imports it into MongoDB.

Dataset: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
License: Public Domain (US Government work)

Usage:
    python -m scripts.download_dataset
"""

import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data')

# CISA KEV Catalog – authoritative, regularly updated, open source
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# CVE Summary dataset (GitHub - open)
CVE_SUMMARY_URL = "https://raw.githubusercontent.com/olbat/nvdcve/master/nvdcve/2024.json"


def ensure_data_dir():
    """Create data directory if it doesn't exist."""
    os.makedirs(DATA_DIR, exist_ok=True)
    print(f"  📁 Data directory: {DATA_DIR}")


def download_cisa_kev():
    """Download CISA Known Exploited Vulnerabilities catalog.

    Returns:
        Path to downloaded file, or None if download failed.
    """
    filepath = os.path.join(DATA_DIR, 'cisa_kev_catalog.json')

    print(f"  📥 Downloading CISA KEV catalog...")
    print(f"     Source: {CISA_KEV_URL}")

    try:
        req = urllib.request.Request(
            CISA_KEV_URL,
            headers={
                "User-Agent": "VulnGuard/1.0 (COM661 University Coursework)",
                "Accept": "application/json",
            }
        )
        response = urllib.request.urlopen(req, timeout=60)
        data = response.read()

        kev_data = json.loads(data)
        vuln_count = len(kev_data.get('vulnerabilities', []))

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(kev_data, f, indent=2)

        file_size_mb = os.path.getsize(filepath) / (1024 * 1024)
        print(f"  ✅ Downloaded CISA KEV catalog")
        print(f"     Vulnerabilities: {vuln_count}")
        print(f"     File size: {file_size_mb:.2f} MB")
        print(f"     Saved to: {filepath}")
        return filepath

    except Exception as e:
        print(f"  ⚠️  CISA KEV download failed: {e}")
        return None


def download_cve_summary():
    """Download CVE summary dataset from GitHub.

    Returns:
        Path to downloaded file, or None if download failed.
    """
    filepath = os.path.join(DATA_DIR, 'nvdcve_2024_summary.json')

    print(f"\n  📥 Downloading NVD CVE 2024 summary from GitHub...")
    print(f"     Source: {CVE_SUMMARY_URL}")

    try:
        req = urllib.request.Request(
            CVE_SUMMARY_URL,
            headers={
                "User-Agent": "VulnGuard/1.0 (COM661 University Coursework)",
                "Accept": "application/json",
            }
        )
        response = urllib.request.urlopen(req, timeout=120)
        data = response.read()

        cve_data = json.loads(data)
        cve_count = len(cve_data) if isinstance(cve_data, list) else len(cve_data.get('CVE_Items', []))

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(cve_data, f, indent=2)

        file_size_mb = os.path.getsize(filepath) / (1024 * 1024)
        print(f"  ✅ Downloaded NVD CVE summary")
        print(f"     CVE entries: {cve_count}")
        print(f"     File size: {file_size_mb:.2f} MB")
        print(f"     Saved to: {filepath}")
        return filepath

    except Exception as e:
        print(f"  ⚠️  CVE summary download failed: {e}")
        return None


def print_dataset_info(filepath: str):
    """Print information about a downloaded dataset."""
    if not filepath or not os.path.exists(filepath):
        return

    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)

    filename = os.path.basename(filepath)
    print(f"\n  📊 Dataset Info: {filename}")
    print(f"  {'─' * 40}")

    if 'vulnerabilities' in data:
        vulns = data['vulnerabilities']
        print(f"     Total entries: {len(vulns)}")

        if vulns:
            sample = vulns[0]
            print(f"     Sample fields: {list(sample.keys())}")
            print(f"\n     Sample entry:")
            print(f"       CVE ID: {sample.get('cveID', 'N/A')}")
            print(f"       Vendor: {sample.get('vendorProject', 'N/A')}")
            print(f"       Product: {sample.get('product', 'N/A')}")
            print(f"       Name: {sample.get('vulnerabilityName', 'N/A')}")
            print(f"       Date Added: {sample.get('dateAdded', 'N/A')}")

            # Severity distribution (if available)
            vendors = {}
            for v in vulns:
                vendor = v.get('vendorProject', 'Unknown')
                vendors[vendor] = vendors.get(vendor, 0) + 1

            top_vendors = sorted(vendors.items(), key=lambda x: -x[1])[:10]
            print(f"\n     Top 10 Vendors by CVE count:")
            for vendor, count in top_vendors:
                bar = '█' * min(count // 2, 30)
                print(f"       {vendor:<25} {count:>4} {bar}")


def main():
    """Download open source vulnerability datasets."""
    print("\n🌐 VulnGuard Dataset Downloader")
    print("=" * 50)
    print("  Downloading open source vulnerability datasets...\n")

    ensure_data_dir()

    # Download CISA KEV catalog (primary dataset)
    kev_path = download_cisa_kev()

    # Download NVD CVE summary (secondary dataset)
    cve_path = download_cve_summary()

    # Print dataset info
    if kev_path:
        print_dataset_info(kev_path)

    print(f"\n{'=' * 50}")
    downloaded = sum(1 for p in [kev_path, cve_path] if p)
    print(f"✅ Downloaded {downloaded}/2 datasets")
    if kev_path:
        print(f"   🔗 CISA KEV: {kev_path}")
    if cve_path:
        print(f"   🔗 NVD CVE:  {cve_path}")

    print(f"\n📝 To import into MongoDB, run:")
    print(f"   python -m scripts.import_cve_data")
    print()

    return downloaded > 0


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
