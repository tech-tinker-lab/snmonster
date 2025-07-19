import requests
import json
import time

# Test the enhanced security audit functionality
device_ids = [20]  # Device 192.168.1.75 which has SSH credentials

# Start security audit
print("🔒 Starting security audit...")
audit_response = requests.post(
    "http://localhost:8004/api/devices/bulk-security-audit",
    json={"device_ids": device_ids}
)

print(f"Audit Response Status: {audit_response.status_code}")
print(f"Audit Response: {json.dumps(audit_response.json(), indent=2)}")

# Wait a bit for the audit to complete
print("\n⏳ Waiting for audit to complete...")
time.sleep(10)

# Get security reports
print("\n📊 Fetching security reports...")
reports_response = requests.post(
    "http://localhost:8004/api/devices/security-reports",
    json={"device_ids": device_ids}
)

print(f"Reports Response Status: {reports_response.status_code}")
reports_data = reports_response.json()
print(f"Reports Response: {json.dumps(reports_data, indent=2)}")

if reports_data.get("success") and reports_data.get("reports"):
    report = reports_data["reports"][0]
    print(f"\n🎯 Security Audit Summary for {report['ip_address']}:")
    print(f"   Overall Score: {report['overall_score']}")
    print(f"   Audit Date: {report['audit_date']}")
    print(f"   Status: {report['status']}")
    
    if report.get("categories"):
        print("   Category Scores:")
        for category, data in report["categories"].items():
            print(f"     {category}: {data['score']} (Critical: {data['critical_issues']}, Warnings: {data['warnings']})")
    
    if report.get("recommendations"):
        print("   Recommendations:")
        for rec in report["recommendations"]:
            print(f"     - {rec}")
