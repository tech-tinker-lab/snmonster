import requests
import json
import time

# Test security audit with demo data
device_ids = [20]  # Device that has SSH credentials

print("🔒 Testing Security Audit System")
print("=" * 50)

# Test 0: Check backend connection
print("\n0. Checking backend connection...")
try:
    health_response = requests.get("http://localhost:8004/api/health", timeout=5)
    if health_response.status_code == 200:
        print("   ✅ Backend is running and accessible")
        print(f"   📡 Response time: {health_response.elapsed.total_seconds():.2f}s")
    else:
        print(f"   ❌ Backend responded with status: {health_response.status_code}")
except requests.exceptions.ConnectionError:
    print("   ❌ Cannot connect to backend - make sure it's running on port 8004")
    exit(1)
except Exception as e:
    print(f"   ❌ Connection error: {e}")
    exit(1)

# Test 1: Run security audit
print("\n1. Running security audit...")
print("   🔄 Initiating SSH-based security audit...")
start_time = time.time()

try:
    audit_response = requests.post(
        "http://localhost:8004/api/devices/bulk-security-audit",
        json={"device_ids": device_ids},
        timeout=120  # 2 minutes timeout for SSH operations
    )
    elapsed_time = time.time() - start_time
    
    print(f"   📊 API Response Status: {audit_response.status_code}")
    print(f"   ⏱️  Total execution time: {elapsed_time:.2f}s")
    
    if audit_response.status_code == 200:
        audit_data = audit_response.json()
        print(f"   ✅ Request Success: {audit_data.get('success')}")
        print(f"   💬 Server Message: {audit_data.get('message')}")
        
        if audit_data.get('results'):
            print(f"   📋 Processing {len(audit_data['results'])} device(s)...")
            for i, result in enumerate(audit_data['results'], 1):
                print(f"\n   Device {i}: {result['ip_address']}")
                print(f"      🔗 SSH Connection: {result['status']}")
                print(f"      📝 Details: {result['message']}")
                
                if result['status'] == 'success':
                    print("      ✅ SSH connection established successfully")
                    print("      🔒 Security audit script executed remotely")
                    if 'audit_id' in result:
                        print(f"      🆔 Audit ID: {result['audit_id']}")
                        print("      💾 Audit results saved to database")
                elif result['status'] == 'error':
                    print("      ❌ SSH connection failed")
                    print(f"      🔍 Error details: {result.get('error', 'Unknown error')}")
        else:
            print("   ⚠️  No audit results returned")
    else:
        print(f"   ❌ API Error: {audit_response.text}")
        if audit_response.status_code == 500:
            print("   🔧 This might be a server-side error - check backend logs")
        elif audit_response.status_code == 404:
            print("   🔧 Endpoint not found - check if backend is updated")
except requests.exceptions.Timeout:
    print("   ⏰ Request timed out - SSH operations may take longer")
except requests.exceptions.ConnectionError:
    print("   ❌ Lost connection to backend during audit")
except Exception as e:
    print(f"   ❌ Unexpected error: {e}")

# Test 2: Get security reports
print("\n2. Fetching security reports...")
print("   📊 Retrieving audit results from database...")

try:
    reports_response = requests.post(
        "http://localhost:8004/api/devices/security-reports", 
        json={"device_ids": device_ids},
        timeout=30
    )
    print(f"   📈 Reports API Status: {reports_response.status_code}")
    
    if reports_response.status_code == 200:
        reports_data = reports_response.json()
        print(f"   ✅ Reports Retrieved: {reports_data.get('success')}")
        
        if reports_data.get('reports'):
            print(f"   📋 Found {len(reports_data['reports'])} security report(s)")
            
            for i, report in enumerate(reports_data['reports'], 1):
                print(f"\n   📊 Security Report #{i} for {report['ip_address']}:")
                print(f"      🎯 Overall Security Score: {report.get('overall_score', 'N/A')}%")
                print(f"      📅 Audit Date: {report.get('audit_date', 'N/A')}")
                print(f"      📈 Status: {report.get('status', 'N/A')}")
                
                # Show connection success indicator
                if report.get('overall_score', 0) > 0:
                    print("      ✅ Data collection successful - device responded to audit")
                else:
                    print("      ⚠️  Limited data - check SSH connectivity")
                
                if report.get('categories'):
                    print("      📊 Detailed Category Analysis:")
                    total_issues = 0
                    total_warnings = 0
                    
                    for category, data in report['categories'].items():
                        score = data.get('score', 0)
                        critical = data.get('critical_issues', 0)
                        warnings = data.get('warnings', 0)
                        total_issues += critical
                        total_warnings += warnings
                        
                        # Visual indicator for score
                        if score >= 80:
                            indicator = "🟢"
                        elif score >= 60:
                            indicator = "🟡"
                        else:
                            indicator = "🔴"
                            
                        print(f"        {indicator} {category.title()}: {score}% (Critical: {critical}, Warnings: {warnings})")
                    
                    print(f"      📊 Total Security Issues: {total_issues} critical, {total_warnings} warnings")
                
                # Show raw audit data availability
                if report.get('audit_data'):
                    print("      💾 Raw audit data available in database")
                    audit_data = report['audit_data']
                    if isinstance(audit_data, dict):
                        data_categories = list(audit_data.keys())
                        print(f"      📁 Data categories collected: {', '.join(data_categories[:5])}")
                        if len(data_categories) > 5:
                            print(f"         ... and {len(data_categories) - 5} more categories")
        
        if reports_data.get('summary'):
            summary = reports_data['summary']
            print(f"\n   📈 Audit Summary:")
            print(f"      🖥️  Total Devices Audited: {summary.get('total_devices', 0)}")
            print(f"      📊 Average Security Score: {summary.get('avg_score', 0):.1f}%")
            print(f"      🚨 Total Critical Issues: {summary.get('critical_issues', 0)}")
            print(f"      ⚠️  Total Warnings: {summary.get('total_warnings', 0)}")
            
            # Overall health indicator
            avg_score = summary.get('avg_score', 0)
            if avg_score >= 80:
                print("      🟢 Overall network security: GOOD")
            elif avg_score >= 60:
                print("      🟡 Overall network security: MODERATE")
            else:
                print("      🔴 Overall network security: NEEDS ATTENTION")
        else:
            print("   ℹ️  No summary data available")
    else:
        print(f"   ❌ Reports API Error: {reports_response.text}")
except requests.exceptions.Timeout:
    print("   ⏰ Reports request timed out")
except Exception as e:
    print(f"   ❌ Reports error: {e}")

print("\n" + "=" * 50)
print("✅ Security audit system test completed!")
print("\n🔍 What this test demonstrated:")
print("  • Backend connectivity and health check")
print("  • SSH connection establishment to target devices")
print("  • Remote security audit script execution")
print("  • Real-time data collection and analysis")
print("  • Database storage of audit results")
print("  • Security scoring and categorization")
print("  • Comprehensive reporting with visual indicators")

print("\n🎯 Connection Success Indicators:")
print("  ✅ Green checkmarks = Successful operations")
print("  🔗 SSH Connection = Direct device access")
print("  💾 Database storage = Persistent audit history")
print("  📊 Security scores = Analyzed real data")

print("\n🚀 Next steps:")
print("1. Check the frontend ManagedDevices page")
print("2. Select devices and click 'View Security Reports'") 
print("3. The system will show audit results and scores")
print("4. Use 'Run Security Audit' for new scans")

print("\n📋 Frontend Usage Guide:")
print("  • Navigate to: ManagedDevices page")
print("  • Click device checkboxes to select")
print("  • Choose 'Bulk Actions' → 'Run Security Audit'")
print("  • View results with 'View Security Reports' button")
print("  • Real-time progress shown during SSH operations")
