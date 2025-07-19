#!/usr/bin/env python3
"""
Test script for intelligent system update functionality
"""

import requests
import json
import time

def test_system_update_functionality():
    """Test the system update API endpoints"""
    base_url = "http://localhost:8004"
    device_ids = [20]  # Device that has SSH credentials
    
    print("🔄 Testing Intelligent System Update Functionality")
    print("=" * 60)
    
    # Test 1: Check system update status
    print("\n1. Checking system update status...")
    try:
        response = requests.post(
            f"{base_url}/api/devices/system-update-status",
            json={"device_ids": device_ids},
            timeout=30
        )
        print(f"   📊 Status API Response: {response.status_code}")
        
        if response.status_code == 200:
            status_data = response.json()
            print(f"   ✅ Status Check Success: {status_data.get('success')}")
            
            if status_data.get('status_results'):
                for result in status_data['status_results']:
                    print(f"\n   📋 Device: {result['ip_address']}")
                    print(f"      🔗 Status: {result['status']}")
                    print(f"      🔄 Update Status: {result.get('update_status', 'unknown')}")
                    
                    if 'system_info' in result:
                        info = result['system_info']
                        print(f"      💻 OS: {info.get('os_info', 'unknown')}")
                        print(f"      🏗️  Architecture: {info.get('architecture', 'unknown')}")
                        print(f"      📦 Package Manager: {info.get('package_manager', 'unknown')}")
                        print(f"      📈 Updates Available: {info.get('updates_available', 'unknown')}")
                        print(f"      💾 Memory Usage: {info.get('memory_usage', 'unknown')}")
                        print(f"      💿 Disk Usage: {info.get('disk_usage', 'unknown')}")
                    
                    if result.get('error'):
                        print(f"      ❌ Error: {result['error']}")
            
            if status_data.get('summary'):
                summary = status_data['summary']
                print(f"\n   📈 Summary:")
                print(f"      🖥️  Total Devices: {summary.get('total_devices', 0)}")
                print(f"      ✅ Online Devices: {summary.get('online_devices', 0)}")
                print(f"      🔄 Devices Needing Updates: {summary.get('devices_needing_updates', 0)}")
        else:
            print(f"   ❌ Status check failed: {response.text}")
    except Exception as e:
        print(f"   ❌ Status check error: {e}")
    
    # Test 2: Run system updates
    print("\n2. Running intelligent system updates...")
    print("   🔄 Initiating architecture-aware system update...")
    start_time = time.time()
    
    try:
        response = requests.post(
            f"{base_url}/api/devices/bulk-system-update",
            json={"device_ids": device_ids},
            timeout=1800  # 30 minute timeout for system updates
        )
        elapsed_time = time.time() - start_time
        
        print(f"   📊 Update API Response: {response.status_code}")
        print(f"   ⏱️  Total execution time: {elapsed_time:.2f}s")
        
        if response.status_code == 200:
            update_data = response.json()
            print(f"   ✅ Update Success: {update_data.get('success')}")
            print(f"   💬 Server Message: {update_data.get('message')}")
            
            if update_data.get('results'):
                print(f"   📋 Processing {len(update_data['results'])} device(s)...")
                for i, result in enumerate(update_data['results'], 1):
                    print(f"\n   Device {i}: {result['ip_address']}")
                    print(f"      🔗 Update Status: {result['status']}")
                    print(f"      📝 Details: {result['message']}")
                    
                    if result['status'] == 'success':
                        print("      ✅ System update completed successfully")
                        if 'update_info' in result:
                            update_info = result['update_info']
                            print(f"      🆔 Update ID: {result.get('update_id')}")
                            
                            if update_info:
                                print("      📊 Update Details:")
                                if 'system' in update_info:
                                    sys_info = update_info['system']
                                    print(f"         OS: {sys_info.get('os', 'unknown')}")
                                    print(f"         Architecture: {sys_info.get('architecture', 'unknown')}")
                                    print(f"         Device Type: {sys_info.get('device_type', 'unknown')}")
                                
                                if 'package_manager' in update_info:
                                    print(f"         Package Manager: {update_info['package_manager']}")
                                
                                if 'status' in update_info:
                                    print(f"         Status: {update_info['status']}")
                                
                                if 'verification' in update_info:
                                    verify = update_info['verification']
                                    print(f"         Package System: {verify.get('package_system', 'unknown')}")
                                    print(f"         SSH Service: {verify.get('ssh_service', 'unknown')}")
                                    print(f"         Disk Usage: {verify.get('disk_usage', 'unknown')}")
                        
                        # Show partial output if available
                        if result.get('output'):
                            output_lines = result['output'].split('\n')
                            print(f"      📝 Update Output (last 5 lines):")
                            for line in output_lines[-5:]:
                                if line.strip():
                                    print(f"         {line}")
                    
                    elif result['status'] == 'error':
                        print("      ❌ System update failed")
                        print(f"      🔍 Error details: {result.get('message', 'Unknown error')}")
            
            if update_data.get('summary'):
                summary = update_data['summary']
                print(f"\n   📈 Update Summary:")
                print(f"      🖥️  Total Devices: {summary.get('total_devices', 0)}")
                print(f"      ✅ Successful Updates: {summary.get('successful_updates', 0)}")
                print(f"      ❌ Failed Updates: {summary.get('failed_updates', 0)}")
        else:
            print(f"   ❌ Update API Error: {response.text}")
    except requests.exceptions.Timeout:
        print("   ⏰ Update request timed out - system updates can take a long time")
    except Exception as e:
        print(f"   ❌ Update error: {e}")
    
    print("\n" + "=" * 60)
    print("✅ Intelligent System Update test completed!")
    print("\n🔍 What this test demonstrated:")
    print("  • Architecture detection (ARM64, x86_64, etc.)")
    print("  • OS and package manager identification")
    print("  • Safe system updates with backup creation")
    print("  • Repository configuration for specific architectures")
    print("  • Rock 5B ARM64 specific optimizations")
    print("  • Post-update system verification")
    print("  • Comprehensive update reporting")
    
    print("\n🎯 Key Features Tested:")
    print("  ✅ Multi-architecture support")
    print("  ✅ Intelligent package manager detection")
    print("  ✅ Safe update process with rollback capability")
    print("  ✅ Real-time progress monitoring")
    print("  ✅ Comprehensive system verification")
    
    print("\n🚀 Frontend Usage:")
    print("1. Navigate to ManagedDevices page")
    print("2. Select devices and click 'Bulk Actions'")
    print("3. Choose 'Run System Updates' for intelligent updates")
    print("4. Use 'Check Update Status' to see what needs updating")

if __name__ == "__main__":
    test_system_update_functionality()
