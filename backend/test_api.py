#!/usr/bin/env python3
"""
Test script to verify the API is working correctly
"""

import requests
import json
import time
import sys

def test_api_endpoints():
    """Test various API endpoints"""
    base_url = "http://localhost:8001"
    
    print("🧪 Testing Network Admin API...")
    print("=" * 50)
    
    # Test 1: Root endpoint
    print("1. Testing root endpoint...")
    try:
        response = requests.get(f"{base_url}/", timeout=5)
        if response.status_code == 200:
            print("   ✅ Root endpoint working")
            print(f"   📄 Response: {response.json()}")
        else:
            print(f"   ❌ Root endpoint failed: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Root endpoint error: {e}")
    
    # Test 2: Health check
    print("\n2. Testing health check...")
    try:
        response = requests.get(f"{base_url}/api/health", timeout=5)
        if response.status_code == 200:
            print("   ✅ Health check working")
            health_data = response.json()
            print(f"   📊 Status: {health_data.get('status')}")
            print(f"   🔍 Scanner running: {health_data.get('scanner_running')}")
            print(f"   🤖 AI system ready: {health_data.get('ai_system_ready')}")
            print(f"   📋 Registry ready: {health_data.get('registry_ready')}")
            print(f"   🌐 Network range: {health_data.get('network_range')}")
        else:
            print(f"   ❌ Health check failed: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Health check error: {e}")
    
    # Test 3: Devices endpoint
    print("\n3. Testing devices endpoint...")
    try:
        response = requests.get(f"{base_url}/api/devices", timeout=5)
        if response.status_code == 200:
            print("   ✅ Devices endpoint working")
            devices_data = response.json()
            print(f"   📱 Total devices: {devices_data.get('total', 0)}")
            if devices_data.get('devices'):
                print("   📋 Sample devices:")
                for device in devices_data['devices'][:3]:  # Show first 3 devices
                    print(f"      - {device.get('ip_address')} ({device.get('hostname', 'Unknown')})")
        else:
            print(f"   ❌ Devices endpoint failed: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Devices endpoint error: {e}")
    
    # Test 4: Registry overview
    print("\n4. Testing registry overview...")
    try:
        response = requests.get(f"{base_url}/api/registry/overview", timeout=5)
        if response.status_code == 200:
            print("   ✅ Registry overview working")
            registry_data = response.json()
            summary = registry_data.get('summary', {})
            print(f"   🏗️  Boundaries: {summary.get('total_boundaries', 0)}")
            print(f"   📦 Namespaces: {summary.get('total_namespaces', 0)}")
            print(f"   🖥️  Nodes: {summary.get('total_nodes', 0)}")
            print(f"   🐳 Pods: {summary.get('total_pods', 0)}")
        else:
            print(f"   ❌ Registry overview failed: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Registry overview error: {e}")
    
    # Test 5: CORS test
    print("\n5. Testing CORS...")
    try:
        response = requests.get(f"{base_url}/api/cors-test", timeout=5)
        if response.status_code == 200:
            print("   ✅ CORS test working")
            cors_data = response.json()
            print(f"   🌐 Allowed origins: {len(cors_data.get('allowed_origins', []))}")
        else:
            print(f"   ❌ CORS test failed: {response.status_code}")
    except Exception as e:
        print(f"   ❌ CORS test error: {e}")
    
    print("\n" + "=" * 50)
    print("🎯 API Testing Complete!")

def check_server_running():
    """Check if the server is running"""
    try:
        response = requests.get("http://localhost:8001/api/health", timeout=2)
        return response.status_code == 200
    except:
        return False

def main():
    """Main function"""
    print("🔍 Network Admin API Test Suite")
    print("=" * 50)
    
    # Check if server is running
    print("Checking if server is running...")
    if not check_server_running():
        print("❌ Server is not running on http://localhost:8001")
        print("💡 Please start the server first:")
        print("   python run_backend.py")
        print("   or")
        print("   python start_backend.py")
        return False
    
    print("✅ Server is running!")
    print()
    
    # Run tests
    test_api_endpoints()
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 