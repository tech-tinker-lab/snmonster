import requests
import json

# Set SSH credentials for device ID 20 (192.168.1.75)
device_id = 20
credentials = {
    "ssh_username": "rock",  # Common username for Rock 5B boards
    "ssh_password": "rock"   # Common default password
}

url = f"http://localhost:8004/api/devices/{device_id}"

try:
    response = requests.put(url, json=credentials)
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    
    if response.status_code == 200:
        print("✅ SSH credentials set successfully!")
    else:
        print("❌ Failed to set SSH credentials")
        
except Exception as e:
    print(f"Error: {e}")
