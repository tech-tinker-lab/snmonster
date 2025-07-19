import requests
import json

# Set SSH credentials for multiple rock-5b devices
devices_to_update = [
    {"id": 4, "ip": "192.168.1.83"},
    {"id": 9, "ip": "192.168.1.86"},
    {"id": 13, "ip": "192.168.1.84"},
    {"id": 16, "ip": "192.168.1.85"},
    {"id": 17, "ip": "192.168.1.79"},
    {"id": 19, "ip": "192.168.1.77"}
]

# Common credentials for rock-5b boards
credentials = {
    "ssh_username": "rock",
    "ssh_password": "rock"
}

for device in devices_to_update:
    url = f"http://localhost:8004/api/devices/{device['id']}"
    
    try:
        response = requests.put(url, json=credentials)
        if response.status_code == 200:
            print(f"✅ {device['ip']}: SSH credentials set successfully!")
        else:
            print(f"❌ {device['ip']}: Failed - Status {response.status_code}")
    except Exception as e:
        print(f"❌ {device['ip']}: Error - {e}")

print("\nDone setting credentials for rock-5b devices!")
