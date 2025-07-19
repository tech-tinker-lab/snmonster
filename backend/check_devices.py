from database import get_db
from models import Device
import json

# Get all devices
db = get_db()
devices = db.query(Device).all()

print('Current devices in database:')
print('-' * 80)
for device in devices:
    print(f'ID: {device.id}')
    print(f'IP: {device.ip_address}')
    print(f'Hostname: {device.hostname}')
    print(f'SSH Username: {device.ssh_username}')
    has_password = "Set" if device.ssh_password_enc else "Not Set"
    print(f'SSH Password: {has_password}')
    print(f'Is Managed: {device.is_managed}')
    print('-' * 40)

db.close()
