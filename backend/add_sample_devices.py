#!/usr/bin/env python3
"""
Script to add sample devices to the database for testing
"""

import asyncio
import sys
import os
from datetime import datetime

# Add the backend directory to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from database import init_db, get_db
from models import Device, DeviceStatus, DeviceType, OperatingSystem

async def add_sample_devices():
    """Add sample devices to the database"""
    try:
        # Initialize database
        await init_db()
        
        # Get database session
        db = get_db()
        
        # Sample devices data
        sample_devices = [
            {
                "ip_address": "192.168.1.1",
                "mac_address": "00:11:22:33:44:55",
                "hostname": "router.local",
                "device_type": DeviceType.ROUTER,
                "operating_system": OperatingSystem.LINUX,
                "status": DeviceStatus.ONLINE,
                "subnet": "192.168.1.0/24",
                "gateway": "192.168.1.1",
                "dns_servers": '["8.8.8.8", "8.8.4.4"]',
                "open_ports": '[22, 80, 443, 8080]',
                "vendor": "TP-Link",
                "model": "Archer C7",
                "location": "Network Closet",
                "notes": "Main router"
            },
            {
                "ip_address": "192.168.1.10",
                "mac_address": "AA:BB:CC:DD:EE:FF",
                "hostname": "desktop-pc",
                "device_type": DeviceType.COMPUTER,
                "operating_system": OperatingSystem.WINDOWS,
                "status": DeviceStatus.ONLINE,
                "subnet": "192.168.1.0/24",
                "gateway": "192.168.1.1",
                "dns_servers": '["8.8.8.8", "8.8.4.4"]',
                "open_ports": '[80, 443, 3389]',
                "vendor": "Dell",
                "model": "OptiPlex 7090",
                "location": "Office",
                "notes": "Main desktop computer"
            },
            {
                "ip_address": "192.168.1.20",
                "mac_address": "11:22:33:44:55:66",
                "hostname": "laptop-user",
                "device_type": DeviceType.COMPUTER,
                "operating_system": OperatingSystem.MACOS,
                "status": DeviceStatus.ONLINE,
                "subnet": "192.168.1.0/24",
                "gateway": "192.168.1.1",
                "dns_servers": '["8.8.8.8", "8.8.4.4"]',
                "open_ports": '[22, 80, 443]',
                "vendor": "Apple",
                "model": "MacBook Pro",
                "location": "Office",
                "notes": "User laptop"
            },
            {
                "ip_address": "192.168.1.30",
                "mac_address": "AA:AA:AA:AA:AA:AA",
                "hostname": "printer-office",
                "device_type": DeviceType.PRINTER,
                "operating_system": OperatingSystem.UNKNOWN,
                "status": DeviceStatus.ONLINE,
                "subnet": "192.168.1.0/24",
                "gateway": "192.168.1.1",
                "dns_servers": '["8.8.8.8", "8.8.4.4"]',
                "open_ports": '[80, 443, 9100]',
                "vendor": "HP",
                "model": "LaserJet Pro",
                "location": "Office",
                "notes": "Network printer"
            },
            {
                "ip_address": "192.168.1.40",
                "mac_address": "BB:BB:BB:BB:BB:BB",
                "hostname": "server-dev",
                "device_type": DeviceType.SERVER,
                "operating_system": OperatingSystem.LINUX,
                "status": DeviceStatus.ONLINE,
                "subnet": "192.168.1.0/24",
                "gateway": "192.168.1.1",
                "dns_servers": '["8.8.8.8", "8.8.4.4"]',
                "open_ports": '[22, 80, 443, 3306, 5432]',
                "vendor": "Dell",
                "model": "PowerEdge R740",
                "location": "Server Room",
                "notes": "Development server"
            },
            {
                "ip_address": "192.168.1.50",
                "mac_address": "CC:CC:CC:CC:CC:CC",
                "hostname": "switch-core",
                "device_type": DeviceType.SWITCH,
                "operating_system": OperatingSystem.UNKNOWN,
                "status": DeviceStatus.ONLINE,
                "subnet": "192.168.1.0/24",
                "gateway": "192.168.1.1",
                "dns_servers": '["8.8.8.8", "8.8.4.4"]',
                "open_ports": '[22, 23, 80, 443]',
                "vendor": "Cisco",
                "model": "Catalyst 2960",
                "location": "Network Closet",
                "notes": "Core switch"
            },
            {
                "ip_address": "192.168.1.60",
                "mac_address": "DD:DD:DD:DD:DD:DD",
                "hostname": "mobile-device",
                "device_type": DeviceType.MOBILE,
                "operating_system": OperatingSystem.ANDROID,
                "status": DeviceStatus.OFFLINE,
                "subnet": "192.168.1.0/24",
                "gateway": "192.168.1.1",
                "dns_servers": '["8.8.8.8", "8.8.4.4"]',
                "open_ports": '[80, 443]',
                "vendor": "Samsung",
                "model": "Galaxy S21",
                "location": "Office",
                "notes": "User mobile device"
            }
        ]
        
        # Add devices to database
        for device_data in sample_devices:
            # Check if device already exists
            existing_device = db.query(Device).filter(
                Device.ip_address == device_data["ip_address"]
            ).first()
            
            if existing_device:
                print(f"Device {device_data['ip_address']} already exists, updating...")
                # Update existing device
                for key, value in device_data.items():
                    if hasattr(existing_device, key):
                        setattr(existing_device, key, value)
                existing_device.updated_at = datetime.now()
            else:
                print(f"Adding new device: {device_data['ip_address']}")
                # Create new device
                new_device = Device(**device_data)
                db.add(new_device)
        
        # Commit changes
        db.commit()
        print(f"Successfully added/updated {len(sample_devices)} sample devices")
        
        # Close database session
        db.close()
        
    except Exception as e:
        print(f"Error adding sample devices: {e}")
        if 'db' in locals():
            db.rollback()
            db.close()

if __name__ == "__main__":
    asyncio.run(add_sample_devices()) 