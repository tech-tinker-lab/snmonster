# 🔄 Intelligent System Update Guide

## Overview
The Intelligent System Update feature provides automated, architecture-aware system updates for your managed devices. It's designed to safely update Rock 5B ARM64 devices, x86_64 systems, and any Linux distribution without breaking your systems.

## 🎯 Key Features

### **Multi-Architecture Support**
- **ARM64 (aarch64)**: Optimized for Rock 5B and other ARM64 devices
- **x86_64**: Standard Intel/AMD 64-bit systems  
- **ARM**: 32-bit ARM devices
- **Automatic Detection**: Script detects architecture and configures appropriate repositories

### **Package Manager Intelligence**
- **APT**: Ubuntu, Debian, and derivatives
- **YUM**: CentOS, RHEL 7 and older
- **DNF**: Fedora, RHEL 8+, CentOS 8+
- **Pacman**: Arch Linux and derivatives
- **Zypper**: openSUSE, SUSE Enterprise

### **Safety Features**
- **Pre-update Backup**: Automatic backup of critical configuration files
- **Package List Backup**: Complete inventory of installed packages
- **Post-update Verification**: System integrity checks after updates
- **SSH Service Protection**: Ensures SSH remains accessible
- **Disk Space Monitoring**: Prevents updates if insufficient space

## 🔧 How It Works

### **1. System Detection Phase**
```bash
# The script automatically detects:
- Operating System (Ubuntu, CentOS, Fedora, etc.)
- Architecture (ARM64, x86_64, ARM)
- Package Manager (apt, yum, dnf, pacman, zypper)
- Device Type (Rock 5B detection)
- Kernel Version and Distribution
```

### **2. Backup Phase**
```bash
# Creates comprehensive backups:
- /etc configuration files → /tmp/system_backup_TIMESTAMP/etc_backup
- Package lists → /tmp/system_backup_TIMESTAMP/packages_list.txt
- APT sources → /tmp/system_backup_TIMESTAMP/sources.list.backup
```

### **3. Repository Configuration**
```bash
# For ARM64 devices (like Rock 5B):
- Configures ARM64-specific repositories
- Ubuntu: Uses ports.ubuntu.com for ARM64 packages
- Debian: Ensures ARM64 repository access
- Updates repository metadata
```

### **4. Security Updates First**
```bash
# Prioritizes security updates:
- OpenSSH server updates
- OpenSSL and crypto libraries
- Core system security packages
- Uses unattended-upgrades when available
```

### **5. System Package Updates**
```bash
# Performs intelligent updates:
- Downloads packages first (safer approach)
- Installs updates with proper error handling
- Cleans up unnecessary packages
- Maintains package cache efficiently
```

### **6. Architecture-Specific Updates**
```bash
# For Rock 5B and ARM64:
- Updates device tree files
- Firmware updates (when available)
- ARM64-specific kernel packages
- Hardware-specific optimizations
```

### **7. Post-Update Verification**
```bash
# Comprehensive system checks:
- Kernel files integrity
- Package manager consistency
- SSH service status
- Disk space availability
- Service health verification
```

## 🎮 Usage Instructions

### **Via Frontend (Recommended)**

1. **Navigate to ManagedDevices Page**
   - Open your Network Admin System
   - Go to the "Managed Devices" section

2. **Select Target Devices**
   - Check the boxes next to devices you want to update
   - Can select individual devices or all devices

3. **Access Bulk Actions**
   - Click the "Bulk Actions" button
   - Choose from the dropdown menu:

4. **System Update Options**
   - **"Run System Updates"**: Execute intelligent updates on selected devices
   - **"Check Update Status"**: See what updates are available before updating

5. **Monitor Progress**
   - Real-time status updates shown in the UI
   - Success/failure notifications
   - Detailed progress for each device

### **Via API Testing**

```python
# Test the system update functionality
cd backend
python test_system_update.py
```

### **Direct SSH Testing**

```bash
# Run the script directly on a device
cd /tmp/edu_admin
./system_update.sh
```

## 📊 Update Reports

### **JSON Report Structure**
```json
{
    "update_id": "update_1234567890",
    "timestamp": "2025-07-19T10:51:26.746698",
    "system": {
        "os": "ubuntu",
        "version": "22.04",
        "architecture": "aarch64",
        "device_type": "rock5b",
        "kernel": "5.15.0-rock5b"
    },
    "package_manager": "apt",
    "backup_location": "/tmp/system_backup_20250719_105126",
    "log_file": "/tmp/system_update_20250719_105126.log",
    "status": "completed",
    "verification": {
        "package_system": "ok",
        "ssh_service": "active",
        "disk_usage": "67%"
    }
}
```

### **API Response Structure**
```json
{
    "success": true,
    "message": "System update completed for 3 out of 3 devices",
    "results": [
        {
            "device_id": 20,
            "ip_address": "192.168.1.75",
            "hostname": "rock5b-device1",
            "status": "success",
            "message": "System update completed successfully",
            "update_id": "update_20_1752918681",
            "update_info": { /* Detailed update information */ },
            "output": "Update log output..."
        }
    ],
    "summary": {
        "total_devices": 3,
        "successful_updates": 3,
        "failed_updates": 0
    }
}
```

## 🔒 Security Considerations

### **Safe Update Practices**
- **Staging**: Test updates on non-production devices first
- **Timing**: Run updates during maintenance windows
- **Monitoring**: Watch for any service disruptions
- **Rollback**: Use backup files if needed to restore configuration

### **Network Considerations**
- **Bandwidth**: Updates can be large, especially for full system updates
- **Timeouts**: System updates can take 5-30 minutes depending on system and updates
- **SSH Stability**: Script monitors SSH service to prevent lockouts

### **Rock 5B Specific Considerations**
- **Power**: Ensure stable power supply during updates
- **Storage**: Verify sufficient storage space (recommend 2GB+ free)
- **Cooling**: Monitor temperature during intensive update processes

## 🛠️ Troubleshooting

### **Common Issues**

**1. Update Timeouts**
```bash
# Increase timeout in API call
timeout=1800  # 30 minutes
```

**2. Insufficient Disk Space**
```bash
# Check disk space before update
df -h /
# Clean up if needed
apt autoremove && apt autoclean
```

**3. Repository Errors**
```bash
# For ARM64 devices, ensure proper repositories
cat /etc/apt/sources.list
# Should contain ports.ubuntu.com for Ubuntu ARM64
```

**4. SSH Connection Issues**
```bash
# Verify SSH credentials are set
# Check SSH service status after update
systemctl status ssh
```

### **Manual Recovery**
```bash
# If update fails, restore from backup
cp -r /tmp/system_backup_*/etc_backup/* /etc/
systemctl restart ssh
```

## 📋 Supported Systems

### **Tested Operating Systems**
- ✅ Ubuntu 18.04+ (ARM64, x86_64)
- ✅ Debian 10+ (ARM64, x86_64)
- ✅ CentOS 7+ (x86_64)
- ✅ RHEL 8+ (x86_64, ARM64)
- ✅ Fedora 35+ (x86_64, ARM64)
- ✅ Arch Linux (x86_64, ARM64)

### **Tested Hardware**
- ✅ Rock 5B (ARM64)
- ✅ Raspberry Pi 4 (ARM64)
- ✅ Standard x86_64 servers
- ✅ Virtual machines (all architectures)

### **Package Managers**
- ✅ APT (Advanced Package Tool)
- ✅ YUM (Yellowdog Updater Modified)
- ✅ DNF (Dandified YUM)
- ✅ Pacman (Package Manager)
- ✅ Zypper (openSUSE package manager)

## 🚀 Best Practices

### **Before Running Updates**
1. **Check System Status**: Use "Check Update Status" first
2. **Verify Connectivity**: Ensure stable network connection
3. **Plan Downtime**: Updates may require service restarts
4. **Backup Critical Data**: Beyond what the script backs up

### **During Updates**
1. **Monitor Progress**: Watch the frontend for real-time status
2. **Don't Interrupt**: Let updates complete fully
3. **Check Logs**: Review any error messages
4. **Verify Services**: Ensure critical services remain running

### **After Updates**
1. **Verify System Health**: Check that all services are running
2. **Test Applications**: Ensure applications work correctly
3. **Review Logs**: Check for any post-update issues
4. **Plan Reboots**: Some updates may require system restart

## 📞 Support

If you encounter issues with system updates:

1. **Check the update logs** in the frontend output
2. **Review the system backup** location provided in the report
3. **Verify SSH connectivity** to the affected devices
4. **Check disk space** and system resources
5. **Review the specific error messages** for troubleshooting guidance

The intelligent update system is designed to be safe and robust, but always test in a non-production environment first!
