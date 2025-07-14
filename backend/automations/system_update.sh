#!/bin/bash
# Comprehensive System Update Script
# Supports Ubuntu/Debian, CentOS/RHEL, and Windows

set -e

echo "=== System Update Automation ==="
echo "Detecting operating system..."

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    if command -v apt-get &> /dev/null; then
        echo "Detected Ubuntu/Debian system"
        echo "Updating package lists..."
        sudo apt-get update
        
        echo "Upgrading packages..."
        sudo apt-get upgrade -y
        
        echo "Upgrading distribution..."
        sudo apt-get dist-upgrade -y
        
        echo "Cleaning up..."
        sudo apt-get autoremove -y
        sudo apt-get autoclean
        
        echo "Checking for kernel updates..."
        if [ -f /var/run/reboot-required ]; then
            echo "⚠️  System reboot required!"
            echo "Run: sudo reboot"
        fi
        
    elif command -v yum &> /dev/null; then
        echo "Detected CentOS/RHEL system"
        echo "Updating packages..."
        sudo yum update -y
        
        echo "Cleaning up..."
        sudo yum autoremove -y
        
    elif command -v dnf &> /dev/null; then
        echo "Detected Fedora/DNF system"
        echo "Updating packages..."
        sudo dnf update -y
        
        echo "Cleaning up..."
        sudo dnf autoremove -y
        
    else
        echo "Unknown Linux distribution"
        exit 1
    fi
    
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
    echo "Detected Windows system"
    echo "Checking for Windows updates..."
    
    # PowerShell commands for Windows updates
    powershell -Command "Get-WindowsUpdate -Install -AcceptAll -IgnoreReboot"
    
else
    echo "Unsupported operating system: $OSTYPE"
    exit 1
fi

echo "=== System Update Complete ==="
echo "✅ All packages updated successfully" 