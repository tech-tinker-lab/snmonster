#!/bin/bash
# Rock 5B Device 2 Power Management Script
# Specifically for turning on and managing the second Rock 5B device

set -e

echo "=== Rock 5B Device 2 Power Management ==="

# Configuration - Update these with your actual device details
DEVICE2_IP="192.168.1.101"  # Change to your second Rock 5B IP
DEVICE2_MAC="aa:bb:cc:dd:ee:ff"  # Change to your second Rock 5B MAC
DEVICE2_USER="rock"
DEVICE2_SSH_PORT="22"

# Load configuration if exists
CONFIG_FILE="/tmp/rock5b_device2.conf"
if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
    echo "📁 Loaded configuration from $CONFIG_FILE"
fi

# Function to show current configuration
show_config() {
    echo "📋 Current Device 2 Configuration:"
    echo "IP Address: $DEVICE2_IP"
    echo "MAC Address: $DEVICE2_MAC"
    echo "Username: $DEVICE2_USER"
    echo "SSH Port: $DEVICE2_SSH_PORT"
}

# Function to test if device is online
test_online() {
    echo "🔍 Testing if Device 2 is online..."
    if ping -c 3 -W 5 "$DEVICE2_IP" >/dev/null 2>&1; then
        echo "✅ Device 2 is ONLINE at $DEVICE2_IP"
        return 0
    else
        echo "❌ Device 2 is OFFLINE or unreachable"
        return 1
    fi
}

# Function to power on Device 2 using Wake-on-LAN
power_on_device2() {
    echo "🔌 Powering on Rock 5B Device 2..."
    
    # Check if already online
    if test_online; then
        echo "ℹ️ Device 2 is already online!"
        return 0
    fi
    
    echo "📡 Sending Wake-on-LAN packet to $DEVICE2_MAC..."
    
    # Try different WOL tools
    if command -v wakeonlan >/dev/null 2>&1; then
        wakeonlan "$DEVICE2_MAC"
        echo "✅ Wake-on-LAN packet sent using wakeonlan"
    elif command -v etherwake >/dev/null 2>&1; then
        etherwake "$DEVICE2_MAC"
        echo "✅ Wake-on-LAN packet sent using etherwake"
    elif command -v wol >/dev/null 2>&1; then
        wol "$DEVICE2_MAC"
        echo "✅ Wake-on-LAN packet sent using wol"
    else
        echo "❌ No Wake-on-LAN tool found!"
        echo "💡 Install one of: wakeonlan, etherwake, or wol"
        echo "Ubuntu/Debian: sudo apt install wakeonlan"
        echo "CentOS/RHEL: sudo yum install wakeonlan"
        return 1
    fi
    
    # Wait for device to come online
    echo "⏳ Waiting for Device 2 to boot up..."
    for i in {1..60}; do
        if test_online >/dev/null 2>&1; then
            echo "✅ Device 2 is now ONLINE! (took ${i} attempts)"
            
            # Give SSH service time to start
            echo "⏳ Waiting for SSH service..."
            sleep 5
            
            # Test SSH connectivity
            if ssh -o ConnectTimeout=5 -o BatchMode=yes "$DEVICE2_USER@$DEVICE2_IP" "echo 'SSH test successful'" 2>/dev/null; then
                echo "✅ SSH is ready on Device 2"
                return 0
            else
                echo "⚠️ Device is online but SSH not ready yet"
            fi
            return 0
        fi
        
        echo "Attempt $i/60 - waiting..."
        sleep 2
    done
    
    echo "❌ Device 2 did not come online within 2 minutes"
    echo "💡 Check if:"
    echo "   - Wake-on-LAN is enabled in BIOS/UEFI"
    echo "   - Network cable is connected"
    echo "   - MAC address is correct: $DEVICE2_MAC"
    echo "   - Device has power connected"
    return 1
}

# Function to shutdown Device 2
shutdown_device2() {
    echo "🔴 Shutting down Rock 5B Device 2..."
    
    if ! test_online; then
        echo "ℹ️ Device 2 is already offline"
        return 0
    fi
    
    echo "Sending shutdown command..."
    if ssh -o ConnectTimeout=10 "$DEVICE2_USER@$DEVICE2_IP" "sudo shutdown -h now" 2>/dev/null; then
        echo "✅ Shutdown command sent successfully"
        
        # Wait for device to go offline
        echo "⏳ Waiting for device to shutdown..."
        for i in {1..30}; do
            if ! test_online >/dev/null 2>&1; then
                echo "✅ Device 2 has shut down successfully"
                return 0
            fi
            echo "Waiting for shutdown... ($i/30)"
            sleep 2
        done
        
        echo "⚠️ Device may still be shutting down"
    else
        echo "❌ Could not send shutdown command"
        echo "💡 Try: ssh $DEVICE2_USER@$DEVICE2_IP 'sudo shutdown -h now'"
        return 1
    fi
}

# Function to reboot Device 2
reboot_device2() {
    echo "🔄 Rebooting Rock 5B Device 2..."
    
    if ! test_online; then
        echo "❌ Device 2 is offline - cannot reboot"
        echo "💡 Use 'power-on' command instead"
        return 1
    fi
    
    echo "Sending reboot command..."
    if ssh -o ConnectTimeout=10 "$DEVICE2_USER@$DEVICE2_IP" "sudo reboot" 2>/dev/null; then
        echo "✅ Reboot command sent successfully"
        
        # Wait for device to go offline then come back online
        echo "⏳ Waiting for device to reboot..."
        sleep 10
        
        for i in {1..60}; do
            if test_online >/dev/null 2>&1; then
                echo "✅ Device 2 has rebooted successfully"
                return 0
            fi
            echo "Waiting for reboot... ($i/60)"
            sleep 2
        done
        
        echo "❌ Device did not come back online after reboot"
    else
        echo "❌ Could not send reboot command"
        return 1
    fi
}

# Function to get detailed status of Device 2
get_device2_status() {
    echo "📊 Getting detailed status of Rock 5B Device 2..."
    
    if ! test_online; then
        echo "❌ Device 2 is offline - cannot get status"
        return 1
    fi
    
    echo "Connecting to Device 2..."
    ssh -o ConnectTimeout=10 "$DEVICE2_USER@$DEVICE2_IP" '
        echo "=== Rock 5B Device 2 System Status ==="
        echo "Date: $(date)"
        echo "Hostname: $(hostname)"
        echo "Kernel: $(uname -r)"
        echo "Uptime: $(uptime)"
        echo ""
        
        echo "=== Hardware Information ==="
        echo "Model: $(cat /proc/device-tree/model 2>/dev/null || echo "Unknown")"
        echo "CPU: $(lscpu | grep "Model name" | cut -d: -f2 | xargs)"
        echo "Architecture: $(uname -m)"
        echo ""
        
        echo "=== System Resources ==="
        echo "Load Average: $(cat /proc/loadavg)"
        echo "Memory Usage:"
        free -h
        echo ""
        echo "Disk Usage:"
        df -h /
        echo ""
        
        echo "=== Temperature ==="
        for zone in /sys/class/thermal/thermal_zone*/temp; do
            if [ -f "$zone" ]; then
                temp=$(cat "$zone")
                temp_c=$((temp / 1000))
                zone_name=$(basename "$(dirname "$zone")")
                echo "$zone_name: ${temp_c}°C"
            fi
        done
        echo ""
        
        echo "=== Network Information ==="
        echo "IP Addresses:"
        ip addr show | grep "inet " | grep -v 127.0.0.1
        echo ""
        echo "Active Connections:"
        ss -tuln | head -10
        echo ""
        
        echo "=== Running Services ==="
        systemctl list-units --type=service --state=running | head -10
    ' 2>/dev/null || echo "❌ Could not retrieve status from Device 2"
}

# Function to setup Device 2 configuration
setup_device2() {
    echo "🔧 Setting up Rock 5B Device 2 configuration..."
    
    read -p "Enter IP address for Device 2 [$DEVICE2_IP]: " new_ip
    read -p "Enter MAC address for Device 2 [$DEVICE2_MAC]: " new_mac
    read -p "Enter username for Device 2 [$DEVICE2_USER]: " new_user
    
    # Use defaults if nothing entered
    DEVICE2_IP=${new_ip:-$DEVICE2_IP}
    DEVICE2_MAC=${new_mac:-$DEVICE2_MAC}
    DEVICE2_USER=${new_user:-$DEVICE2_USER}
    
    # Save configuration
    cat > "$CONFIG_FILE" << EOF
# Rock 5B Device 2 Configuration
# Generated on $(date)
DEVICE2_IP=$DEVICE2_IP
DEVICE2_MAC=$DEVICE2_MAC
DEVICE2_USER=$DEVICE2_USER
DEVICE2_SSH_PORT=$DEVICE2_SSH_PORT
EOF
    
    echo "✅ Configuration saved to $CONFIG_FILE"
    show_config
    
    # Test the new configuration
    echo ""
    echo "🧪 Testing new configuration..."
    test_online
}

# Function to enable Wake-on-LAN on Device 2
enable_wol_device2() {
    echo "📡 Enabling Wake-on-LAN on Device 2..."
    
    if ! test_online; then
        echo "❌ Device 2 must be online to enable Wake-on-LAN"
        return 1
    fi
    
    ssh -o ConnectTimeout=10 "$DEVICE2_USER@$DEVICE2_IP" '
        echo "Checking network interfaces..."
        for iface in $(ls /sys/class/net/ | grep -E "eth|en"); do
            echo "Interface: $iface"
            
            # Check if WOL is supported
            if command -v ethtool >/dev/null 2>&1; then
                echo "WOL support:"
                sudo ethtool "$iface" | grep "Wake-on" || echo "WOL info not available"
                
                # Enable WOL
                echo "Enabling Wake-on-LAN for $iface..."
                sudo ethtool -s "$iface" wol g 2>/dev/null && echo "✅ WOL enabled" || echo "❌ WOL enable failed"
            else
                echo "ethtool not available"
            fi
            echo ""
        done
        
        # Make WOL persistent
        echo "Making WOL persistent..."
        echo "ethtool -s eth0 wol g" | sudo tee /etc/rc.local >/dev/null 2>&1 || echo "Could not make persistent"
    ' 2>/dev/null || echo "❌ Could not configure Wake-on-LAN"
}

# Function to show help
show_help() {
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Rock 5B Device 2 Management Commands:"
    echo "  power-on        - Turn on Device 2 using Wake-on-LAN"
    echo "  shutdown        - Safely shutdown Device 2"
    echo "  reboot          - Reboot Device 2"
    echo "  status          - Get detailed status of Device 2"
    echo "  test            - Test if Device 2 is online"
    echo "  config          - Show current configuration"
    echo "  setup           - Setup Device 2 configuration"
    echo "  enable-wol      - Enable Wake-on-LAN on Device 2"
    echo "  help            - Show this help message"
    echo ""
    echo "Quick Commands:"
    echo "  $0 power-on     # Turn on the second Rock 5B"
    echo "  $0 status       # Check if it's running properly"
    echo "  $0 shutdown     # Safely turn it off"
}

# Main script logic
case "${1:-help}" in
    "power-on"|"on"|"start")
        power_on_device2
        ;;
    "shutdown"|"off"|"stop")
        shutdown_device2
        ;;
    "reboot"|"restart")
        reboot_device2
        ;;
    "status"|"info")
        get_device2_status
        ;;
    "test"|"ping")
        test_online
        ;;
    "config"|"show-config")
        show_config
        ;;
    "setup"|"configure")
        setup_device2
        ;;
    "enable-wol"|"wol")
        enable_wol_device2
        ;;
    "help"|*)
        show_help
        ;;
esac
