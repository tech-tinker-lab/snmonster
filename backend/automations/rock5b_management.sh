#!/bin/bash
# Rock 5B Single Board Computer Management Script
# Provides useful commands for managing Rock 5B devices

set -e

echo "=== Rock 5B Management System ==="

# Rock 5B specific configurations
ROCK5B_DEFAULT_USER="rock"
ROCK5B_DEFAULT_SSH_PORT="22"
GPIO_BASE="/sys/class/gpio"
POWER_LED_GPIO="32"
STATUS_LED_GPIO="35"

# Function to show help
show_help() {
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Rock 5B Management Commands:"
    echo "  power-on <ip>             - Power on Rock 5B device remotely"
    echo "  power-off <ip>            - Safe shutdown Rock 5B device"
    echo "  reboot <ip>               - Reboot Rock 5B device"
    echo "  status <ip>               - Check Rock 5B device status"
    echo "  wake-on-lan <mac>         - Wake device using WOL"
    echo "  gpio-control <pin> <val>  - Control GPIO pins"
    echo "  temperature               - Check system temperature"
    echo "  performance               - Show performance metrics"
    echo "  usb-devices               - List USB devices"
    echo "  network-config            - Show network configuration"
    echo "  storage-info              - Show storage information"
    echo "  setup-second-device       - Setup second Rock 5B device"
    echo "  cluster-setup             - Setup Rock 5B cluster"
    echo "  help                      - Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 power-on 192.168.1.100"
    echo "  $0 wake-on-lan aa:bb:cc:dd:ee:ff"
    echo "  $0 setup-second-device"
    echo "  $0 cluster-setup"
}

# Function to check if device is Rock 5B
check_rock5b() {
    local ip=$1
    echo "🔍 Checking if device is Rock 5B..."
    
    # Check via SSH
    if ssh -o ConnectTimeout=5 "$ROCK5B_DEFAULT_USER@$ip" "cat /proc/device-tree/model" 2>/dev/null | grep -i "rock.*5b"; then
        echo "✅ Confirmed Rock 5B device at $ip"
        return 0
    else
        echo "❌ Device at $ip is not a Rock 5B or not accessible"
        return 1
    fi
}

# Function to power on Rock 5B device
power_on_device() {
    local ip=$1
    if [ -z "$ip" ]; then
        echo "Please provide IP address"
        return 1
    fi
    
    echo "🔌 Attempting to power on Rock 5B at $ip..."
    
    # Try Wake-on-LAN first (if MAC is known)
    echo "Attempting Wake-on-LAN..."
    # You'll need to replace with actual MAC address
    # wakeonlan aa:bb:cc:dd:ee:ff
    
    # Try IPMI or other remote power methods if available
    echo "Checking for remote power management..."
    
    # Wait and check if device comes online
    echo "Waiting for device to come online..."
    for i in {1..30}; do
        if ping -c 1 "$ip" >/dev/null 2>&1; then
            echo "✅ Device is now online at $ip"
            return 0
        fi
        echo "Waiting... ($i/30)"
        sleep 2
    done
    
    echo "❌ Device did not come online within 60 seconds"
    return 1
}

# Function to safely shutdown device
power_off_device() {
    local ip=$1
    if [ -z "$ip" ]; then
        echo "Please provide IP address"
        return 1
    fi
    
    echo "🔴 Safely shutting down Rock 5B at $ip..."
    
    if check_rock5b "$ip"; then
        ssh "$ROCK5B_DEFAULT_USER@$ip" "sudo shutdown -h now"
        echo "✅ Shutdown command sent to $ip"
    fi
}

# Function to reboot device
reboot_device() {
    local ip=$1
    if [ -z "$ip" ]; then
        echo "Please provide IP address"
        return 1
    fi
    
    echo "🔄 Rebooting Rock 5B at $ip..."
    
    if check_rock5b "$ip"; then
        ssh "$ROCK5B_DEFAULT_USER@$ip" "sudo reboot"
        echo "✅ Reboot command sent to $ip"
    fi
}

# Function to check device status
check_status() {
    local ip=$1
    if [ -z "$ip" ]; then
        echo "Please provide IP address"
        return 1
    fi
    
    echo "📊 Checking Rock 5B status at $ip..."
    
    if ping -c 1 "$ip" >/dev/null 2>&1; then
        echo "✅ Device is online"
        
        if check_rock5b "$ip"; then
            echo "🔍 Getting detailed status..."
            ssh "$ROCK5B_DEFAULT_USER@$ip" '
                echo "=== Rock 5B System Status ==="
                echo "Hostname: $(hostname)"
                echo "Uptime: $(uptime)"
                echo "Load: $(cat /proc/loadavg)"
                echo "Memory: $(free -h | grep Mem)"
                echo "Temperature: $(cat /sys/class/thermal/thermal_zone*/temp 2>/dev/null | head -1 | awk "{print \$1/1000\"°C\"}")"
                echo "Disk usage: $(df -h / | tail -1)"
                echo "Network: $(ip addr show | grep "inet " | grep -v 127.0.0.1)"
            '
        fi
    else
        echo "❌ Device is offline or unreachable"
    fi
}

# Function for Wake-on-LAN
wake_on_lan() {
    local mac=$1
    if [ -z "$mac" ]; then
        echo "Please provide MAC address (format: aa:bb:cc:dd:ee:ff)"
        return 1
    fi
    
    echo "📡 Sending Wake-on-LAN packet to $mac..."
    
    if command -v wakeonlan >/dev/null 2>&1; then
        wakeonlan "$mac"
        echo "✅ Wake-on-LAN packet sent"
    elif command -v etherwake >/dev/null 2>&1; then
        etherwake "$mac"
        echo "✅ Wake-on-LAN packet sent"
    else
        echo "❌ Wake-on-LAN tool not found. Install wakeonlan or etherwake"
        return 1
    fi
}

# Function to control GPIO (local only)
gpio_control() {
    local pin=$1
    local value=$2
    
    if [ -z "$pin" ] || [ -z "$value" ]; then
        echo "Usage: gpio-control <pin> <value>"
        echo "Example: gpio-control 32 1"
        return 1
    fi
    
    echo "🔌 Controlling GPIO pin $pin = $value"
    
    # Export GPIO if not already exported
    if [ ! -d "$GPIO_BASE/gpio$pin" ]; then
        echo "$pin" > "$GPIO_BASE/export"
    fi
    
    # Set direction to output
    echo "out" > "$GPIO_BASE/gpio$pin/direction"
    
    # Set value
    echo "$value" > "$GPIO_BASE/gpio$pin/value"
    
    echo "✅ GPIO $pin set to $value"
}

# Function to check temperature
check_temperature() {
    echo "🌡️ Rock 5B Temperature Status:"
    
    for zone in /sys/class/thermal/thermal_zone*/temp; do
        if [ -f "$zone" ]; then
            temp=$(cat "$zone")
            temp_c=$((temp / 1000))
            zone_name=$(basename "$(dirname "$zone")")
            echo "$zone_name: ${temp_c}°C"
        fi
    done
    
    # Check CPU frequency
    echo -e "\n⚡ CPU Frequency:"
    for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq; do
        if [ -f "$cpu" ]; then
            freq=$(cat "$cpu")
            freq_mhz=$((freq / 1000))
            cpu_num=$(echo "$cpu" | grep -o 'cpu[0-9]*' | grep -o '[0-9]*')
            echo "CPU$cpu_num: ${freq_mhz}MHz"
        fi
    done
}

# Function to show performance metrics
show_performance() {
    echo "📈 Rock 5B Performance Metrics:"
    echo "=== CPU Information ==="
    lscpu | grep -E "(Model name|CPU\(s\)|Thread|Core|Socket)"
    
    echo -e "\n=== Memory Information ==="
    free -h
    
    echo -e "\n=== Storage Performance ==="
    if command -v hdparm >/dev/null 2>&1; then
        hdparm -t /dev/mmcblk* 2>/dev/null || echo "Storage test not available"
    fi
    
    echo -e "\n=== Network Performance ==="
    for iface in $(ls /sys/class/net/ | grep -E "eth|wlan|en"); do
        speed=$(cat "/sys/class/net/$iface/speed" 2>/dev/null || echo "unknown")
        echo "$iface: ${speed}Mbps"
    done
}

# Function to list USB devices
list_usb_devices() {
    echo "🔌 USB Devices Connected to Rock 5B:"
    
    if command -v lsusb >/dev/null 2>&1; then
        lsusb
    else
        echo "lsusb not available, checking /sys/bus/usb/devices"
        for device in /sys/bus/usb/devices/*/product; do
            if [ -f "$device" ]; then
                echo "$(cat "$device")"
            fi
        done
    fi
}

# Function to show network configuration
show_network_config() {
    echo "🌐 Rock 5B Network Configuration:"
    
    echo "=== Network Interfaces ==="
    ip addr show
    
    echo -e "\n=== Routing Table ==="
    ip route show
    
    echo -e "\n=== DNS Configuration ==="
    cat /etc/resolv.conf
    
    echo -e "\n=== Network Statistics ==="
    cat /proc/net/dev
}

# Function to show storage information
show_storage_info() {
    echo "💾 Rock 5B Storage Information:"
    
    echo "=== Mounted Filesystems ==="
    df -h
    
    echo -e "\n=== Block Devices ==="
    lsblk
    
    echo -e "\n=== Storage Device Details ==="
    for dev in /dev/mmcblk* /dev/sd* /dev/nvme*; do
        if [ -b "$dev" ]; then
            echo "Device: $dev"
            if command -v fdisk >/dev/null 2>&1; then
                fdisk -l "$dev" 2>/dev/null | head -5
            fi
            echo ""
        fi
    done
}

# Function to setup second Rock 5B device
setup_second_device() {
    echo "🔧 Setting up second Rock 5B device..."
    
    read -p "Enter IP address of second Rock 5B: " second_ip
    read -p "Enter MAC address for Wake-on-LAN (optional): " second_mac
    
    if [ -z "$second_ip" ]; then
        echo "IP address is required"
        return 1
    fi
    
    echo "Testing connection to second device..."
    if check_rock5b "$second_ip"; then
        echo "✅ Second Rock 5B detected and accessible"
        
        # Configure SSH keys for passwordless access
        echo "Setting up SSH keys..."
        ssh-copy-id "$ROCK5B_DEFAULT_USER@$second_ip" 2>/dev/null || echo "SSH key setup skipped"
        
        # Enable Wake-on-LAN if MAC provided
        if [ -n "$second_mac" ]; then
            echo "Configuring Wake-on-LAN..."
            ssh "$ROCK5B_DEFAULT_USER@$second_ip" "sudo ethtool -s eth0 wol g" 2>/dev/null || echo "WOL setup skipped"
        fi
        
        # Save configuration
        echo "Saving device configuration..."
        cat > "/tmp/rock5b_device2.conf" << EOF
# Rock 5B Device 2 Configuration
DEVICE2_IP=$second_ip
DEVICE2_MAC=$second_mac
DEVICE2_USER=$ROCK5B_DEFAULT_USER
DEVICE2_SETUP_DATE=$(date)
EOF
        
        echo "✅ Second Rock 5B device setup complete!"
        echo "Configuration saved to /tmp/rock5b_device2.conf"
    else
        echo "❌ Could not connect to second Rock 5B device"
        return 1
    fi
}

# Function to setup Rock 5B cluster
setup_cluster() {
    echo "🖥️ Setting up Rock 5B cluster..."
    
    read -p "Number of Rock 5B devices in cluster (2-8): " cluster_size
    
    if [ "$cluster_size" -lt 2 ] || [ "$cluster_size" -gt 8 ]; then
        echo "Cluster size must be between 2 and 8"
        return 1
    fi
    
    echo "Setting up $cluster_size node Rock 5B cluster..."
    
    # Collect device information
    declare -a cluster_ips
    declare -a cluster_macs
    
    for i in $(seq 1 "$cluster_size"); do
        read -p "Enter IP for Rock 5B node $i: " node_ip
        read -p "Enter MAC for Rock 5B node $i (optional): " node_mac
        cluster_ips[$i]=$node_ip
        cluster_macs[$i]=$node_mac
    done
    
    # Test connectivity to all nodes
    echo "Testing connectivity to all cluster nodes..."
    for i in $(seq 1 "$cluster_size"); do
        echo "Testing node $i: ${cluster_ips[$i]}"
        if ! check_rock5b "${cluster_ips[$i]}"; then
            echo "❌ Node $i is not accessible"
            return 1
        fi
    done
    
    echo "✅ All cluster nodes are accessible"
    
    # Generate cluster configuration
    cat > "/tmp/rock5b_cluster.conf" << EOF
# Rock 5B Cluster Configuration
CLUSTER_SIZE=$cluster_size
CLUSTER_SETUP_DATE=$(date)

EOF
    
    for i in $(seq 1 "$cluster_size"); do
        cat >> "/tmp/rock5b_cluster.conf" << EOF
NODE${i}_IP=${cluster_ips[$i]}
NODE${i}_MAC=${cluster_macs[$i]}
EOF
    done
    
    echo "✅ Rock 5B cluster configuration saved to /tmp/rock5b_cluster.conf"
    echo "💡 Consider setting up Kubernetes or Docker Swarm for container orchestration"
}

# Main script logic
case "${1:-help}" in
    "power-on")
        power_on_device "$2"
        ;;
    "power-off")
        power_off_device "$2"
        ;;
    "reboot")
        reboot_device "$2"
        ;;
    "status")
        check_status "$2"
        ;;
    "wake-on-lan")
        wake_on_lan "$2"
        ;;
    "gpio-control")
        gpio_control "$2" "$3"
        ;;
    "temperature")
        check_temperature
        ;;
    "performance")
        show_performance
        ;;
    "usb-devices")
        list_usb_devices
        ;;
    "network-config")
        show_network_config
        ;;
    "storage-info")
        show_storage_info
        ;;
    "setup-second-device")
        setup_second_device
        ;;
    "cluster-setup")
        setup_cluster
        ;;
    "help"|*)
        show_help
        ;;
esac
