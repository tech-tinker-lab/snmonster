#!/bin/bash
# Comprehensive Security Audit Script
# Collects security data for AI analysis

set -e

echo "=== Security Audit & Network Analysis ==="
echo "Collecting security data for AI analysis..."

# Create audit directory
AUDIT_DIR="/tmp/security_audit_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$AUDIT_DIR"

echo "📁 Audit data will be saved to: $AUDIT_DIR"

# System Information
echo "🔍 Collecting system information..."
{
    echo "=== SYSTEM INFORMATION ==="
    echo "Hostname: $(hostname)"
    echo "OS: $(cat /etc/os-release 2>/dev/null || echo 'Unknown')"
    echo "Kernel: $(uname -r)"
    echo "Architecture: $(uname -m)"
    echo "Uptime: $(uptime)"
    echo "Load Average: $(cat /proc/loadavg 2>/dev/null || echo 'N/A')"
    echo "Memory: $(free -h 2>/dev/null || echo 'N/A')"
    echo "Disk Usage: $(df -h 2>/dev/null || echo 'N/A')"
} > "$AUDIT_DIR/system_info.txt"

# Network Analysis
echo "🌐 Analyzing network configuration..."
{
    echo "=== NETWORK ANALYSIS ==="
    echo "IP Addresses:"
    ip addr show 2>/dev/null || ifconfig 2>/dev/null || echo "Network tools not available"
    
    echo -e "\nRouting Table:"
    ip route show 2>/dev/null || route -n 2>/dev/null || echo "Routing info not available"
    
    echo -e "\nDNS Configuration:"
    cat /etc/resolv.conf 2>/dev/null || echo "DNS config not available"
    
    echo -e "\nNetwork Interfaces:"
    ip link show 2>/dev/null || echo "Interface info not available"
} > "$AUDIT_DIR/network_analysis.txt"

# Open Ports and Services
echo "🔌 Scanning open ports and services..."
{
    echo "=== OPEN PORTS & SERVICES ==="
    echo "Listening ports:"
    netstat -tuln 2>/dev/null || ss -tuln 2>/dev/null || echo "Port scanning tools not available"
    
    echo -e "\nActive connections:"
    netstat -tuln 2>/dev/null || ss -tuln 2>/dev/null || echo "Connection info not available"
    
    echo -e "\nRunning services:"
    systemctl list-units --type=service --state=running 2>/dev/null || service --status-all 2>/dev/null || echo "Service info not available"
} > "$AUDIT_DIR/ports_services.txt"

# Process Analysis
echo "⚙️ Analyzing running processes..."
{
    echo "=== PROCESS ANALYSIS ==="
    echo "Top processes by CPU:"
    ps aux --sort=-%cpu | head -20 2>/dev/null || echo "Process info not available"
    
    echo -e "\nTop processes by memory:"
    ps aux --sort=-%mem | head -20 2>/dev/null || echo "Process info not available"
    
    echo -e "\nSuspicious processes (high CPU/memory):"
    ps aux | awk '$3 > 50 || $4 > 50 {print}' 2>/dev/null || echo "Process analysis not available"
} > "$AUDIT_DIR/process_analysis.txt"

# Security Analysis
echo "🔒 Performing security analysis..."
{
    echo "=== SECURITY ANALYSIS ==="
    
    echo "Failed login attempts:"
    grep "Failed password" /var/log/auth.log 2>/dev/null | tail -20 || echo "Auth logs not available"
    
    echo -e "\nSuccessful logins:"
    grep "Accepted password" /var/log/auth.log 2>/dev/null | tail -20 || echo "Auth logs not available"
    
    echo -e "\nSudo usage:"
    grep "sudo:" /var/log/auth.log 2>/dev/null | tail -20 || echo "Sudo logs not available"
    
    echo -e "\nSSH connections:"
    grep "sshd" /var/log/auth.log 2>/dev/null | tail -20 || echo "SSH logs not available"
    
    echo -e "\nFirewall status:"
    ufw status 2>/dev/null || iptables -L 2>/dev/null || echo "Firewall info not available"
} > "$AUDIT_DIR/security_analysis.txt"

# Package Analysis
echo "📦 Analyzing installed packages..."
{
    echo "=== PACKAGE ANALYSIS ==="
    
    if command -v apt &> /dev/null; then
        echo "Ubuntu/Debian packages:"
        apt list --installed 2>/dev/null | head -50 || echo "Package list not available"
    elif command -v yum &> /dev/null; then
        echo "CentOS/RHEL packages:"
        yum list installed 2>/dev/null | head -50 || echo "Package list not available"
    elif command -v dnf &> /dev/null; then
        echo "Fedora packages:"
        dnf list installed 2>/dev/null | head -50 || echo "Package list not available"
    else
        echo "Package manager not detected"
    fi
} > "$AUDIT_DIR/package_analysis.txt"

# Network Traffic Analysis (if tcpdump available)
echo "📊 Analyzing network traffic patterns..."
{
    echo "=== NETWORK TRAFFIC ANALYSIS ==="
    
    if command -v tcpdump &> /dev/null; then
        echo "Capturing network traffic for 30 seconds..."
        echo "This will show active connections and traffic patterns"
        timeout 30 tcpdump -i any -c 100 2>/dev/null || echo "Network capture failed"
    else
        echo "tcpdump not available for traffic analysis"
    fi
    
    echo -e "\nActive network connections:"
    netstat -tuln 2>/dev/null || ss -tuln 2>/dev/null || echo "Connection info not available"
} > "$AUDIT_DIR/network_traffic.txt"

# Create AI-ready summary
echo "🤖 Generating AI-ready summary..."
{
    echo "=== AI ANALYSIS SUMMARY ==="
    echo "Generated: $(date)"
    echo "Hostname: $(hostname)"
    echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2 2>/dev/null || echo 'Unknown')"
    echo "Open ports count: $(netstat -tuln 2>/dev/null | grep LISTEN | wc -l || echo '0')"
    echo "Running services count: $(systemctl list-units --type=service --state=running 2>/dev/null | wc -l || echo '0')"
    echo "Failed login attempts (last 24h): $(grep 'Failed password' /var/log/auth.log 2>/dev/null | grep "$(date '+%b %d')" | wc -l || echo '0')"
    echo "Memory usage: $(free | grep Mem | awk '{printf "%.1f%%", $3/$2 * 100.0}')"
    echo "Disk usage: $(df / | tail -1 | awk '{print $5}')"
    
    echo -e "\n=== SECURITY RISK INDICATORS ==="
    echo "High CPU processes: $(ps aux | awk '$3 > 50 {count++} END {print count+0}')"
    echo "High memory processes: $(ps aux | awk '$4 > 50 {count++} END {print count+0}')"
    echo "Suspicious network connections: $(netstat -tuln 2>/dev/null | grep -E ':(22|23|3389|5900)' | wc -l || echo '0')"
    
    echo -e "\n=== RECOMMENDATIONS ==="
    echo "1. Review failed login attempts for brute force attacks"
    echo "2. Check high CPU/memory processes for malware"
    echo "3. Verify all open ports are necessary"
    echo "4. Update system packages regularly"
    echo "5. Monitor network traffic for anomalies"
} > "$AUDIT_DIR/ai_summary.txt"

echo "✅ Security audit complete!"
echo "📁 All data saved to: $AUDIT_DIR"
echo "🤖 AI-ready summary: $AUDIT_DIR/ai_summary.txt"
echo ""
echo "Files generated:"
ls -la "$AUDIT_DIR" 