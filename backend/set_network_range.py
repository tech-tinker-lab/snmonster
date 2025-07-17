#!/usr/bin/env python3
"""
Script to help set the correct network range for scanning
"""

import psutil
import socket
import ipaddress
import sys
import os

def get_available_networks():
    """Get all available network interfaces and their ranges"""
    networks = []
    
    try:
        gateways = psutil.net_if_addrs()
        
        for interface, addrs in gateways.items():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                    ip = ipaddress.IPv4Address(addr.address)
                    network = ipaddress.IPv4Network(f"{addr.address}/{addr.netmask}", strict=False)
                    
                    # Determine if it's a virtual interface
                    is_virtual = any(skip in interface.lower() for skip in ['vmware', 'virtualbox', 'hyper-v', 'vbox'])
                    
                    networks.append({
                        'interface': interface,
                        'ip_address': addr.address,
                        'network_range': str(network),
                        'is_virtual': is_virtual,
                        'is_private': ip.is_private
                    })
        
        return networks
    except Exception as e:
        print(f"Error getting network interfaces: {e}")
        return []

def main():
    print("🔍 Network Interface Scanner")
    print("=" * 50)
    
    networks = get_available_networks()
    
    if not networks:
        print("❌ No network interfaces found!")
        return
    
    print(f"Found {len(networks)} network interface(s):\n")
    
    # Display all networks
    for i, net in enumerate(networks, 1):
        virtual_marker = " (Virtual)" if net['is_virtual'] else ""
        private_marker = " (Private)" if net['is_private'] else " (Public)"
        
        print(f"{i}. Interface: {net['interface']}{virtual_marker}")
        print(f"   IP Address: {net['ip_address']}")
        print(f"   Network Range: {net['network_range']}{private_marker}")
        print()
    
    # Filter to show only private, non-virtual networks
    private_networks = [net for net in networks if net['is_private'] and not net['is_virtual']]
    
    if private_networks:
        print("🎯 Recommended networks (private, non-virtual):")
        for i, net in enumerate(private_networks, 1):
            print(f"   {i}. {net['network_range']} (via {net['interface']})")
        print()
    
    # Ask user to select
    try:
        if len(networks) == 1:
            selected = 1
            print(f"Auto-selecting the only available network: {networks[0]['network_range']}")
        else:
            print("Select a network range to use for scanning:")
            selected = int(input("Enter number (or 0 to cancel): "))
            
        if selected == 0:
            print("Cancelled.")
            return
            
        if 1 <= selected <= len(networks):
            chosen_network = networks[selected - 1]
            network_range = chosen_network['network_range']
            
            print(f"\n✅ Selected: {network_range}")
            print(f"Interface: {chosen_network['interface']}")
            print(f"IP Address: {chosen_network['ip_address']}")
            
            # Set environment variable
            os.environ['NETWORK_RANGE'] = network_range
            
            # Create a .env file for persistence
            env_content = f"NETWORK_RANGE={network_range}\n"
            with open('.env', 'w') as f:
                f.write(env_content)
            
            print(f"\n💾 Network range saved to environment variable and .env file")
            print(f"🔧 To use this setting, restart your application or run:")
            print(f"   set NETWORK_RANGE={network_range}  # Windows")
            print(f"   export NETWORK_RANGE={network_range}  # Linux/Mac")
            
        else:
            print("❌ Invalid selection!")
            
    except ValueError:
        print("❌ Please enter a valid number!")
    except KeyboardInterrupt:
        print("\n❌ Cancelled by user.")

if __name__ == "__main__":
    main() 