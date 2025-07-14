import asyncio
import ipaddress
import socket
import subprocess
import platform
import json
import logging
import re
from datetime import datetime
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed, thread
import threading
import nmap
from scapy.all import ARP, Ether, srp
import psutil
from backend.database import get_db
from backend.models import Device, DeviceStatus, DeviceType, OperatingSystem

logger = logging.getLogger(__name__)

class NetworkScanner:
    def __init__(self, websocket_manager):
        self.websocket_manager = websocket_manager
        self.is_running = False
        self.is_scanning = False
        self.last_scan_time = None
        self.devices_found = 0
        self.scan_task = None
        self.stop_scan_event = asyncio.Event()
        
        # Network configuration
        self.network_range = self._get_network_range()
        self.scan_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443]
        
        # Initialize nmap scanner (optional)
        self.nmap_scanner = None
        try:
            self.nmap_scanner = nmap.PortScanner()
            logger.info("Nmap scanner initialized successfully")
        except Exception as e:
            logger.warning(f"Nmap not available: {e}")
            logger.info("Network scanning will use alternative methods (ping, socket)")
        
        logger.info(f"Network scanner initialized for range: {self.network_range}")
    
    def _get_network_range(self) -> str:
        """Get the local network range"""
        try:
            # Get default gateway interface
            gateways = psutil.net_if_addrs()
            for interface, addrs in gateways.items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                        ip = ipaddress.IPv4Address(addr.address)
                        network = ipaddress.IPv4Network(f"{addr.address}/{addr.netmask}", strict=False)
                        return str(network)
            
            # Fallback to common local ranges
            return "192.168.1.0/24"
        except Exception as e:
            logger.error(f"Error getting network range: {e}")
            return "192.168.1.0/24"
    
    async def start_periodic_scan(self):
        """Start periodic network scanning"""
        self.is_running = True
        logger.info("Starting periodic network scanning...")
        
        while self.is_running:
            try:
                await self.scan_network()
                # Wait 5 minutes before next scan
                await asyncio.sleep(300)
            except Exception as e:
                logger.error(f"Error in periodic scan: {e}")
                await asyncio.sleep(60)  # Wait 1 minute on error
    
    async def scan_network(self):
        """Perform a comprehensive network scan"""
        if self.is_scanning:
            logger.warning("Scan already in progress")
            return
        
        self.is_scanning = True
        self.stop_scan_event.clear()
        start_time = datetime.now()
        
        logger.info(f"Starting network scan of {self.network_range}")
        
        try:
            # Notify frontend
            await self.websocket_manager.broadcast({
                "type": "scan_started",
                "timestamp": start_time.isoformat(),
                "network_range": self.network_range
            })
            
            # Perform different types of scans
            devices = []
            
            # 1. ARP scan (fast)
            arp_devices = await self._arp_scan()
            devices.extend(arp_devices)
            
            if self.stop_scan_event.is_set():
                return
            
            # 2. Ping scan
            ping_devices = await self._ping_scan()
            devices.extend(ping_devices)
            
            if self.stop_scan_event.is_set():
                return
            
            # 3. Port scan for discovered devices
            await self._port_scan_devices(devices)
            
            # 4. OS detection
            await self._detect_operating_systems(devices)
            
            # Save devices to database
            await self._save_devices(devices)
            
            self.devices_found = len(devices)
            self.last_scan_time = datetime.now()
            
            # Notify frontend
            await self.websocket_manager.broadcast({
                "type": "scan_completed",
                "timestamp": self.last_scan_time.isoformat(),
                "devices_found": self.devices_found,
                "scan_duration": (self.last_scan_time - start_time).total_seconds()
            })
            
            logger.info(f"Network scan completed. Found {self.devices_found} devices")
            
        except Exception as e:
            logger.error(f"Error during network scan: {e}")
            await self.websocket_manager.broadcast({
                "type": "scan_error",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            })
        finally:
            self.is_scanning = False
    
    async def _arp_scan(self) -> List[Dict[str, Any]]:
        """Perform ARP scan to discover devices"""
        logger.info("Starting ARP scan...")
        devices = []
        
        try:
            # Create ARP request packet
            arp = ARP(pdst=self.network_range)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            # Send packet and capture responses
            result = srp(packet, timeout=3, verbose=0)[0]
            
            for sent, received in result:
                device = {
                    "ip_address": received.psrc,
                    "mac_address": received.hwsrc,
                    "hostname": None,
                    "device_type": DeviceType.UNKNOWN,
                    "operating_system": OperatingSystem.UNKNOWN,
                    "status": DeviceStatus.ONLINE,
                    "last_seen": datetime.now(),
                    "response_time": None
                }
                devices.append(device)
                
                logger.info(f"ARP: Found device {device['ip_address']} ({device['mac_address']})")
        
        except Exception as e:
            logger.error(f"Error in ARP scan: {e}")
        
        return devices
    
    async def _ping_scan(self) -> List[Dict[str, Any]]:
        """Perform ping scan to discover devices"""
        logger.info("Starting ping scan...")
        devices = []
        
        try:
            network = ipaddress.IPv4Network(self.network_range, strict=False)
            
            # Use ThreadPoolExecutor for concurrent pings
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = []
                
                for ip in network.hosts():
                    if self.stop_scan_event.is_set():
                        break
                    futures.append(executor.submit(self._ping_host, str(ip)))
                
                for future in as_completed(futures):
                    if self.stop_scan_event.is_set():
                        break
                    result = future.result()
                    if result:
                        devices.append(result)
        
        except Exception as e:
            logger.error(f"Error in ping scan: {e}")
        
        return devices
    
    def _ping_host(self, ip: str) -> Optional[Dict[str, Any]]:
        """Ping a single host"""
        try:
            # Use platform-specific ping command
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", "1", "-w", "1000", ip]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
            
            if result.returncode == 0:
                device = {
                    "ip_address": ip,
                    "mac_address": None,
                    "hostname": None,
                    "device_type": DeviceType.UNKNOWN,
                    "operating_system": OperatingSystem.UNKNOWN,
                    "status": DeviceStatus.ONLINE,
                    "last_seen": datetime.now(),
                    "response_time": None
                }
                
                logger.info(f"Ping: Found device {ip}")
                return device
        
        except Exception as e:
            logger.debug(f"Ping failed for {ip}: {e}")
        
        return None
    
    def _detect_service(self, port: int, banner: str) -> str:
        """AI-powered (heuristic) service detection based on port and banner"""
        banner_l = (banner or '').lower()
        if 'ssh' in banner_l:
            return 'SSH'
        if 'http' in banner_l:
            return 'HTTP'
        if 'smtp' in banner_l:
            return 'SMTP'
        if 'ftp' in banner_l:
            return 'FTP'
        if 'rdp' in banner_l or 'remote desktop' in banner_l:
            return 'RDP'
        if 'telnet' in banner_l:
            return 'Telnet'
        # Fallback to port mapping
        common_ports = {22: 'SSH', 80: 'HTTP', 443: 'HTTPS', 21: 'FTP', 25: 'SMTP', 3389: 'RDP', 23: 'Telnet'}
        return common_ports.get(port, 'Unknown')

    async def _port_scan_devices(self, devices: List[Dict[str, Any]]):
        """Perform port scan on discovered devices, grab banners, and detect services using a thread pool for concurrency. Threads are daemonized for responsive shutdown."""
        logger.info("Starting port scan...")
        loop = asyncio.get_event_loop()
        for device in devices:
            if self.stop_scan_event.is_set():
                break
            try:
                ip = device["ip_address"]
                open_ports = []
                def scan_port(port):
                    if self.stop_scan_event.is_set():
                        return None
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)
                        result = sock.connect_ex((ip, port))
                        banner = ''
                        if result == 0:
                            try:
                                sock.settimeout(2)
                                banner = sock.recv(1024).decode(errors='ignore').strip()
                            except Exception:
                                banner = ''
                            service = self._detect_service(port, banner)
                            logger.debug(f"Port {port} open on {ip} - Service: {service} - Banner: {banner}")
                            return {'port': port, 'service': service, 'banner': banner}
                        sock.close()
                    except Exception as e:
                        logger.debug(f"Error scanning port {port} on {ip}: {e}")
                    return None
                class DaemonThreadPoolExecutor(ThreadPoolExecutor):
                    def _thread_factory(self, *args, **kwargs):
                        t = threading.Thread(*args, **kwargs)
                        t.daemon = True
                        return t
                with DaemonThreadPoolExecutor(max_workers=16) as executor:
                    futures = [loop.run_in_executor(executor, scan_port, port) for port in self.scan_ports]
                    results = await asyncio.gather(*futures)
                    open_ports = [r for r in results if r]
                device["open_ports"] = json.dumps(open_ports)
                device["device_type"] = self._determine_device_type([p['port'] for p in open_ports])
            except Exception as e:
                logger.error(f"Error port scanning {device.get('ip_address', 'unknown')}: {e}")
    
    def _determine_device_type(self, open_ports: List[int]) -> DeviceType:
        """Determine device type based on open ports"""
        if 80 in open_ports or 443 in open_ports or 8080 in open_ports:
            return DeviceType.SERVER
        elif 22 in open_ports and 23 in open_ports:
            return DeviceType.ROUTER
        elif 21 in open_ports or 23 in open_ports:
            return DeviceType.SWITCH
        elif 9100 in open_ports or 631 in open_ports:
            return DeviceType.PRINTER
        else:
            return DeviceType.COMPUTER
    
    async def _detect_operating_systems(self, devices: List[Dict[str, Any]]):
        """Detect operating systems of discovered devices using a thread pool for concurrency."""
        logger.info("Starting OS detection...")
        import threading
        from concurrent.futures import ThreadPoolExecutor

        def detect_os(device):
            try:
                ip = device["ip_address"]
                # Use nmap for OS detection (if available)
                if self.nmap_scanner:
                    try:
                        self.nmap_scanner.scan(ip, arguments='-O --osscan-guess')
                        if ip in self.nmap_scanner.all_hosts():
                            os_info = self.nmap_scanner[ip].get('osmatch', [])
                            if os_info:
                                os_name = os_info[0]['name'].lower()
                                if 'windows' in os_name:
                                    device["operating_system"] = OperatingSystem.WINDOWS
                                elif 'linux' in os_name:
                                    device["operating_system"] = OperatingSystem.LINUX
                                elif 'mac' in os_name or 'darwin' in os_name:
                                    device["operating_system"] = OperatingSystem.MACOS
                                elif 'android' in os_name:
                                    device["operating_system"] = OperatingSystem.ANDROID
                                elif 'ios' in os_name:
                                    device["operating_system"] = OperatingSystem.IOS
                    except Exception as e:
                        logger.debug(f"OS detection failed for {ip}: {e}")
                else:
                    # Fallback OS detection based on TTL values
                    try:
                        ttl = self._get_ttl(ip)
                        if ttl:
                            if ttl <= 64:
                                device["operating_system"] = OperatingSystem.LINUX
                            elif ttl <= 128:
                                device["operating_system"] = OperatingSystem.WINDOWS
                            else:
                                device["operating_system"] = OperatingSystem.UNKNOWN
                    except Exception as e:
                        logger.debug(f"Fallback OS detection failed for {ip}: {e}")
                # Try to get hostname
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                    device["hostname"] = hostname
                except Exception as e:
                    logger.debug(f"Hostname resolution failed for {ip}: {e}")
            except Exception as e:
                logger.error(f"Error in OS detection for {device.get('ip_address', 'unknown')}: {e}")

        class DaemonThreadPoolExecutor(ThreadPoolExecutor):
            def _thread_factory(self, *args, **kwargs):
                t = threading.Thread(*args, **kwargs)
                t.daemon = True
                return t

        with DaemonThreadPoolExecutor(max_workers=16) as executor:
            futures = [executor.submit(detect_os, device) for device in devices]
            for future in futures:
                future.result()  # Wait for all to complete
    
    async def _save_devices(self, devices: List[Dict[str, Any]]):
        """Save discovered devices to database"""
        logger.info("Saving devices to database...")
        
        try:
            db = get_db()
            
            for device_data in devices:
                try:
                    # Check if device already exists
                    existing_device = db.query(Device).filter(
                        Device.ip_address == device_data["ip_address"]
                    ).first()
                    
                    if existing_device:
                        # Update existing device
                        existing_device.last_seen = device_data["last_seen"]
                        existing_device.status = device_data["status"]
                        if device_data.get("hostname"):
                            existing_device.hostname = device_data["hostname"]
                        if device_data.get("mac_address"):
                            existing_device.mac_address = device_data["mac_address"]
                        if device_data.get("device_type"):
                            existing_device.device_type = device_data["device_type"]
                        if device_data.get("operating_system"):
                            existing_device.operating_system = device_data["operating_system"]
                        if device_data.get("open_ports"):
                            existing_device.open_ports = device_data["open_ports"]
                    else:
                        # Create new device
                        new_device = Device(**device_data)
                        db.add(new_device)
                    
                    db.commit()
                    
                except Exception as e:
                    logger.error(f"Error saving device {device_data.get('ip_address', 'unknown')}: {e}")
                    db.rollback()
            
            logger.info(f"Successfully saved {len(devices)} devices to database")
            
        except Exception as e:
            logger.error(f"Error saving devices to database: {e}")
    
    async def stop_current_scan(self):
        """Stop the current scan"""
        if self.is_scanning:
            logger.info("Stopping current scan...")
            self.stop_scan_event.set()
            if self.scan_task:
                self.scan_task.cancel()
    
    def _get_ttl(self, ip: str) -> Optional[int]:
        """Get TTL value for OS detection"""
        try:
            # Use ping to get TTL
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", "1", "-w", "1000", ip]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            
            if result.returncode == 0:
                # Parse TTL from ping output
                output = result.stdout
                if "TTL=" in output:
                    ttl_match = re.search(r'TTL=(\d+)', output)
                    if ttl_match:
                        return int(ttl_match.group(1))
        except Exception as e:
            logger.debug(f"TTL detection failed for {ip}: {e}")
        
        return None
    
    async def stop(self):
        """Stop the network scanner"""
        logger.info("Stopping network scanner...")
        self.is_running = False
        await self.stop_current_scan() 