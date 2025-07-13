from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, Float, Enum
from sqlalchemy.sql import func
from database import Base
import enum
from datetime import datetime
from typing import Dict, Any

class DeviceStatus(enum.Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    UNKNOWN = "unknown"
    MAINTENANCE = "maintenance"

class DeviceType(enum.Enum):
    COMPUTER = "computer"
    ROUTER = "router"
    SWITCH = "switch"
    PRINTER = "printer"
    MOBILE = "mobile"
    IOT = "iot"
    SERVER = "server"
    UNKNOWN = "unknown"

class OperatingSystem(enum.Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    ANDROID = "android"
    IOS = "ios"
    UNKNOWN = "unknown"

class Device(Base):
    __tablename__ = "devices"
    
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(15), unique=True, index=True, nullable=False)
    mac_address = Column(String(17), index=True)
    hostname = Column(String(255))
    device_type = Column(Enum(DeviceType), default=DeviceType.UNKNOWN)
    operating_system = Column(Enum(OperatingSystem), default=OperatingSystem.UNKNOWN)
    status = Column(Enum(DeviceStatus), default=DeviceStatus.UNKNOWN)
    
    # Network information
    subnet = Column(String(18))
    gateway = Column(String(15))
    dns_servers = Column(Text)  # JSON string of DNS servers
    
    # System information
    cpu_info = Column(Text)  # JSON string of CPU information
    memory_info = Column(Text)  # JSON string of memory information
    disk_info = Column(Text)  # JSON string of disk information
    
    # Security information
    open_ports = Column(Text)  # JSON string of open ports
    vulnerabilities = Column(Text)  # JSON string of detected vulnerabilities
    last_security_scan = Column(DateTime)
    
    # Monitoring information
    last_seen = Column(DateTime, default=func.now())
    first_seen = Column(DateTime, default=func.now())
    uptime = Column(Float)  # in seconds
    response_time = Column(Float)  # in milliseconds
    
    # AI analysis
    ai_risk_score = Column(Float, default=0.0)
    ai_recommendations = Column(Text)  # JSON string of AI recommendations
    
    # Metadata
    vendor = Column(String(255))
    model = Column(String(255))
    serial_number = Column(String(255))
    location = Column(String(255))
    notes = Column(Text)
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert device to dictionary"""
        result = {
            "id": self.id,
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "hostname": self.hostname,
            "subnet": self.subnet,
            "gateway": self.gateway,
            "dns_servers": self.dns_servers,
            "cpu_info": self.cpu_info,
            "memory_info": self.memory_info,
            "disk_info": self.disk_info,
            "open_ports": self.open_ports,
            "vulnerabilities": self.vulnerabilities,
            "uptime": self.uptime,
            "response_time": self.response_time,
            "ai_risk_score": self.ai_risk_score,
            "ai_recommendations": self.ai_recommendations,
            "vendor": self.vendor,
            "model": self.model,
            "serial_number": self.serial_number,
            "location": self.location,
            "notes": self.notes,
        }
        
        # Handle enum values
        if self.device_type:
            result["device_type"] = self.device_type.value
        if self.operating_system:
            result["operating_system"] = self.operating_system.value
        if self.status:
            result["status"] = self.status.value
            
        # Handle datetime values
        if self.last_security_scan:
            result["last_security_scan"] = self.last_security_scan.isoformat()
        if self.last_seen:
            result["last_seen"] = self.last_seen.isoformat()
        if self.first_seen:
            result["first_seen"] = self.first_seen.isoformat()
        if self.created_at:
            result["created_at"] = self.created_at.isoformat()
        if self.updated_at:
            result["updated_at"] = self.updated_at.isoformat()
            
        return result

class NetworkScan(Base):
    __tablename__ = "network_scans"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_type = Column(String(50), nullable=False)  # "full", "quick", "targeted"
    start_time = Column(DateTime, default=func.now())
    end_time = Column(DateTime)
    status = Column(String(20), default="running")  # "running", "completed", "failed"
    devices_found = Column(Integer, default=0)
    scan_config = Column(Text)  # JSON string of scan configuration
    results = Column(Text)  # JSON string of scan results
    errors = Column(Text)  # JSON string of errors encountered
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert scan to dictionary"""
        return {
            "id": self.id,
            "scan_type": self.scan_type,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "status": self.status,
            "devices_found": self.devices_found,
            "scan_config": self.scan_config,
            "results": self.results,
            "errors": self.errors
        }

class SecurityVulnerability(Base):
    __tablename__ = "security_vulnerabilities"
    
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, nullable=False)
    vulnerability_type = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)  # "low", "medium", "high", "critical"
    description = Column(Text, nullable=False)
    cve_id = Column(String(20))  # Common Vulnerabilities and Exposures ID
    affected_component = Column(String(255))
    detection_date = Column(DateTime, default=func.now())
    remediation_status = Column(String(20), default="open")  # "open", "in_progress", "resolved"
    remediation_notes = Column(Text)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert vulnerability to dictionary"""
        return {
            "id": self.id,
            "device_id": self.device_id,
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity,
            "description": self.description,
            "cve_id": self.cve_id,
            "affected_component": self.affected_component,
            "detection_date": self.detection_date.isoformat() if self.detection_date else None,
            "remediation_status": self.remediation_status,
            "remediation_notes": self.remediation_notes
        }

class SystemPatch(Base):
    __tablename__ = "system_patches"
    
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, nullable=False)
    patch_type = Column(String(50), nullable=False)  # "os", "security", "application"
    patch_name = Column(String(255), nullable=False)
    version = Column(String(50))
    description = Column(Text)
    release_date = Column(DateTime)
    installation_date = Column(DateTime)
    status = Column(String(20), default="available")  # "available", "installing", "installed", "failed"
    size = Column(Integer)  # Size in bytes
    source = Column(String(255))  # Where the patch came from
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert patch to dictionary"""
        return {
            "id": self.id,
            "device_id": self.device_id,
            "patch_type": self.patch_type,
            "patch_name": self.patch_name,
            "version": self.version,
            "description": self.description,
            "release_date": self.release_date.isoformat() if self.release_date else None,
            "installation_date": self.installation_date.isoformat() if self.installation_date else None,
            "status": self.status,
            "size": self.size,
            "source": self.source
        } 