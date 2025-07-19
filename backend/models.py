from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, Float, Enum, ForeignKey, Table
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from database import Base
import enum
from datetime import datetime
from typing import Dict, Any
import os
from cryptography.fernet import Fernet
from sqlalchemy.orm.attributes import InstrumentedAttribute

# Create a persistent Fernet key for password encryption
def get_or_create_fernet_key():
    """Get existing Fernet key or create a new one and save it"""
    key_file = os.path.join(os.path.dirname(__file__), 'fernet.key')
    
    # Try to load existing key from environment variable first
    env_key = os.environ.get('FERNET_KEY')
    if env_key:
        return env_key.encode() if isinstance(env_key, str) else env_key
    
    # Try to load existing key from file
    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            return f.read()
    
    # Generate new key and save it
    key = Fernet.generate_key()
    with open(key_file, 'wb') as f:
        f.write(key)
    return key

FERNET_KEY = get_or_create_fernet_key()
fernet = Fernet(FERNET_KEY)

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

class BoundaryType(enum.Enum):
    NETWORK = "network"
    GEOGRAPHIC = "geographic"
    ORGANIZATIONAL = "organizational"
    FUNCTIONAL = "functional"
    SECURITY = "security"

class NamespaceStatus(enum.Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    MAINTENANCE = "maintenance"
    DEPLOYING = "deploying"

class PodStatus(enum.Enum):
    RUNNING = "running"
    STOPPED = "stopped"
    ERROR = "error"
    DEPLOYING = "deploying"
    SCALING = "scaling"

class NodeStatus(enum.Enum):
    READY = "ready"
    NOT_READY = "not_ready"
    MAINTENANCE = "maintenance"
    OFFLINE = "offline"

# Association tables for many-to-many relationships
device_boundary_association = Table(
    'device_boundary_association',
    Base.metadata,
    Column('device_id', Integer, ForeignKey('devices.id')),
    Column('boundary_id', Integer, ForeignKey('virtual_boundaries.id'))
)

boundary_namespace_association = Table(
    'boundary_namespace_association',
    Base.metadata,
    Column('boundary_id', Integer, ForeignKey('virtual_boundaries.id')),
    Column('namespace_id', Integer, ForeignKey('namespaces.id'))
)

class VirtualBoundary(Base):
    __tablename__ = "virtual_boundaries"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, nullable=False)
    description = Column(Text)
    boundary_type = Column(Enum(BoundaryType), default=BoundaryType.NETWORK)
    
    # Network configuration
    network_range = Column(String(18))  # CIDR notation
    gateway = Column(String(15))
    dns_servers = Column(Text)  # JSON string
    
    # Security settings
    isolation_level = Column(String(50), default="standard")  # standard, strict, permissive
    firewall_rules = Column(Text)  # JSON string of firewall rules
    access_policies = Column(Text)  # JSON string of access policies
    
    # Metadata
    tags = Column(Text)  # JSON string of tags
    created_by = Column(String(255))
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    devices = relationship("Device", secondary=device_boundary_association, back_populates="boundaries")
    namespaces = relationship("Namespace", secondary=boundary_namespace_association, back_populates="boundaries")
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "boundary_type": self.boundary_type.value if self.boundary_type else None,
            "network_range": self.network_range,
            "gateway": self.gateway,
            "dns_servers": self.dns_servers,
            "isolation_level": self.isolation_level,
            "firewall_rules": self.firewall_rules,
            "access_policies": self.access_policies,
            "tags": self.tags,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "device_count": len(self.devices) if self.devices else 0,
            "namespace_count": len(self.namespaces) if self.namespaces else 0
        }

class Namespace(Base):
    __tablename__ = "namespaces"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, nullable=False)
    display_name = Column(String(255))
    description = Column(Text)
    status = Column(Enum(NamespaceStatus), default=NamespaceStatus.ACTIVE)
    
    # Resource limits
    cpu_limit = Column(Float, default=0.0)  # CPU cores
    memory_limit = Column(Float, default=0.0)  # Memory in GB
    storage_limit = Column(Float, default=0.0)  # Storage in GB
    
    # Network isolation
    network_policy = Column(Text)  # JSON string of network policies
    ingress_rules = Column(Text)  # JSON string of ingress rules
    egress_rules = Column(Text)  # JSON string of egress rules
    
    # Security
    security_context = Column(Text)  # JSON string of security context
    service_account = Column(String(255))
    
    # Metadata
    labels = Column(Text)  # JSON string of labels
    annotations = Column(Text)  # JSON string of annotations
    created_by = Column(String(255))
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    boundaries = relationship("VirtualBoundary", secondary=boundary_namespace_association, back_populates="namespaces")
    service_pods = relationship("ServicePod", back_populates="namespace")
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "status": self.status.value if self.status else None,
            "cpu_limit": self.cpu_limit,
            "memory_limit": self.memory_limit,
            "storage_limit": self.storage_limit,
            "network_policy": self.network_policy,
            "ingress_rules": self.ingress_rules,
            "egress_rules": self.egress_rules,
            "security_context": self.security_context,
            "service_account": self.service_account,
            "labels": self.labels,
            "annotations": self.annotations,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "pod_count": len(self.service_pods) if self.service_pods else 0
        }

class Node(Base):
    __tablename__ = "nodes"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, nullable=False)
    hostname = Column(String(255))
    ip_address = Column(String(15), unique=True, nullable=False)
    status = Column(Enum(NodeStatus), default=NodeStatus.READY)
    
    # Hardware specifications
    cpu_cores = Column(Integer, default=0)
    cpu_model = Column(String(255))
    memory_gb = Column(Float, default=0.0)
    storage_gb = Column(Float, default=0.0)
    
    # Operating system
    os_type = Column(String(50))
    os_version = Column(String(100))
    kernel_version = Column(String(100))
    
    # Network information
    network_interfaces = Column(Text)  # JSON string of network interfaces
    mac_address = Column(String(17))
    
    # Resource usage
    cpu_usage = Column(Float, default=0.0)
    memory_usage = Column(Float, default=0.0)
    storage_usage = Column(Float, default=0.0)
    
    # Labels and taints
    labels = Column(Text)  # JSON string of labels
    taints = Column(Text)  # JSON string of taints
    
    # Metadata
    location = Column(String(255))
    rack = Column(String(100))
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    service_pods = relationship("ServicePod", back_populates="node")
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "status": self.status.value if self.status else None,
            "cpu_cores": self.cpu_cores,
            "cpu_model": self.cpu_model,
            "memory_gb": self.memory_gb,
            "storage_gb": self.storage_gb,
            "os_type": self.os_type,
            "os_version": self.os_version,
            "kernel_version": self.kernel_version,
            "network_interfaces": self.network_interfaces,
            "mac_address": self.mac_address,
            "cpu_usage": self.cpu_usage,
            "memory_usage": self.memory_usage,
            "storage_usage": self.storage_usage,
            "labels": self.labels,
            "taints": self.taints,
            "location": self.location,
            "rack": self.rack,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "pod_count": len(self.service_pods) if self.service_pods else 0
        }

class ServicePod(Base):
    __tablename__ = "service_pods"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    display_name = Column(String(255))
    description = Column(Text)
    status = Column(Enum(PodStatus), default=PodStatus.STOPPED)
    
    # Container configuration
    image = Column(String(500), nullable=False)
    image_tag = Column(String(100), default="latest")
    container_port = Column(Integer, default=80)
    host_port = Column(Integer)
    
    # Resource requirements
    cpu_request = Column(Float, default=0.1)
    cpu_limit = Column(Float, default=0.5)
    memory_request = Column(Float, default=0.1)  # GB
    memory_limit = Column(Float, default=0.5)  # GB
    
    # Environment variables
    environment_vars = Column(Text)  # JSON string of environment variables
    config_maps = Column(Text)  # JSON string of config maps
    secrets = Column(Text)  # JSON string of secrets
    
    # Networking
    service_type = Column(String(50), default="ClusterIP")  # ClusterIP, NodePort, LoadBalancer
    external_ip = Column(String(15))
    load_balancer_ip = Column(String(15))
    
    # Health checks
    health_check_path = Column(String(255), default="/health")
    health_check_port = Column(Integer)
    readiness_probe = Column(Text)  # JSON string of readiness probe
    liveness_probe = Column(Text)  # JSON string of liveness probe
    
    # Scaling
    replicas = Column(Integer, default=1)
    min_replicas = Column(Integer, default=1)
    max_replicas = Column(Integer, default=10)
    autoscaling_enabled = Column(Boolean, default=False)
    
    # Security
    security_context = Column(Text)  # JSON string of security context
    service_account = Column(String(255))
    
    # Metadata
    labels = Column(Text)  # JSON string of labels
    annotations = Column(Text)  # JSON string of annotations
    created_by = Column(String(255))
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Foreign keys
    namespace_id = Column(Integer, ForeignKey('namespaces.id'))
    node_id = Column(Integer, ForeignKey('nodes.id'))
    
    # Relationships
    namespace = relationship("Namespace", back_populates="service_pods")
    node = relationship("Node", back_populates="service_pods")
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "status": self.status.value if self.status else None,
            "image": self.image,
            "image_tag": self.image_tag,
            "container_port": self.container_port,
            "host_port": self.host_port,
            "cpu_request": self.cpu_request,
            "cpu_limit": self.cpu_limit,
            "memory_request": self.memory_request,
            "memory_limit": self.memory_limit,
            "environment_vars": self.environment_vars,
            "config_maps": self.config_maps,
            "secrets": self.secrets,
            "service_type": self.service_type,
            "external_ip": self.external_ip,
            "load_balancer_ip": self.load_balancer_ip,
            "health_check_path": self.health_check_path,
            "health_check_port": self.health_check_port,
            "readiness_probe": self.readiness_probe,
            "liveness_probe": self.liveness_probe,
            "replicas": self.replicas,
            "min_replicas": self.min_replicas,
            "max_replicas": self.max_replicas,
            "autoscaling_enabled": self.autoscaling_enabled,
            "security_context": self.security_context,
            "service_account": self.service_account,
            "labels": self.labels,
            "annotations": self.annotations,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "namespace_id": self.namespace_id,
            "node_id": self.node_id
        }

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

    # SSH credentials
    ssh_username = Column(String(255))
    ssh_password_enc = Column(String(255))  # Encrypted password
    
    # Management status
    is_managed = Column(Boolean, default=False)  # Whether this device is managed

    # Timestamps
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    boundaries = relationship("VirtualBoundary", secondary=device_boundary_association, back_populates="devices")

    def set_ssh_password(self, password: str):
        self.ssh_password_enc = fernet.encrypt(password.encode()).decode()

    def get_ssh_password(self) -> str:
        if self.ssh_password_enc is not None:
            return fernet.decrypt(self.ssh_password_enc.encode()).decode()
        return ''
    
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
            "ssh_username": self.ssh_username,
            "ssh_password": '********' if self.ssh_password_enc is not None and not isinstance(self.ssh_password_enc, InstrumentedAttribute) and bool(self.ssh_password_enc) else '',
            "is_managed": self.is_managed,
        }
        
        # Handle enum values
        if self.device_type is not None and not isinstance(self.device_type, InstrumentedAttribute):
            result["device_type"] = self.device_type.value
        if self.operating_system is not None and not isinstance(self.operating_system, InstrumentedAttribute):
            result["operating_system"] = self.operating_system.value
        if self.status is not None and not isinstance(self.status, InstrumentedAttribute):
            result["status"] = self.status.value
        
        # Add boundary information
        result["boundaries"] = [boundary.to_dict() for boundary in self.boundaries] if self.boundaries else []
        
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