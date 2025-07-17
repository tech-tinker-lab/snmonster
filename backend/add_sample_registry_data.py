#!/usr/bin/env python3
"""
Script to add sample registry data for testing the virtual boundaries, namespaces, nodes, and service pods
"""

import asyncio
import sys
import os
import json
from datetime import datetime

# Add the backend directory to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from database import init_db, get_db
from models import (
    VirtualBoundary, Namespace, Node, ServicePod, Device,
    BoundaryType, NamespaceStatus, PodStatus, NodeStatus
)
from registry_manager import RegistryManager

async def add_sample_registry_data():
    """Add sample registry data to the database"""
    try:
        # Initialize database
        await init_db()
        
        # Get database session
        db = get_db()
        registry_manager = RegistryManager()
        
        print("Adding sample registry data...")
        
        # 1. Create Virtual Boundaries
        print("Creating virtual boundaries...")
        boundaries_data = [
            {
                "name": "production-network",
                "description": "Production network boundary for critical services",
                "boundary_type": BoundaryType.NETWORK,
                "network_range": "10.0.0.0/24",
                "gateway": "10.0.0.1",
                "dns_servers": json.dumps(["8.8.8.8", "8.8.4.4"]),
                "isolation_level": "strict",
                "firewall_rules": json.dumps([
                    {"port": 22, "protocol": "tcp", "action": "allow"},
                    {"port": 80, "protocol": "tcp", "action": "allow"},
                    {"port": 443, "protocol": "tcp", "action": "allow"}
                ]),
                "tags": json.dumps(["production", "critical", "high-security"]),
                "created_by": "admin"
            },
            {
                "name": "development-environment",
                "description": "Development environment for testing and development",
                "boundary_type": BoundaryType.FUNCTIONAL,
                "network_range": "10.1.0.0/24",
                "gateway": "10.1.0.1",
                "dns_servers": json.dumps(["8.8.8.8", "8.8.4.4"]),
                "isolation_level": "permissive",
                "firewall_rules": json.dumps([
                    {"port": 22, "protocol": "tcp", "action": "allow"},
                    {"port": 80, "protocol": "tcp", "action": "allow"},
                    {"port": 443, "protocol": "tcp", "action": "allow"},
                    {"port": 3000, "protocol": "tcp", "action": "allow"},
                    {"port": 8080, "protocol": "tcp", "action": "allow"}
                ]),
                "tags": json.dumps(["development", "testing", "devops"]),
                "created_by": "admin"
            },
            {
                "name": "dmz-zone",
                "description": "Demilitarized zone for public-facing services",
                "boundary_type": BoundaryType.SECURITY,
                "network_range": "10.2.0.0/24",
                "gateway": "10.2.0.1",
                "dns_servers": json.dumps(["8.8.8.8", "8.8.4.4"]),
                "isolation_level": "strict",
                "firewall_rules": json.dumps([
                    {"port": 80, "protocol": "tcp", "action": "allow"},
                    {"port": 443, "protocol": "tcp", "action": "allow"},
                    {"port": 25, "protocol": "tcp", "action": "allow"},
                    {"port": 587, "protocol": "tcp", "action": "allow"}
                ]),
                "tags": json.dumps(["dmz", "public", "security"]),
                "created_by": "admin"
            }
        ]
        
        boundaries = []
        for boundary_data in boundaries_data:
            try:
                boundary = await registry_manager.create_virtual_boundary(boundary_data)
                boundaries.append(boundary)
                print(f"Created boundary: {boundary.name}")
            except Exception as e:
                print(f"Error creating boundary {boundary_data['name']}: {e}")
        
        # 2. Create Namespaces
        print("Creating namespaces...")
        namespaces_data = [
            {
                "name": "web-apps",
                "display_name": "Web Applications",
                "description": "Namespace for web application services",
                "status": NamespaceStatus.ACTIVE,
                "cpu_limit": 8.0,
                "memory_limit": 16.0,
                "storage_limit": 100.0,
                "network_policy": json.dumps({
                    "ingress": [{"port": 80}, {"port": 443}],
                    "egress": [{"port": 53}, {"port": 443}]
                }),
                "labels": json.dumps({"environment": "production", "team": "web"}),
                "created_by": "admin"
            },
            {
                "name": "database",
                "display_name": "Database Services",
                "description": "Namespace for database services",
                "status": NamespaceStatus.ACTIVE,
                "cpu_limit": 4.0,
                "memory_limit": 8.0,
                "storage_limit": 500.0,
                "network_policy": json.dumps({
                    "ingress": [{"port": 3306}, {"port": 5432}],
                    "egress": [{"port": 53}]
                }),
                "labels": json.dumps({"environment": "production", "team": "data"}),
                "created_by": "admin"
            },
            {
                "name": "monitoring",
                "display_name": "Monitoring & Logging",
                "description": "Namespace for monitoring and logging services",
                "status": NamespaceStatus.ACTIVE,
                "cpu_limit": 2.0,
                "memory_limit": 4.0,
                "storage_limit": 200.0,
                "network_policy": json.dumps({
                    "ingress": [{"port": 9090}, {"port": 3000}],
                    "egress": [{"port": 53}, {"port": 443}]
                }),
                "labels": json.dumps({"environment": "production", "team": "ops"}),
                "created_by": "admin"
            }
        ]
        
        namespaces = []
        for namespace_data in namespaces_data:
            try:
                namespace = await registry_manager.create_namespace(namespace_data)
                namespaces.append(namespace)
                print(f"Created namespace: {namespace.name}")
            except Exception as e:
                print(f"Error creating namespace {namespace_data['name']}: {e}")
        
        # 3. Create Nodes
        print("Creating nodes...")
        nodes_data = [
            {
                "name": "prod-node-01",
                "hostname": "prod-node-01.company.com",
                "ip_address": "10.0.0.10",
                "status": NodeStatus.READY,
                "cpu_cores": 8,
                "cpu_model": "Intel Xeon E5-2680",
                "memory_gb": 32.0,
                "storage_gb": 1000.0,
                "os_type": "linux",
                "os_version": "Ubuntu 20.04 LTS",
                "kernel_version": "5.4.0-42-generic",
                "network_interfaces": json.dumps([
                    {"name": "eth0", "ip": "10.0.0.10", "mac": "00:11:22:33:44:55"}
                ]),
                "mac_address": "00:11:22:33:44:55",
                "labels": json.dumps({"environment": "production", "zone": "primary"}),
                "location": "Data Center A",
                "rack": "R01"
            },
            {
                "name": "prod-node-02",
                "hostname": "prod-node-02.company.com",
                "ip_address": "10.0.0.11",
                "status": NodeStatus.READY,
                "cpu_cores": 8,
                "cpu_model": "Intel Xeon E5-2680",
                "memory_gb": 32.0,
                "storage_gb": 1000.0,
                "os_type": "linux",
                "os_version": "Ubuntu 20.04 LTS",
                "kernel_version": "5.4.0-42-generic",
                "network_interfaces": json.dumps([
                    {"name": "eth0", "ip": "10.0.0.11", "mac": "00:11:22:33:44:66"}
                ]),
                "mac_address": "00:11:22:33:44:66",
                "labels": json.dumps({"environment": "production", "zone": "secondary"}),
                "location": "Data Center A",
                "rack": "R02"
            },
            {
                "name": "dev-node-01",
                "hostname": "dev-node-01.company.com",
                "ip_address": "10.1.0.10",
                "status": NodeStatus.READY,
                "cpu_cores": 4,
                "cpu_model": "Intel Core i7-8700",
                "memory_gb": 16.0,
                "storage_gb": 500.0,
                "os_type": "linux",
                "os_version": "Ubuntu 18.04 LTS",
                "kernel_version": "4.15.0-112-generic",
                "network_interfaces": json.dumps([
                    {"name": "eth0", "ip": "10.1.0.10", "mac": "00:11:22:33:44:77"}
                ]),
                "mac_address": "00:11:22:33:44:77",
                "labels": json.dumps({"environment": "development", "zone": "dev"}),
                "location": "Development Lab",
                "rack": "DEV-R01"
            }
        ]
        
        nodes = []
        for node_data in nodes_data:
            try:
                node = await registry_manager.create_node(node_data)
                nodes.append(node)
                print(f"Created node: {node.name}")
            except Exception as e:
                print(f"Error creating node {node_data['name']}: {e}")
        
        # 4. Create Service Pods
        print("Creating service pods...")
        pods_data = [
            {
                "name": "web-app-frontend",
                "display_name": "Web App Frontend",
                "description": "Frontend web application",
                "status": PodStatus.RUNNING,
                "image": "nginx:latest",
                "image_tag": "latest",
                "container_port": 80,
                "host_port": 8080,
                "cpu_request": 0.5,
                "cpu_limit": 1.0,
                "memory_request": 0.5,
                "memory_limit": 1.0,
                "environment_vars": json.dumps({
                    "NODE_ENV": "production",
                    "API_URL": "http://api-service:3000"
                }),
                "service_type": "ClusterIP",
                "health_check_path": "/health",
                "health_check_port": 80,
                "replicas": 2,
                "autoscaling_enabled": True,
                "labels": json.dumps({"app": "web-frontend", "tier": "frontend"}),
                "namespace_id": namespaces[0].id if namespaces else None,
                "node_id": nodes[0].id if nodes else None,
                "created_by": "admin"
            },
            {
                "name": "api-service",
                "display_name": "API Service",
                "description": "Backend API service",
                "status": PodStatus.RUNNING,
                "image": "node:16-alpine",
                "image_tag": "16-alpine",
                "container_port": 3000,
                "host_port": 3000,
                "cpu_request": 1.0,
                "cpu_limit": 2.0,
                "memory_request": 1.0,
                "memory_limit": 2.0,
                "environment_vars": json.dumps({
                    "NODE_ENV": "production",
                    "DB_HOST": "mysql-service",
                    "DB_PORT": "3306"
                }),
                "service_type": "ClusterIP",
                "health_check_path": "/api/health",
                "health_check_port": 3000,
                "replicas": 3,
                "autoscaling_enabled": True,
                "labels": json.dumps({"app": "api-service", "tier": "backend"}),
                "namespace_id": namespaces[0].id if namespaces else None,
                "node_id": nodes[1].id if len(nodes) > 1 else (nodes[0].id if nodes else None),
                "created_by": "admin"
            },
            {
                "name": "mysql-database",
                "display_name": "MySQL Database",
                "description": "Primary MySQL database",
                "status": PodStatus.RUNNING,
                "image": "mysql:8.0",
                "image_tag": "8.0",
                "container_port": 3306,
                "host_port": 3306,
                "cpu_request": 2.0,
                "cpu_limit": 4.0,
                "memory_request": 4.0,
                "memory_limit": 8.0,
                "environment_vars": json.dumps({
                    "MYSQL_ROOT_PASSWORD": "secure_password",
                    "MYSQL_DATABASE": "app_db"
                }),
                "service_type": "ClusterIP",
                "health_check_path": "/health",
                "health_check_port": 3306,
                "replicas": 1,
                "autoscaling_enabled": False,
                "labels": json.dumps({"app": "mysql", "tier": "database"}),
                "namespace_id": namespaces[1].id if len(namespaces) > 1 else (namespaces[0].id if namespaces else None),
                "node_id": nodes[0].id if nodes else None,
                "created_by": "admin"
            },
            {
                "name": "prometheus-monitoring",
                "display_name": "Prometheus Monitoring",
                "description": "Prometheus monitoring server",
                "status": PodStatus.RUNNING,
                "image": "prom/prometheus:latest",
                "image_tag": "latest",
                "container_port": 9090,
                "host_port": 9090,
                "cpu_request": 0.5,
                "cpu_limit": 1.0,
                "memory_request": 1.0,
                "memory_limit": 2.0,
                "environment_vars": json.dumps({
                    "PROMETHEUS_CONFIG": "/etc/prometheus/prometheus.yml"
                }),
                "service_type": "ClusterIP",
                "health_check_path": "/-/healthy",
                "health_check_port": 9090,
                "replicas": 1,
                "autoscaling_enabled": False,
                "labels": json.dumps({"app": "prometheus", "tier": "monitoring"}),
                "namespace_id": namespaces[2].id if len(namespaces) > 2 else (namespaces[0].id if namespaces else None),
                "node_id": nodes[0].id if nodes else None,
                "created_by": "admin"
            }
        ]
        
        for pod_data in pods_data:
            try:
                pod = await registry_manager.create_service_pod(pod_data)
                print(f"Created pod: {pod.name}")
            except Exception as e:
                print(f"Error creating pod {pod_data['name']}: {e}")
        
        # 5. Link boundaries and namespaces
        print("Linking boundaries and namespaces...")
        if boundaries and namespaces:
            try:
                # Link production boundary to web-apps and database namespaces
                if len(boundaries) > 0 and len(namespaces) > 1:
                    boundary = boundaries[0]  # production-network
                    namespace1 = namespaces[0]  # web-apps
                    namespace2 = namespaces[1]  # database
                    
                    boundary.namespaces.append(namespace1)
                    boundary.namespaces.append(namespace2)
                    db.commit()
                    print(f"Linked boundary '{boundary.name}' to namespaces '{namespace1.name}' and '{namespace2.name}'")
                
                # Link development boundary to monitoring namespace
                if len(boundaries) > 1 and len(namespaces) > 2:
                    boundary = boundaries[1]  # development-environment
                    namespace = namespaces[2]  # monitoring
                    
                    boundary.namespaces.append(namespace)
                    db.commit()
                    print(f"Linked boundary '{boundary.name}' to namespace '{namespace.name}'")
                    
            except Exception as e:
                print(f"Error linking boundaries and namespaces: {e}")
        
        print(f"Successfully added sample registry data!")
        print(f"Created {len(boundaries)} boundaries, {len(namespaces)} namespaces, {len(nodes)} nodes, and {len(pods_data)} service pods")
        
        # Close database session
        db.close()
        
    except Exception as e:
        print(f"Error adding sample registry data: {e}")
        if 'db' in locals():
            db.rollback()
            db.close()

if __name__ == "__main__":
    asyncio.run(add_sample_registry_data()) 