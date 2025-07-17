import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from database import get_db
from models import (
    VirtualBoundary, Namespace, Node, ServicePod, Device,
    BoundaryType, NamespaceStatus, PodStatus, NodeStatus
)

logger = logging.getLogger(__name__)

class RegistryManager:
    """Manages virtual boundaries, namespaces, nodes, and service pods"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    # Virtual Boundary Management
    async def create_virtual_boundary(self, boundary_data: Dict[str, Any]) -> VirtualBoundary:
        """Create a new virtual boundary"""
        try:
            db = get_db()
            
            # Validate required fields
            if not boundary_data.get('name'):
                raise ValueError("Boundary name is required")
            
            # Check if boundary already exists
            existing = db.query(VirtualBoundary).filter(
                VirtualBoundary.name == boundary_data['name']
            ).first()
            if existing:
                raise ValueError(f"Boundary with name '{boundary_data['name']}' already exists")
            
            # Create new boundary
            boundary = VirtualBoundary(**boundary_data)
            db.add(boundary)
            db.commit()
            db.refresh(boundary)
            
            self.logger.info(f"Created virtual boundary: {boundary.name}")
            return boundary
            
        except Exception as e:
            self.logger.error(f"Error creating virtual boundary: {e}")
            if 'db' in locals():
                db.rollback()
            raise
    
    async def get_virtual_boundaries(self) -> List[Dict[str, Any]]:
        """Get all virtual boundaries"""
        try:
            db = get_db()
            boundaries = db.query(VirtualBoundary).all()
            return [boundary.to_dict() for boundary in boundaries]
        except Exception as e:
            self.logger.error(f"Error fetching virtual boundaries: {e}")
            raise
    
    async def get_virtual_boundary(self, boundary_id: int) -> Optional[Dict[str, Any]]:
        """Get a specific virtual boundary"""
        try:
            db = get_db()
            boundary = db.query(VirtualBoundary).filter(
                VirtualBoundary.id == boundary_id
            ).first()
            return boundary.to_dict() if boundary else None
        except Exception as e:
            self.logger.error(f"Error fetching virtual boundary {boundary_id}: {e}")
            raise
    
    async def update_virtual_boundary(self, boundary_id: int, boundary_data: Dict[str, Any]) -> VirtualBoundary:
        """Update a virtual boundary"""
        try:
            db = get_db()
            boundary = db.query(VirtualBoundary).filter(
                VirtualBoundary.id == boundary_id
            ).first()
            
            if not boundary:
                raise ValueError(f"Boundary with id {boundary_id} not found")
            
            # Update fields
            for key, value in boundary_data.items():
                if hasattr(boundary, key):
                    setattr(boundary, key, value)
            
            boundary.updated_at = datetime.now()
            db.commit()
            db.refresh(boundary)
            
            self.logger.info(f"Updated virtual boundary: {boundary.name}")
            return boundary
            
        except Exception as e:
            self.logger.error(f"Error updating virtual boundary {boundary_id}: {e}")
            if 'db' in locals():
                db.rollback()
            raise
    
    async def delete_virtual_boundary(self, boundary_id: int) -> bool:
        """Delete a virtual boundary"""
        try:
            db = get_db()
            boundary = db.query(VirtualBoundary).filter(
                VirtualBoundary.id == boundary_id
            ).first()
            
            if not boundary:
                raise ValueError(f"Boundary with id {boundary_id} not found")
            
            db.delete(boundary)
            db.commit()
            
            self.logger.info(f"Deleted virtual boundary: {boundary.name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error deleting virtual boundary {boundary_id}: {e}")
            if 'db' in locals():
                db.rollback()
            raise
    
    async def add_device_to_boundary(self, boundary_id: int, device_id: int) -> bool:
        """Add a device to a virtual boundary"""
        try:
            db = get_db()
            boundary = db.query(VirtualBoundary).filter(
                VirtualBoundary.id == boundary_id
            ).first()
            device = db.query(Device).filter(Device.id == device_id).first()
            
            if not boundary:
                raise ValueError(f"Boundary with id {boundary_id} not found")
            if not device:
                raise ValueError(f"Device with id {device_id} not found")
            
            if device not in boundary.devices:
                boundary.devices.append(device)
                db.commit()
                self.logger.info(f"Added device {device.ip_address} to boundary {boundary.name}")
                return True
            else:
                self.logger.warning(f"Device {device.ip_address} already in boundary {boundary.name}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error adding device to boundary: {e}")
            if 'db' in locals():
                db.rollback()
            raise
    
    # Namespace Management
    async def create_namespace(self, namespace_data: Dict[str, Any]) -> Namespace:
        """Create a new namespace"""
        try:
            db = get_db()
            
            if not namespace_data.get('name'):
                raise ValueError("Namespace name is required")
            
            # Check if namespace already exists
            existing = db.query(Namespace).filter(
                Namespace.name == namespace_data['name']
            ).first()
            if existing:
                raise ValueError(f"Namespace with name '{namespace_data['name']}' already exists")
            
            namespace = Namespace(**namespace_data)
            db.add(namespace)
            db.commit()
            db.refresh(namespace)
            
            self.logger.info(f"Created namespace: {namespace.name}")
            return namespace
            
        except Exception as e:
            self.logger.error(f"Error creating namespace: {e}")
            if 'db' in locals():
                db.rollback()
            raise
    
    async def get_namespaces(self) -> List[Dict[str, Any]]:
        """Get all namespaces"""
        try:
            db = get_db()
            namespaces = db.query(Namespace).all()
            return [namespace.to_dict() for namespace in namespaces]
        except Exception as e:
            self.logger.error(f"Error fetching namespaces: {e}")
            raise
    
    async def get_namespace(self, namespace_id: int) -> Optional[Dict[str, Any]]:
        """Get a specific namespace"""
        try:
            db = get_db()
            namespace = db.query(Namespace).filter(
                Namespace.id == namespace_id
            ).first()
            return namespace.to_dict() if namespace else None
        except Exception as e:
            self.logger.error(f"Error fetching namespace {namespace_id}: {e}")
            raise
    
    async def update_namespace(self, namespace_id: int, namespace_data: Dict[str, Any]) -> Namespace:
        """Update a namespace"""
        try:
            db = get_db()
            namespace = db.query(Namespace).filter(
                Namespace.id == namespace_id
            ).first()
            
            if not namespace:
                raise ValueError(f"Namespace with id {namespace_id} not found")
            
            for key, value in namespace_data.items():
                if hasattr(namespace, key):
                    setattr(namespace, key, value)
            
            namespace.updated_at = datetime.now()
            db.commit()
            db.refresh(namespace)
            
            self.logger.info(f"Updated namespace: {namespace.name}")
            return namespace
            
        except Exception as e:
            self.logger.error(f"Error updating namespace {namespace_id}: {e}")
            if 'db' in locals():
                db.rollback()
            raise
    
    async def delete_namespace(self, namespace_id: int) -> bool:
        """Delete a namespace"""
        try:
            db = get_db()
            namespace = db.query(Namespace).filter(
                Namespace.id == namespace_id
            ).first()
            
            if not namespace:
                raise ValueError(f"Namespace with id {namespace_id} not found")
            
            # Check if namespace has pods
            if namespace.service_pods:
                raise ValueError(f"Cannot delete namespace with {len(namespace.service_pods)} active pods")
            
            db.delete(namespace)
            db.commit()
            
            self.logger.info(f"Deleted namespace: {namespace.name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error deleting namespace {namespace_id}: {e}")
            if 'db' in locals():
                db.rollback()
            raise
    
    # Node Management
    async def create_node(self, node_data: Dict[str, Any]) -> Node:
        """Create a new node"""
        try:
            db = get_db()
            
            if not node_data.get('name') or not node_data.get('ip_address'):
                raise ValueError("Node name and IP address are required")
            
            # Check if node already exists
            existing = db.query(Node).filter(
                (Node.name == node_data['name']) | (Node.ip_address == node_data['ip_address'])
            ).first()
            if existing:
                raise ValueError(f"Node with name '{node_data['name']}' or IP '{node_data['ip_address']}' already exists")
            
            node = Node(**node_data)
            db.add(node)
            db.commit()
            db.refresh(node)
            
            self.logger.info(f"Created node: {node.name}")
            return node
            
        except Exception as e:
            self.logger.error(f"Error creating node: {e}")
            if 'db' in locals():
                db.rollback()
            raise
    
    async def get_nodes(self) -> List[Dict[str, Any]]:
        """Get all nodes"""
        try:
            db = get_db()
            nodes = db.query(Node).all()
            return [node.to_dict() for node in nodes]
        except Exception as e:
            self.logger.error(f"Error fetching nodes: {e}")
            raise
    
    async def get_node(self, node_id: int) -> Optional[Dict[str, Any]]:
        """Get a specific node"""
        try:
            db = get_db()
            node = db.query(Node).filter(Node.id == node_id).first()
            return node.to_dict() if node else None
        except Exception as e:
            self.logger.error(f"Error fetching node {node_id}: {e}")
            raise
    
    async def update_node_status(self, node_id: int, status: NodeStatus) -> Node:
        """Update node status"""
        try:
            db = get_db()
            node = db.query(Node).filter(Node.id == node_id).first()
            
            if not node:
                raise ValueError(f"Node with id {node_id} not found")
            
            node.status = status
            node.updated_at = datetime.now()
            db.commit()
            db.refresh(node)
            
            self.logger.info(f"Updated node {node.name} status to {status.value}")
            return node
            
        except Exception as e:
            self.logger.error(f"Error updating node status {node_id}: {e}")
            if 'db' in locals():
                db.rollback()
            raise
    
    # Service Pod Management
    async def create_service_pod(self, pod_data: Dict[str, Any]) -> ServicePod:
        """Create a new service pod"""
        try:
            db = get_db()
            
            if not pod_data.get('name') or not pod_data.get('image'):
                raise ValueError("Pod name and image are required")
            
            # Validate namespace exists
            if pod_data.get('namespace_id'):
                namespace = db.query(Namespace).filter(
                    Namespace.id == pod_data['namespace_id']
                ).first()
                if not namespace:
                    raise ValueError(f"Namespace with id {pod_data['namespace_id']} not found")
            
            # Validate node exists if specified
            if pod_data.get('node_id'):
                node = db.query(Node).filter(Node.id == pod_data['node_id']).first()
                if not node:
                    raise ValueError(f"Node with id {pod_data['node_id']} not found")
            
            pod = ServicePod(**pod_data)
            db.add(pod)
            db.commit()
            db.refresh(pod)
            
            self.logger.info(f"Created service pod: {pod.name}")
            return pod
            
        except Exception as e:
            self.logger.error(f"Error creating service pod: {e}")
            if 'db' in locals():
                db.rollback()
            raise
    
    async def get_service_pods(self, namespace_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get all service pods, optionally filtered by namespace"""
        try:
            db = get_db()
            query = db.query(ServicePod)
            
            if namespace_id:
                query = query.filter(ServicePod.namespace_id == namespace_id)
            
            pods = query.all()
            return [pod.to_dict() for pod in pods]
        except Exception as e:
            self.logger.error(f"Error fetching service pods: {e}")
            raise
    
    async def get_service_pod(self, pod_id: int) -> Optional[Dict[str, Any]]:
        """Get a specific service pod"""
        try:
            db = get_db()
            pod = db.query(ServicePod).filter(ServicePod.id == pod_id).first()
            return pod.to_dict() if pod else None
        except Exception as e:
            self.logger.error(f"Error fetching service pod {pod_id}: {e}")
            raise
    
    async def update_pod_status(self, pod_id: int, status: PodStatus) -> ServicePod:
        """Update pod status"""
        try:
            db = get_db()
            pod = db.query(ServicePod).filter(ServicePod.id == pod_id).first()
            
            if not pod:
                raise ValueError(f"Pod with id {pod_id} not found")
            
            pod.status = status
            pod.updated_at = datetime.now()
            db.commit()
            db.refresh(pod)
            
            self.logger.info(f"Updated pod {pod.name} status to {status.value}")
            return pod
            
        except Exception as e:
            self.logger.error(f"Error updating pod status {pod_id}: {e}")
            if 'db' in locals():
                db.rollback()
            raise
    
    async def delete_service_pod(self, pod_id: int) -> bool:
        """Delete a service pod"""
        try:
            db = get_db()
            pod = db.query(ServicePod).filter(ServicePod.id == pod_id).first()
            
            if not pod:
                raise ValueError(f"Pod with id {pod_id} not found")
            
            db.delete(pod)
            db.commit()
            
            self.logger.info(f"Deleted service pod: {pod.name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error deleting service pod {pod_id}: {e}")
            if 'db' in locals():
                db.rollback()
            raise
    
    # Advanced Registry Operations
    async def get_boundary_summary(self, boundary_id: int) -> Dict[str, Any]:
        """Get comprehensive summary of a virtual boundary"""
        try:
            db = get_db()
            boundary = db.query(VirtualBoundary).filter(
                VirtualBoundary.id == boundary_id
            ).first()
            
            if not boundary:
                raise ValueError(f"Boundary with id {boundary_id} not found")
            
            summary = boundary.to_dict()
            summary['devices'] = [device.to_dict() for device in boundary.devices]
            summary['namespaces'] = [ns.to_dict() for ns in boundary.namespaces]
            
            # Count pods in namespaces
            total_pods = sum(len(ns.service_pods) for ns in boundary.namespaces)
            summary['total_pods'] = total_pods
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Error getting boundary summary {boundary_id}: {e}")
            raise
    
    async def get_namespace_summary(self, namespace_id: int) -> Dict[str, Any]:
        """Get comprehensive summary of a namespace"""
        try:
            db = get_db()
            namespace = db.query(Namespace).filter(
                Namespace.id == namespace_id
            ).first()
            
            if not namespace:
                raise ValueError(f"Namespace with id {namespace_id} not found")
            
            summary = namespace.to_dict()
            summary['pods'] = [pod.to_dict() for pod in namespace.service_pods]
            summary['boundaries'] = [boundary.to_dict() for boundary in namespace.boundaries]
            
            # Calculate resource usage
            total_cpu_request = sum(pod.cpu_request for pod in namespace.service_pods)
            total_memory_request = sum(pod.memory_request for pod in namespace.service_pods)
            
            summary['resource_usage'] = {
                'cpu_requested': total_cpu_request,
                'memory_requested_gb': total_memory_request,
                'cpu_utilization': (total_cpu_request / namespace.cpu_limit * 100) if namespace.cpu_limit > 0 else 0,
                'memory_utilization': (total_memory_request / namespace.memory_limit * 100) if namespace.memory_limit > 0 else 0
            }
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Error getting namespace summary {namespace_id}: {e}")
            raise
    
    async def get_node_summary(self, node_id: int) -> Dict[str, Any]:
        """Get comprehensive summary of a node"""
        try:
            db = get_db()
            node = db.query(Node).filter(Node.id == node_id).first()
            
            if not node:
                raise ValueError(f"Node with id {node_id} not found")
            
            summary = node.to_dict()
            summary['pods'] = [pod.to_dict() for pod in node.service_pods]
            
            # Calculate resource usage
            total_cpu_request = sum(pod.cpu_request for pod in node.service_pods)
            total_memory_request = sum(pod.memory_request for pod in node.service_pods)
            
            summary['resource_usage'] = {
                'cpu_requested': total_cpu_request,
                'memory_requested_gb': total_memory_request,
                'cpu_available': node.cpu_cores - total_cpu_request,
                'memory_available_gb': node.memory_gb - total_memory_request,
                'cpu_utilization': (total_cpu_request / node.cpu_cores * 100) if node.cpu_cores > 0 else 0,
                'memory_utilization': (total_memory_request / node.memory_gb * 100) if node.memory_gb > 0 else 0
            }
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Error getting node summary {node_id}: {e}")
            raise 