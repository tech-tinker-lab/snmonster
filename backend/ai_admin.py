import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import asyncio
from backend.database import get_db
from backend.models import Device, SecurityVulnerability, SystemPatch, DeviceStatus

logger = logging.getLogger(__name__)

class AIAdminSystem:
    def __init__(self):
        self.is_ready = True
        self.analysis_cache = {}
        self.cache_duration = timedelta(minutes=5)
        
        # Security risk weights
        self.risk_weights = {
            "open_ports": 0.3,
            "outdated_os": 0.25,
            "no_security_scan": 0.2,
            "unusual_activity": 0.15,
            "vulnerabilities": 0.1
        }
        
        logger.info("AI Admin System initialized")
    
    async def analyze_network(self) -> Dict[str, Any]:
        """Perform comprehensive network analysis"""
        logger.info("Starting AI-powered network analysis...")
        
        try:
            db = get_db()
            devices = db.query(Device).all()
            
            analysis = {
                "timestamp": datetime.now().isoformat(),
                "total_devices": len(devices),
                "device_types": {},
                "operating_systems": {},
                "security_analysis": {},
                "performance_metrics": {},
                "recommendations": []
            }
            
            # Analyze device types
            for device in devices:
                device_type = device.device_type.value if device.device_type else "unknown"
                analysis["device_types"][device_type] = analysis["device_types"].get(device_type, 0) + 1
            
            # Analyze operating systems
            for device in devices:
                os_type = device.operating_system.value if device.operating_system else "unknown"
                analysis["operating_systems"][os_type] = analysis["operating_systems"].get(os_type, 0) + 1
            
            # Security analysis
            security_issues = await self._analyze_security(devices)
            analysis["security_analysis"] = security_issues
            
            # Performance metrics
            performance = await self._analyze_performance(devices)
            analysis["performance_metrics"] = performance
            
            # Generate recommendations
            recommendations = await self._generate_recommendations(analysis)
            analysis["recommendations"] = recommendations
            
            # Cache the analysis
            self.analysis_cache = {
                "data": analysis,
                "timestamp": datetime.now()
            }
            
            logger.info("Network analysis completed successfully")
            return analysis
            
        except Exception as e:
            logger.error(f"Error in network analysis: {e}")
            return {
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    async def _analyze_security(self, devices: List[Device]) -> Dict[str, Any]:
        """Analyze security posture of devices"""
        security_analysis = {
            "high_risk_devices": 0,
            "medium_risk_devices": 0,
            "low_risk_devices": 0,
            "open_ports_analysis": {},
            "vulnerability_summary": {},
            "security_recommendations": []
        }
        
        for device in devices:
            risk_score = await self._calculate_device_risk(device)
            
            if risk_score > 0.7:
                security_analysis["high_risk_devices"] += 1
            elif risk_score > 0.4:
                security_analysis["medium_risk_devices"] += 1
            else:
                security_analysis["low_risk_devices"] += 1
            
            # Analyze open ports
            if device.open_ports:
                try:
                    open_ports = json.loads(device.open_ports)
                    for port in open_ports:
                        port_name = self._get_port_name(port)
                        security_analysis["open_ports_analysis"][port_name] = \
                            security_analysis["open_ports_analysis"].get(port_name, 0) + 1
                except json.JSONDecodeError:
                    pass
        
        return security_analysis
    
    async def _analyze_performance(self, devices: List[Device]) -> Dict[str, Any]:
        """Analyze performance metrics"""
        performance = {
            "online_devices": 0,
            "offline_devices": 0,
            "average_response_time": 0,
            "device_uptime_stats": {},
            "performance_issues": []
        }
        
        total_response_time = 0
        response_count = 0
        
        for device in devices:
            if device.status == DeviceStatus.ONLINE:
                performance["online_devices"] += 1
            else:
                performance["offline_devices"] += 1
            
            if device.response_time:
                total_response_time += device.response_time
                response_count += 1
            
            if device.uptime:
                uptime_hours = device.uptime / 3600
                if uptime_hours < 24:
                    performance["performance_issues"].append({
                        "device": device.ip_address,
                        "issue": "Low uptime",
                        "value": f"{uptime_hours:.1f} hours"
                    })
        
        if response_count > 0:
            performance["average_response_time"] = total_response_time / response_count
        
        return performance
    
    async def _calculate_device_risk(self, device: Device) -> float:
        """Calculate risk score for a device"""
        risk_score = 0.0
        
        # Check for open ports
        if device.open_ports:
            try:
                open_ports = json.loads(device.open_ports)
                risky_ports = [21, 23, 3389, 22]  # FTP, Telnet, RDP, SSH
                for port in open_ports:
                    if port in risky_ports:
                        risk_score += self.risk_weights["open_ports"]
                        break
            except json.JSONDecodeError:
                pass
        
        # Check for outdated OS
        if device.operating_system:
            os_age = await self._get_os_age(device.operating_system.value)
            if os_age > 5:  # More than 5 years old
                risk_score += self.risk_weights["outdated_os"]
        
        # Check for security scan
        if not device.last_security_scan:
            risk_score += self.risk_weights["no_security_scan"]
        else:
            days_since_scan = (datetime.now() - device.last_security_scan).days
            if days_since_scan > 30:
                risk_score += self.risk_weights["no_security_scan"] * 0.5
        
        # Check for vulnerabilities
        if device.vulnerabilities:
            try:
                vulns = json.loads(device.vulnerabilities)
                if len(vulns) > 0:
                    risk_score += self.risk_weights["vulnerabilities"]
            except json.JSONDecodeError:
                pass
        
        return min(risk_score, 1.0)
    
    async def _get_os_age(self, os_name: str) -> int:
        """Get approximate age of operating system in years"""
        os_release_dates = {
            "windows": {
                "10": 2015,
                "11": 2021,
                "8.1": 2013,
                "8": 2012,
                "7": 2009
            },
            "linux": {
                "ubuntu": 2004,
                "centos": 2004,
                "debian": 1993
            },
            "macos": {
                "monterey": 2021,
                "big_sur": 2020,
                "catalina": 2019
            }
        }
        
        # This is a simplified version - in practice, you'd parse actual OS versions
        return 3  # Default to 3 years
    
    def _get_port_name(self, port: int) -> str:
        """Get service name for port number"""
        port_names = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            993: "IMAPS",
            995: "POP3S",
            3389: "RDP",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt"
        }
        return port_names.get(port, f"Port-{port}")
    
    async def _generate_recommendations(self, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate AI-powered recommendations"""
        recommendations = []
        
        # Security recommendations
        if analysis["security_analysis"]["high_risk_devices"] > 0:
            recommendations.append({
                "type": "security",
                "priority": "high",
                "title": "High-risk devices detected",
                "description": f"Found {analysis['security_analysis']['high_risk_devices']} high-risk devices. Review and secure these devices immediately.",
                "action": "Review device security configurations and apply necessary patches."
            })
        
        # OS diversity recommendations
        os_count = len(analysis["operating_systems"])
        if os_count > 3:
            recommendations.append({
                "type": "management",
                "priority": "medium",
                "title": "High OS diversity",
                "description": f"Network has {os_count} different operating systems, which may increase management complexity.",
                "action": "Consider standardizing on fewer OS platforms for easier management."
            })
        
        # Performance recommendations
        if analysis["performance_metrics"]["offline_devices"] > 0:
            recommendations.append({
                "type": "performance",
                "priority": "medium",
                "title": "Offline devices detected",
                "description": f"Found {analysis['performance_metrics']['offline_devices']} offline devices.",
                "action": "Investigate why devices are offline and ensure proper monitoring."
            })
        
        # Patch management recommendations
        if analysis["security_analysis"]["medium_risk_devices"] > 0:
            recommendations.append({
                "type": "maintenance",
                "priority": "medium",
                "title": "Patch management needed",
                "description": "Several devices may need security updates.",
                "action": "Implement automated patch management and schedule regular updates."
            })
        
        return recommendations
    
    async def get_recommendations(self) -> Dict[str, Any]:
        """Get AI-powered recommendations for network improvements"""
        logger.info("Generating AI recommendations...")
        
        try:
            # Use cached analysis if available and recent
            if (self.analysis_cache and 
                datetime.now() - self.analysis_cache["timestamp"] < self.cache_duration):
                analysis = self.analysis_cache["data"]
            else:
                analysis = await self.analyze_network()
            
            recommendations = {
                "timestamp": datetime.now().isoformat(),
                "network_health_score": await self._calculate_network_health(analysis),
                "recommendations": analysis.get("recommendations", []),
                "priority_actions": await self._get_priority_actions(analysis),
                "long_term_strategy": await self._get_long_term_strategy(analysis)
            }
            
            return recommendations
            
        except Exception as e:
            logger.error(f"Error generating recommendations: {e}")
            return {
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    async def _calculate_network_health(self, analysis: Dict[str, Any]) -> float:
        """Calculate overall network health score (0-100)"""
        score = 100.0
        
        # Deduct points for security issues
        high_risk = analysis["security_analysis"]["high_risk_devices"]
        medium_risk = analysis["security_analysis"]["medium_risk_devices"]
        total_devices = analysis["total_devices"]
        
        if total_devices > 0:
            risk_percentage = (high_risk * 2 + medium_risk) / total_devices
            score -= risk_percentage * 50
        
        # Deduct points for offline devices
        offline_percentage = analysis["performance_metrics"]["offline_devices"] / total_devices
        score -= offline_percentage * 30
        
        return max(score, 0.0)
    
    async def _get_priority_actions(self, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get immediate priority actions"""
        actions = []
        
        # Immediate security actions
        if analysis["security_analysis"]["high_risk_devices"] > 0:
            actions.append({
                "action": "Secure high-risk devices",
                "urgency": "immediate",
                "estimated_time": "2-4 hours",
                "resources_needed": ["Security team", "Device access"]
            })
        
        # Network monitoring
        actions.append({
            "action": "Implement continuous monitoring",
            "urgency": "high",
            "estimated_time": "1-2 days",
            "resources_needed": ["Monitoring tools", "IT staff"]
        })
        
        return actions
    
    async def _get_long_term_strategy(self, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get long-term strategic recommendations"""
        strategy = []
        
        # Security hardening
        strategy.append({
            "goal": "Implement zero-trust security model",
            "timeline": "3-6 months",
            "benefits": ["Improved security", "Better access control", "Reduced attack surface"]
        })
        
        # Automation
        strategy.append({
            "goal": "Automate patch management and monitoring",
            "timeline": "2-4 months",
            "benefits": ["Reduced manual work", "Faster response times", "Consistent updates"]
        })
        
        return strategy 