import os
from typing import Optional

class Config:
    """Application configuration"""
    
    # Network Configuration
    NETWORK_RANGE = os.environ.get('NETWORK_RANGE', None)  # e.g., "192.168.1.0/24"
    SCAN_INTERVAL = int(os.environ.get('SCAN_INTERVAL', 300))  # seconds
    
    # Database Configuration
    DATABASE_URL = os.environ.get('DATABASE_URL', "sqlite:///./network_admin.db")
    
    # API Configuration
    API_HOST = os.environ.get('API_HOST', "0.0.0.0")
    API_PORT = int(os.environ.get('API_PORT', 8001))  # Changed to 8001
    
    # Security Configuration
    CORS_ORIGINS = [
        "http://localhost:3000",
        "http://localhost:3001", 
        "http://127.0.0.1:3000",
        "http://127.0.0.1:3001",
        "http://localhost:3002",
        "http://127.0.0.1:3002"
    ]
    
    # Logging Configuration
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.environ.get('LOG_FILE', 'network_admin.log')
    
    @classmethod
    def get_network_range(cls) -> Optional[str]:
        """Get the configured network range"""
        return cls.NETWORK_RANGE
    
    @classmethod
    def set_network_range(cls, network_range: str):
        """Set the network range"""
        cls.NETWORK_RANGE = network_range
        os.environ['NETWORK_RANGE'] = network_range 