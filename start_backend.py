#!/usr/bin/env python3
"""
Network Admin System - Backend Startup Script
"""

import subprocess
import sys
import os
import time
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def install_dependencies():
    """Install Python dependencies"""
    logger.info("Installing Python dependencies...")
    
    # Try minimal requirements first
    requirements_file = "requirements-minimal.txt"
    if not os.path.exists(requirements_file):
        requirements_file = "requirements.txt"
    
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", requirements_file])
        logger.info("Dependencies installed successfully!")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to install dependencies: {e}")
        logger.info("Trying to install packages individually...")
        
        # Fallback: install core packages individually
        core_packages = [
            "fastapi",
            "uvicorn[standard]",
            "sqlalchemy",
            "pydantic",
            "scapy",
            "python-nmap",
            "psutil",
            "websockets",
            "python-dotenv",
            "aiofiles",
            "httpx",
            "schedule"
        ]
        
        for package in core_packages:
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                logger.info(f"Installed {package}")
            except subprocess.CalledProcessError as e:
                logger.warning(f"Failed to install {package}: {e}")
        
        return True
    return True

def start_backend():
    """Start the FastAPI backend server"""
    logger.info("Starting Network Admin Backend...")
    
    try:
        # Use the simple runner script
        subprocess.run([
            sys.executable, "run_backend.py"
        ])
    except KeyboardInterrupt:
        logger.info("Backend server stopped by user")
    except Exception as e:
        logger.error(f"Error starting backend: {e}")

def main():
    """Main startup function"""
    logger.info("=== Network Admin System - Backend ===")
    
    # Check if we're in the right directory
    if not os.path.exists("requirements.txt"):
        logger.error("requirements.txt not found. Please run this script from the project root.")
        sys.exit(1)
    
    # Install dependencies
    if not install_dependencies():
        sys.exit(1)
    
    # Start backend
    start_backend()

if __name__ == "__main__":
    main() 