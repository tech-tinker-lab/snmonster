#!/usr/bin/env python3
"""
Network Admin System - Full Stack Startup Script
Handles both backend and frontend startup with proper sequencing
"""

import subprocess
import sys
import os
import time
import threading
import signal
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class NetworkAdminSystem:
    def __init__(self):
        self.backend_process = None
        self.frontend_process = None
        self.running = True
        self.python_exe = None  # Store the selected Python interpreter
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def find_python_interpreter(self):
        """Find the best Python interpreter with pip available"""
        if self.python_exe:
            return self.python_exe
        
        python_interpreters = [
            r"C:\projects\snmonster\dev_env\Scripts\python.exe",  # dev_env (preferred)
            sys.executable,  # Current Python
            "python",  # System Python
        ]
        
        for interpreter in python_interpreters:
            try:
                # Test if this Python has pip
                result = subprocess.run([interpreter, "-m", "pip", "--version"], 
                                      capture_output=True, check=True)
                self.python_exe = interpreter
                logger.info(f"✓ Using Python interpreter: {self.python_exe}")
                return self.python_exe
            except (subprocess.CalledProcessError, FileNotFoundError):
                continue
        
        logger.error("✗ No Python interpreter with pip found")
        return None
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        logger.info("Shutdown signal received. Stopping services...")
        self.stop_all()
        sys.exit(0)
    
    def check_dependencies(self):
        """Check if required dependencies are installed"""
        logger.info("Checking dependencies...")
        
        # Check Python
        try:
            subprocess.run([sys.executable, "--version"], check=True, capture_output=True)
            logger.info("✓ Python found")
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.error("✗ Python not found. Please install Python 3.8+")
            return False
        
        # Check Node.js
        try:
            subprocess.run(["node", "--version"], check=True, capture_output=True)
            logger.info("✓ Node.js found")
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.error("✗ Node.js not found. Please install Node.js 16+")
            return False
        
        # Check npm
        try:
            # Try npm.cmd first (Windows), then npm
            npm_command = "npm.cmd" if os.name == 'nt' else "npm"
            subprocess.run([npm_command, "--version"], check=True, capture_output=True)
            logger.info("✓ npm found")
        except (subprocess.CalledProcessError, FileNotFoundError):
            try:
                # Fallback to npm if npm.cmd fails
                subprocess.run(["npm", "--version"], check=True, capture_output=True)
                logger.info("✓ npm found")
            except (subprocess.CalledProcessError, FileNotFoundError):
                logger.error("✗ npm not found. Please install npm")
                return False
        
        return True
    
    def install_backend_dependencies(self):
        """Install Python backend dependencies"""
        logger.info("Installing backend dependencies...")
        
        python_exe = self.find_python_interpreter()
        if not python_exe:
            return False
        
        try:
            # Try minimal requirements first
            if os.path.exists("requirements-minimal.txt"):
                subprocess.run([python_exe, "-m", "pip", "install", "-r", "requirements-minimal.txt"], check=True)
                logger.info("✓ Backend dependencies installed")
                return True
            elif os.path.exists("requirements.txt"):
                subprocess.run([python_exe, "-m", "pip", "install", "-r", "requirements.txt"], check=True)
                logger.info("✓ Backend dependencies installed")
                return True
            else:
                logger.error("✗ No requirements file found")
                return False
        except subprocess.CalledProcessError as e:
            logger.error(f"✗ Failed to install backend dependencies: {e}")
            return False
    
    def install_frontend_dependencies(self):
        """Install Node.js frontend dependencies"""
        logger.info("Installing frontend dependencies...")
        
        frontend_dir = Path("frontend")
        if not frontend_dir.exists():
            logger.error("✗ Frontend directory not found")
            return False
        
        try:
            # Use npm.cmd on Windows, npm on other systems
            npm_command = "npm.cmd" if os.name == 'nt' else "npm"
            subprocess.run([npm_command, "install"], cwd=frontend_dir, check=True)
            logger.info("✓ Frontend dependencies installed")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"✗ Failed to install frontend dependencies: {e}")
            return False
    
    def build_frontend(self):
        """Build the React frontend"""
        logger.info("Building frontend...")
        
        frontend_dir = Path("frontend")
        if not frontend_dir.exists():
            logger.error("✗ Frontend directory not found")
            return False
        
        try:
            # Use npm.cmd on Windows, npm on other systems
            npm_command = "npm.cmd" if os.name == 'nt' else "npm"
            subprocess.run([npm_command, "run", "build"], cwd=frontend_dir, check=True)
            logger.info("✓ Frontend built successfully")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"✗ Failed to build frontend: {e}")
            return False
    
    def start_backend(self):
        """Start the backend server"""
        logger.info("Starting backend server...")
        
        python_exe = self.find_python_interpreter()
        if not python_exe:
            python_exe = sys.executable  # Fallback
        
        try:
            # Use the selected Python interpreter
            self.backend_process = subprocess.Popen([
                python_exe, "run_backend.py"
            ])
            
            # Wait a moment for backend to start
            time.sleep(3)
            
            if self.backend_process.poll() is None:
                logger.info("✓ Backend server started on http://localhost:8001")
                return True
            else:
                logger.error("✗ Backend server failed to start")
                return False
        except Exception as e:
            logger.error(f"✗ Error starting backend: {e}")
            return False
    
    def start_frontend_dev(self):
        """Start frontend in development mode"""
        logger.info("Starting frontend in development mode...")
        
        frontend_dir = Path("frontend")
        if not frontend_dir.exists():
            logger.error("✗ Frontend directory not found")
            return False
        
        try:
            # Use npm.cmd on Windows, npm on other systems
            npm_command = "npm.cmd" if os.name == 'nt' else "npm"
            self.frontend_process = subprocess.Popen([
                npm_command, "start"
            ], cwd=frontend_dir)
            
            # Wait a moment for frontend to start
            time.sleep(5)
            
            if self.frontend_process.poll() is None:
                logger.info("✓ Frontend started on http://localhost:3001")
                return True
            else:
                logger.error("✗ Frontend failed to start")
                return False
        except Exception as e:
            logger.error(f"✗ Error starting frontend: {e}")
            return False
    
    def stop_all(self):
        """Stop all running processes"""
        logger.info("Stopping all services...")
        
        if self.backend_process:
            self.backend_process.terminate()
            logger.info("Backend stopped")
        
        if self.frontend_process:
            self.frontend_process.terminate()
            logger.info("Frontend stopped")
    
    def run(self):
        """Main run method"""
        logger.info("=== Network Admin System - Full Stack Startup ===")
        
        # Check dependencies
        if not self.check_dependencies():
            return False
        
        # Install dependencies
        if not self.install_backend_dependencies():
            return False
        
        if not self.install_frontend_dependencies():
            return False
        
        # Start backend
        if not self.start_backend():
            return False
        
        # Start frontend
        if not self.start_frontend_dev():
            self.stop_all()
            return False
        
        logger.info("")
        logger.info("🎉 Network Admin System is running!")
        logger.info("")
        logger.info("📱 Frontend: http://localhost:3001")
        logger.info("🔧 Backend API: http://localhost:8001")
        logger.info("📚 API Docs: http://localhost:8001/docs")
        logger.info("")
        logger.info("Press Ctrl+C to stop all services")
        logger.info("")
        
        # Keep running until interrupted
        try:
            while self.running:
                time.sleep(1)
                
                # Check if processes are still running
                if self.backend_process and self.backend_process.poll() is not None:
                    logger.error("Backend process stopped unexpectedly")
                    break
                
                if self.frontend_process and self.frontend_process.poll() is not None:
                    logger.error("Frontend process stopped unexpectedly")
                    break
                    
        except KeyboardInterrupt:
            logger.info("Shutdown requested by user")
        finally:
            self.stop_all()
        
        return True

def main():
    """Main entry point"""
    system = NetworkAdminSystem()
    success = system.run()
    
    if success:
        logger.info("Network Admin System stopped successfully")
    else:
        logger.error("Network Admin System failed to start")
        sys.exit(1)

if __name__ == "__main__":
    main() 