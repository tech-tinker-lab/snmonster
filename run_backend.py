#!/usr/bin/env python3
"""
Simple backend runner for Network Admin System
"""

import sys
import os

# Add the backend directory to Python path
backend_dir = os.path.join(os.path.dirname(__file__), 'backend')
sys.path.insert(0, backend_dir)

# Change to backend directory
os.chdir(backend_dir)

# Import and run the FastAPI app
from main import app
import uvicorn

if __name__ == "__main__":
    print("Starting Network Admin Backend...")
    print("Backend will be available at: http://localhost:8001")
    print("API docs will be available at: http://localhost:8001/docs")
    print("Press Ctrl+C to stop the server")
    print()
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8001,
        reload=True,
        log_level="info"
    ) 