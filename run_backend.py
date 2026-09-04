#!/usr/bin/env python3
"""
SecureSite Audit Backend Startup Script

This script sets up the Python path correctly and starts the FastAPI backend.
Run from the project root directory:
    python run_backend.py
"""

import os
import sys
import subprocess
from pathlib import Path


def main():
    """Start the backend server"""
    # Get project root directory
    project_root = Path(__file__).parent.absolute()
    backend_dir = project_root / "backend"
    
    # Add project root to Python path so 'backend' module can be found
    sys.path.insert(0, str(project_root))
    
    # Change to backend directory for relative paths (database, .env, etc.)
    os.chdir(backend_dir)
    
    # Also add backend to path for any direct imports
    sys.path.insert(0, str(backend_dir))
    
    print(f"Project root: {project_root}")
    print(f"Backend directory: {backend_dir}")
    print(f"Python path: {sys.path[:3]}...")
    print("-" * 50)
    
    # Check if .env exists
    env_file = project_root / ".env"
    if env_file.exists():
        print(f"Found .env file: {env_file}")
    else:
        print("Warning: .env file not found in project root")
    
    # Run the backend using uvicorn
    try:
        import uvicorn
        from backend.app.config import settings
        
        print(f"Starting {settings.APP_NAME}...")
        print(f"API docs: http://localhost:8000/docs")
        print(f"API base: http://localhost:8000{settings.API_V1_PREFIX}")
        print("-" * 50)
        
        uvicorn.run(
            "backend.app.main:app",
            host="0.0.0.0",
            port=8000,
            reload=settings.DEBUG,
            log_level="info" if settings.DEBUG else "warning",
        )
    except ImportError as e:
        print(f"Import error: {e}")
        print("Installing dependencies...")
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], check=True)
        print("Dependencies installed. Please run again.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
    except Exception as e:
        print(f"Error starting backend: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()