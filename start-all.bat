@echo off
REM SecureSite Audit Platform - Startup Script
REM Run this to start all services

echo ============================================
echo SecureSite Audit Platform - Starting Services
echo ============================================

REM Check if we're in the right directory
if not exist "backend" (
    echo ERROR: Please run this from the Securesite-Audit root directory
    pause
    exit /b 1
)

echo.
echo [1/4] Starting Backend API (Port 8012)...
start "SecureSite Backend" cmd /k "cd backend && python -m uvicorn app.main:app --port 8012 --reload"

echo.
echo [2/4] Waiting for backend to start...
timeout /t 10 /nobreak >nul

echo.
echo [3/4] Starting Frontend (Port 3000)...
start "SecureSite Frontend" cmd /k "cd frontend && npm run dev"

echo.
echo [4/4] Waiting for frontend to start...
timeout /t 15 /nobreak >nul

echo.
echo ============================================
echo All Services Started!
echo ============================================
echo.
echo Frontend:  http://localhost:3000
echo Backend:   http://localhost:8012
echo API Docs:  http://localhost:8012/docs
echo.
echo Press any key to close this window (services will keep running in separate windows)
pause