@echo off
REM SecureSite Audit Platform - Stop Script

echo ============================================
echo Stopping SecureSite Audit Services
echo ============================================

echo.
echo Stopping backend (uvicorn)...
taskkill /F /FI "WINDOWTITLE eq *SecureSite Backend*" 2>nul
taskkill /F /IM python.exe /FI "COMMANDLINE eq *uvicorn*" 2>nul

echo Stopping frontend (next.js)...
taskkill /F /FI "WINDOWTITLE eq *SecureSite Frontend*" 2>nul
taskkill /F /IM node.exe /FI "COMMANDLINE eq *next*" 2>nul

echo.
echo All services stopped.
pause