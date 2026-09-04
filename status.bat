@echo off
REM SecureSite Audit Platform - Status Check

echo ============================================
echo SecureSite Audit Platform - Service Status
echo ============================================
echo.

echo [Backend API - Port 8012]
curl -s -o nul -w "Status: %{http_code}\n" http://127.0.0.1:8012/health 2>nul || echo "Status: NOT RUNNING"

echo.
echo [Frontend - Port 3000]
curl -s -o nul -w "Status: %{http_code}\n" http://127.0.0.1:3000 2>nul || echo "Status: NOT RUNNING"

echo.
echo [API Documentation - Port 8012]
curl -s -o nul -w "Status: %{http_code}\n" http://127.0.0.1:8012/docs 2>nul || echo "Status: NOT RUNNING"

echo.
echo [MongoDB Analytics - Port 8012]
curl -s -o nul -w "Status: %{http_code}\n" http://127.0.0.1:8012/api/v1/mongodb/statistics 2>nul || echo "Status: NOT RUNNING"

echo.
echo ============================================
echo Process List:
echo ============================================
tasklist /FI "IMAGENAME eq python.exe" /FI "WINDOWTITLE eq *SecureSite*" 2>nul
tasklist /FI "IMAGENAME eq node.exe" /FI "WINDOWTITLE eq *SecureSite*" 2>nul

echo.
pause