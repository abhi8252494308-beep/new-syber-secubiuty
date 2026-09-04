# SecureSite Audit Platform - Quick Start Guide

## 📁 Project Location
`C:\Users\Abhishek Kumar\OneDrive\Desktop\Securesite-Audit\`

## 🚀 Quick Start (Tomorrow)

### Option 1: Double-click `start-all.bat`
This will open two command windows:
1. **Backend API** - Runs on http://localhost:8012
2. **Frontend** - Runs on http://localhost:3000

### Option 2: Manual Start (Two Terminals)

**Terminal 1 - Backend:**
```cmd
cd C:\Users\Abhishek Kumar\OneDrive\Desktop\Securesite-Audit\backend
python -m uvicorn app.main:app --port 8012 --reload
```

**Terminal 2 - Frontend:**
```cmd
cd C:\Users\Abhishek Kumar\OneDrive\Desktop\Securesite-Audit\frontend
npm run dev
```

## ✅ Verify Everything Works

Run `status.bat` or check manually:
- **Frontend:** http://localhost:3000
- **Backend API:** http://localhost:8012
- **API Docs:** http://localhost:8012/docs
- **MongoDB Stats:** http://localhost:8012/api/v1/mongodb/statistics

## 🛑 Stop Services
Run `stop-all.bat` or close the two command windows.

## 🔧 Troubleshooting

### Port Already in Use
```cmd
# Kill processes on ports 3000 and 8012
netstat -ano | findstr "3000\|8012"
taskkill /F /PID <PID_NUMBER>
```

### Backend Won't Start
```cmd
cd backend
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --port 8012 --reload
```

### Frontend Won't Start
```cmd
cd frontend
npm install
npm run dev
```

### Database Issues
The SQLite database auto-creates. If corrupted:
```cmd
del backend\securesite_audit.db
# Restart backend - it will recreate tables
```

## 📂 Key Files

| File | Purpose |
|------|---------|
| `start-all.bat` | Start all services |
| `stop-all.bat` | Stop all services |
| `status.bat` | Check service status |
| `backend/requirements.txt` | Python dependencies |
| `frontend/package.json` | Node.js dependencies |
| `docker-compose.yml` | Docker deployment |
| `README.md` | Full documentation |

## 🌐 Key URLs After Startup

| Service | URL |
|---------|-----|
| Frontend Dashboard | http://localhost:3000 |
| Advanced Dashboard | http://localhost:3000/dashboard/advanced |
| Domains Page | http://localhost:3000/domains |
| Audits Page | http://localhost:3000/audits |
| API Health | http://localhost:8012/health |
| API Docs (Swagger) | http://localhost:8012/docs |
| MongoDB Statistics | http://localhost:8012/api/v1/mongodb/statistics |

## 🧪 Running Tests

**Backend Tests:**
```cmd
cd backend
python -m pytest tests/ -v
```

**Frontend E2E Tests:**
```cmd
cd frontend
npm run cypress:open   # Interactive
npm run cypress:run    # Headless
```

## 📦 Deployment

### Docker (Production)
```cmd
docker-compose up -d --build
```

### Heroku
```cmd
# Backend
heroku create securesite-backend
git push heroku main

# Frontend
heroku create securesite-frontend
git push heroku main
```

## 📝 Key Features Implemented

✅ **Security Checks:**
- HTTPS/TLS Analysis
- SSL Labs Integration
- Security Headers (CSP, HSTS, X-Frame-Options, etc.)
- Cookie Security (Secure, HttpOnly, SameSite)
- DNS Security (SPF, DKIM, DMARC)
- CORS Configuration Analysis
- Clickjacking Detection
- robots.txt & security.txt validation
- Server Information Exposure

✅ **Platform Features:**
- Domain Verification (DNS, File, Meta tag)
- Background Audit Processing
- PDF Report Generation
- D3.js Visualizations (Risk Distribution, Score Gauge, Vulnerabilities)
- MongoDB Analytics Storage
- PostgreSQL Primary Database
- JWT Authentication
- 22 Passing Backend Tests
- Cypress E2E Frontend Tests

## 🔐 Default Test Credentials
- **Email:** default@securesite-audit.local
- **Password:** default123

## 📞 Support
Check `README.md` for full documentation or run:
```cmd
type README.md | more
```

---
**Last Updated:** September 4, 2026
**Status:** ✅ All Systems Operational