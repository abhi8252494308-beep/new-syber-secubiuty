# SecureSite Audit Platform

A comprehensive defensive security audit platform for websites. Perform safe, non-intrusive security checks including HTTPS/TLS analysis, security headers verification, cookie security assessment, and more.

## Features

- **Domain Verification**: Verify domain ownership via DNS TXT record, file upload, or meta tag
- **HTTPS/TLS Analysis**: Check SSL certificate validity, TLS version, cipher suites, and HSTS configuration
- **SSL Labs Integration**: Comprehensive SSL/TLS analysis via Qualys SSL Labs API
- **Security Headers**: Verify Content Security Policy, X-Frame-Options, X-Content-Type-Options, and more
- **Cookie Security**: Analyze cookie attributes including Secure, HttpOnly, and SameSite flags
- **robots.txt & security.txt**: Check for presence and proper configuration
- **Server Information**: Detect publicly exposed server information and technology stack
- **DNS Security**: SPF, DKIM, and DMARC record validation
- **CORS Analysis**: Cross-Origin Resource Sharing configuration review
- **Clickjacking Detection**: X-Frame-Options and CSP frame-ancestors verification
- **PDF Reports**: Generate comprehensive PDF reports with findings and recommendations
- **Security Scoring**: Get an overall security score with actionable recommendations
- **Advanced Dashboard**: D3.js visualizations for risk distribution, score gauges, and vulnerability trends
- **MongoDB Storage**: Persistent audit results with querying capabilities
- **Comprehensive Testing**: Pytest backend tests and Cypress E2E frontend tests

## Tech Stack

- **Frontend**: Next.js 14, TypeScript, Tailwind CSS, D3.js, Cypress
- **Backend**: FastAPI (Python), SQLAlchemy, Pydantic, Motor (MongoDB)
- **Database**: PostgreSQL (primary), MongoDB (analytics)
- **Authentication**: JWT (JSON Web Tokens)
- **Caching**: Redis
- **PDF Generation**: WeasyPrint
- **External APIs**: Qualys SSL Labs API
- **Testing**: Pytest (backend), Cypress (frontend E2E)
- **Deployment**: Docker, Docker Compose, Heroku, AWS Elastic Beanstalk

## Project Structure

```
Securesite-Audit/
├── backend/                 # FastAPI backend
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py         # FastAPI application entry point
│   │   ├── config.py       # Configuration settings
│   │   ├── database.py     # Database connection and session
│   │   ├── models/         # SQLAlchemy models
│   │   ├── schemas/        # Pydantic schemas
│   │   ├── routers/        # API route handlers
│   │   ├── services/       # Business logic services
│   │   └── utils/          # Utility functions
│   ├── alembic/            # Database migrations
│   ├── requirements.txt    # Python dependencies
│   └── Dockerfile          # Backend Docker image
├── frontend/               # Next.js frontend
│   ├── app/                # Next.js app directory
│   │   ├── auth/           # Authentication pages
│   │   ├── dashboard/      # Dashboard page
│   │   ├── domains/        # Domain management pages
│   │   ├── audits/         # Audit pages
│   │   └── reports/        # Report pages
│   ├── components/         # Reusable UI components
│   ├── lib/                # Utility libraries
│   ├── package.json        # Node.js dependencies
│   ├── tailwind.config.ts  # Tailwind CSS configuration
│   ├── tsconfig.json       # TypeScript configuration
│   └── Dockerfile          # Frontend Docker image
├── database/
│   └── schema.sql          # Database schema
├── docker-compose.yml      # Docker Compose configuration
├── .env.example            # Environment variables template
└── .gitignore              # Git ignore rules
```

## Getting Started

### Prerequisites

- Docker and Docker Compose
- Node.js 18+ (for local development)
- Python 3.11+ (for local development)
- PostgreSQL 15+ (for local development without Docker)

### Quick Start with Docker

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd Securesite-Audit
   ```

2. **Create environment file**
   ```bash
   cp .env.example .env
   ```
   Edit `.env` with your configuration values.

3. **Start all services**
   ```bash
   docker-compose up -d
   ```

4. **Access the application**
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:8000
   - API Documentation: http://localhost:8000/docs

### Local Development

#### Backend Setup

1. **Create virtual environment**
   ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables**
   ```bash
   cp ../.env.example ../.env
   # Edit .env with your database credentials
   ```

4. **Run database migrations**
   ```bash
   alembic upgrade head
   ```

5. **Start the development server**
   ```bash
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```

#### Frontend Setup

1. **Install dependencies**
   ```bash
   cd frontend
   npm install
   ```

2. **Start the development server**
   ```bash
   npm run dev
   ```

3. **Access the application**
   - Open http://localhost:3000 in your browser

## Domain Verification Methods

### 1. DNS TXT Record (Recommended)

Add a TXT record to your domain's DNS:

```
Host: _securesite-audit.yourdomain.com
Type: TXT
Value: <verification-token>
TTL: 300
```

### 2. File Upload

Upload a file to your web server:

```
URL: https://yourdomain.com/.well-known/securesite-audit-verification.txt
Content: <verification-token>
```

### 3. Meta Tag

Add a meta tag to your website's HTML `<head>`:

```html
<meta name="securesite-audit-verification" content="<verification-token>">
```

## Testing

### Backend Tests (Pytest)
```bash
cd backend
pip install -r requirements-test.txt
pytest tests/ -v --cov=app --cov-report=html
```

### Frontend Tests (Cypress)
```bash
cd frontend
npm run cypress:open   # Interactive mode
npm run cypress:run    # Headless CI mode
```

### Test Coverage
- Backend: 22 tests covering endpoints, models, schemas, and security checks
- Frontend: E2E tests for dashboard, domains, audits pages
- CI/CD ready for GitHub Actions/GitLab CI

## API Endpoints

### Authentication
- `POST /api/v1/auth/register` - Register a new user
- `POST /api/v1/auth/login` - Login and get tokens
- `POST /api/v1/auth/refresh` - Refresh access token
- `GET /api/v1/auth/verify-email` - Verify email address
- `GET /api/v1/auth/me` - Get current user profile

### Domains
- `POST /api/v1/domains` - Add a new domain
- `GET /api/v1/domains` - List user's domains
- `GET /api/v1/domains/{id}` - Get domain details
- `POST /api/v1/domains/{id}/verify` - Verify domain ownership
- `DELETE /api/v1/domains/{id}` - Delete a domain

### Audits
- `POST /api/v1/audits` - Create a new audit
- `GET /api/v1/audits` - List user's audits
- `GET /api/v1/audits/{id}` - Get audit details with results
- `DELETE /api/v1/audits/{id}` - Delete an audit

### Reports
- `POST /api/v1/reports/generate/{audit_id}` - Generate PDF report
- `GET /api/v1/reports/download/{report_id}` - Download PDF report
- `GET /api/v1/reports` - List user's reports
- `DELETE /api/v1/reports/{report_id}` - Delete a report

### MongoDB Analytics
- `GET /api/v1/mongodb/statistics` - Get overall audit statistics
- `GET /api/v1/mongodb/audits/recent` - Get recent audit results
- `GET /api/v1/mongodb/audits/by-risk-score` - Filter audits by risk score
- `GET /api/v1/mongodb/audits/domain/{domain}` - Get audits for a domain
- `GET /api/v1/mongodb/audits/{audit_id}` - Get specific audit from MongoDB
- `GET /api/v1/mongodb/domains` - Get all domains
- `GET /api/v1/mongodb/domains/{domain}` - Get specific domain

## Security Checks Performed

### HTTPS/TLS Configuration
- HTTPS availability
- TLS version (1.2, 1.3)
- Cipher suite analysis
- SSL certificate validity and expiry
- Certificate issuer and subject
- Subject Alternative Names (SAN)
- HSTS (HTTP Strict Transport Security) configuration

### SSL Labs Analysis (via Qualys SSL Labs API)
- Comprehensive SSL/TLS grade (A+ through F)
- Supported protocols (SSLv2, SSLv3, TLS 1.0-1.3)
- Cipher suite strength analysis
- Known vulnerability detection (POODLE, BEAST, HEARTBLEED, etc.)
- Certificate chain validation

### Security Headers
- Content Security Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- X-XSS-Protection
- Referrer-Policy
- Permissions-Policy
- Cross-Origin-Opener-Policy
- Cross-Origin-Resource-Policy
- Cross-Origin-Embedder-Policy

### Cookie Security
- Secure flag
- HttpOnly flag
- SameSite attribute (Strict, Lax, None)

### robots.txt
- File presence
- Sitemap references
- Security.txt references

### security.txt
- File presence
- Contact information
- Encryption URLs
- Policy URLs
- Expiry date

### Server Information
- Server header analysis
- X-Powered-By header
- Technology stack detection
- IP address resolution

### DNS Security
- SPF (Sender Policy Framework) record validation
- DKIM (DomainKeys Identified Mail) record check
- DMARC (Domain-based Message Authentication) policy review
- Overall DNS security scoring

### CORS Configuration
- Wildcard origin detection
- Credentials with wildcard origin check
- Allowed methods and headers review
- Exposed headers analysis

### Clickjacking Protection
- X-Frame-Options header verification
- CSP frame-ancestors directive check
- Vulnerability assessment

## Deployment

### Production Deployment with Docker

1. **Set production environment variables**
   ```bash
   cp .env.example .env
   # Edit with production values:
   # - JWT_SECRET_KEY: Use a strong random key
   # - DEBUG: Set to False
   # - DATABASE_URL: Production database URL
   # - BACKEND_CORS_ORIGINS: Your frontend domain
   ```

2. **Build and start services**
   ```bash
   docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
   ```

3. **Run database migrations**
   ```bash
   docker-compose exec backend alembic upgrade head
   ```

### Manual Production Deployment

#### Backend

1. **Install dependencies**
   ```bash
   cd backend
   pip install -r requirements.txt
   ```

2. **Set environment variables**
   ```bash
   export DATABASE_URL="postgresql://user:password@host:5432/dbname"
   export JWT_SECRET_KEY="your-secret-key"
   # ... other variables
   ```

3. **Run with Gunicorn**
   ```bash
   gunicorn app.main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
   ```

#### Frontend

1. **Install dependencies**
   ```bash
   cd frontend
   npm install
   ```

2. **Build for production**
   ```bash
   npm run build
   ```

3. **Start production server**
   ```bash
   npm start
   ```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection URL | `postgresql://securesite:securesite_password@db:5432/securesite_audit` |
| `JWT_SECRET_KEY` | Secret key for JWT tokens | Required |
| `JWT_ALGORITHM` | JWT algorithm | `HS256` |
| `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | Access token expiry | `30` |
| `JWT_REFRESH_TOKEN_EXPIRE_DAYS` | Refresh token expiry | `7` |
| `BACKEND_CORS_ORIGINS` | Allowed CORS origins | `http://localhost:3000` |
| `API_V1_PREFIX` | API version prefix | `/api/v1` |
| `REDIS_URL` | Redis connection URL | `redis://redis:6379/0` |
| `APP_NAME` | Application name | `SecureSite Audit` |
| `APP_URL` | Application URL | `http://localhost:3000` |
| `DEBUG` | Debug mode | `True` |
| `AUDIT_TIMEOUT_SECONDS` | Audit timeout | `120` |
| `MAX_CONCURRENT_AUDITS` | Max concurrent audits | `5` |

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, please open an issue on GitHub or contact support@securesite-audit.com.