# VulnGuard – Enterprise Vulnerability Management Platform

> **Module:** COM661 – Full Stack Strategies and Development  
> **Author:** Hritik Sah  
> **Version:** 1.0  
> **Last Updated:** March 11, 2026

VulnGuard is an enterprise-grade, full-stack cybersecurity platform designed for tracking, managing, and analysing security vulnerabilities across organisational IT infrastructure. Built with Python Flask and MongoDB, it provides security teams with comprehensive tools to record discovered vulnerabilities, monitor remediation workflows, enforce patch compliance deadlines, and generate risk analytics dashboards.

## 🎯 Project Overview

**Problem Statement:** Modern organisations face an ever-increasing volume of cybersecurity vulnerabilities across their IT assets. Without a centralised tracking platform, security teams encounter fragmented data, missed patch deadlines, lack of risk visibility, no audit trail, and inability to measure patch compliance rates.

**Solution:** VulnGuard addresses these challenges by providing a centralised vulnerability register, remediation workflow management, activity audit trail, risk analytics engine, role-based access control, and patch compliance reporting with advanced multi-dimensional filtering.

## ✨ Key Features

### Backend Capabilities
- **RESTful API** with strict REST conventions, proper HTTP status codes, and standardised JSON responses
- **Full CRUD Operations** on vulnerability documents with nested sub-documents (remediation steps, activity logs)
- **Advanced MongoDB Patterns:**
  - Multi-stage aggregation pipelines (`$group`, `$match`, `$project`, `$unwind`, `$facet`, `$out`, `$geoNear`)
  - Geospatial queries with 2dsphere indexes and proximity search
  - Text search with full-text indexes
  - Cursor-based (keyset) pagination alongside traditional skip/limit
  - Bulk operations (`insert_many`)
  - Sub-document CRUD with `$push`, `$pull`, and positional operators
  - TTL indexes for automatic token blacklist cleanup
- **JWT Authentication** with HS256 signing, unique `jti` claims, and token blacklisting
- **Three-Tier RBAC** (Admin, Security Analyst, Guest) with decorator-based enforcement
- **Advanced Filtering** using `$in`, `$regex`, `$or`, `$text`, CVSS range queries
- **Enterprise Validation** with comprehensive input validation and centralised error handling
- **Activity Audit Trail** recording every action taken on vulnerabilities

### MongoDB Features Demonstrated
| Feature | Implementation | Endpoint |
|---------|----------------|----------|
| `$geoNear` aggregation | Find nearby vulnerabilities by location | `GET /vulnerabilities/nearby` |
| `$out` aggregation | Persist reports to collection | `POST /analytics/generate-report` |
| `$in` operator | Filter by multiple values | `?severity_in=Critical,High` |
| `$regex` operator | Pattern matching | `?title_regex=SQL.*Injection` |
| `$or` operator | Complex combined filters | `?or_severity=Critical&or_status=Open` |
| `$text` search | Full-text search | `?search=buffer overflow` |
| `insert_many` | Bulk create operations | `POST /vulnerabilities/bulk` |
| Sub-document CRUD | Remediation steps, activity logs | `/remediation-steps`, `/activity-log` |
| TTL index | Auto-expire blacklisted tokens | `blacklist` collection (24h) |
| 2dsphere index | Geospatial queries | `vulnerabilities.location` field |
| Compound index | Multi-field sorting/filtering | `(severity, status, created_at)` |

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Client (Postman / Angular / curl)                      │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│  Flask Application (app.py)                             │
│  ├─ CORS middleware                                     │
│  ├─ Structured logging & request timing                 │
│  ├─ Centralised error handler (JSON responses)          │
│  └─ Blueprint router (/api/v1/*)                        │
│       ├─ auth_bp         → /api/v1/auth                 │
│       ├─ vulnerabilities_bp → /api/v1/vulnerabilities   │
│       ├─ remediation_bp  → /api/v1/vulnerabilities      │
│       ├─ activity_log_bp → /api/v1/vulnerabilities      │
│       ├─ analytics_bp    → /api/v1/analytics            │
│       └─ admin_bp        → /api/v1/admin                │
│                                                          │
│  Middleware chain:                                       │
│  @token_required → @role_required(*) → route handler    │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│  MongoDB 8.2                                            │
│  ├─ users collection                                    │
│  ├─ vulnerabilities (with remediation_steps, activity_log) │
│  ├─ blacklist (TTL index – auto-expires after 24h)     │
│  └─ reports (generated via $out aggregation)           │
└─────────────────────────────────────────────────────────┘
```

## 🛠️ Tech Stack

| Layer | Technology | Version | Purpose |
|-------|-----------|---------|---------|
| **Backend** | Python | 3.14 | Runtime |
| | Flask | 3.1.0 | Web framework with blueprints |
| | PyMongo | 4.11.3 | MongoDB driver |
| | PyJWT | 2.10.1 | JWT token encode/decode (HS256) |
| | bcrypt | 4.2.1 | Password hashing |
| | Flask-CORS | 5.0.1 | Cross-Origin Resource Sharing |
| | python-dotenv | 1.0.1 | Environment variable management |
| **Database** | MongoDB | 8.2.4 | NoSQL document store |
| **Testing** | Postman/Newman | Latest | API integration testing (81 requests) |
| | bash | — | Shell test suite (37 tests) |
| **Server** | Gunicorn | 23.0.0 | Production WSGI server |

## 📁 Project Structure

```
VulnGuard/
├── README.md                          # This file
├── LICENSE                            # MIT License
├── Makefile                          # Common commands
├── pyrightconfig.json                # Type checking config
│
├── backend/                          # Backend API
│   ├── app.py                        # Application factory
│   ├── config.py                     # Environment configs
│   ├── run.py                        # CLI entry point
│   ├── requirements.txt              # Python dependencies
│   ├── README.md                     # Backend documentation
│   │
│   ├── middleware/                   # Request processing
│   │   ├── auth_middleware.py        # JWT validation
│   │   ├── rbac_middleware.py        # Role-based access
│   │   └── error_handler.py          # Error responses
│   │
│   ├── routes/                       # API endpoints (6 blueprints)
│   │   ├── auth/                     # Authentication
│   │   ├── vulnerabilities/          # Vulnerability CRUD
│   │   ├── remediation/              # Remediation steps
│   │   ├── activity_log/             # Activity tracking
│   │   ├── analytics/                # Aggregation pipelines
│   │   └── admin/                    # User management
│   │
│   ├── utils/                        # Helpers & validators
│   ├── seeds/                        # Database seeding
│   ├── scripts/                      # Data import tools
│   ├── tests/                        # Test suites
│   │   ├── test_new_features.sh      # 37 bash tests
│   │   ├── verify_endpoints.sh       # Basic verification
│   │   └── postman/                  # Postman collection (81 requests)
│   ├── data/                         # Downloaded datasets
│   └── logs/                         # Application logs
│
└── docs/                             # Original documentation (for reference)
    ├── PRD.md                        # Product Requirements
    ├── API_SPECIFICATION.md          # Complete API spec
    ├── BLUEPRINTS.md                 # Architecture details
    ├── QA_STRATEGY.md                # Testing strategy
    ├── AGENTS.md                     # AI assistant context
    └── Improvements.md               # Implementation tracker
```

## 🚀 Quick Start

### Prerequisites

- **Python 3.10+** installed
- **MongoDB 6.0+** running on `localhost:27017`
- **curl** or **Postman** for API testing

### Installation

```bash
# 1. Clone the repository
git clone <repository-url>
cd VulnGuard

# 2. Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # macOS/Linux
# or: .\venv\Scripts\activate  # Windows

# 3. Install dependencies
cd backend
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env with your SECRET_KEY and MongoDB URI

# 5. Seed the database
python -m seeds.seed_data

# 6. Start the server
python run.py --port 5001
```

### Verify Installation

```bash
# Health check
curl http://localhost:5001/api/v1/health

# Expected response:
# {"status": "success", "message": "VulnGuard API is running"}
```

### Default User Accounts

After seeding, three user accounts are available:

| Username | Email | Password | Role |
|----------|-------|----------|------|
| admin | admin@vulnguard.test | `Admin@Secure123!` | admin |
| analyst | analyst@vulnguard.test | `Analyst@Secure123!` | analyst |
| guest | guest@vulnguard.test | `Guest@Secure123!` | guest |

### Example API Usage

```bash
# 1. Login
TOKEN=$(curl -X POST http://localhost:5001/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@vulnguard.test","password":"Admin@Secure123!"}' \
  | jq -r '.access_token')

# 2. Get vulnerabilities
curl http://localhost:5001/api/v1/vulnerabilities?severity_in=Critical,High \
  -H "x-access-token: $TOKEN"

# 3. Create vulnerability
curl -X POST http://localhost:5001/api/v1/vulnerabilities \
  -H "x-access-token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "cve_id": "CVE-2026-12345",
    "vulnerability_title": "SQL Injection in Login",
    "description": "SQL injection vulnerability in user authentication",
    "severity": "Critical",
    "cvss_score": 9.8,
    "status": "Open",
    "vulnerability_type": "Software",
    "discovery_method": "Scan",
    "affected_product": "WebApp v1.0",
    "department": "Engineering",
    "asset_type": "Application"
  }'

# 4. Geospatial query (find nearby vulnerabilities)
curl "http://localhost:5001/api/v1/vulnerabilities/nearby?lng=-1.4746&lat=53.3811&radius=50&limit=10"

# 5. Get analytics
curl http://localhost:5001/api/v1/analytics/severity-distribution \
  -H "x-access-token: $TOKEN"
```

## 📊 API Documentation

### Base URL
```
http://localhost:5001/api/v1
```

### Authentication
All protected endpoints require the `x-access-token` header:
```
x-access-token: <jwt_token>
```

**Note:** This project does **not** use the `Authorization: Bearer` scheme as per coursework requirements. Only `x-access-token` and Basic Auth are supported.

### Core Endpoints

#### Authentication (`/auth`)
- `POST /auth/register` – Register new user
- `POST /auth/login` – Login and receive JWT token
- `POST /auth/logout` – Blacklist current token
- `GET /auth/profile` – Get current user profile
- `PUT /auth/profile` – Update profile
- `PUT /auth/change-password` – Change password
- `POST /auth/refresh` – Refresh JWT token

#### Vulnerabilities (`/vulnerabilities`)
- `GET /vulnerabilities` – List all (filters, pagination, search)
- `GET /vulnerabilities/:id` – Get single vulnerability
- `POST /vulnerabilities` – Create vulnerability (admin, analyst)
- `POST /vulnerabilities/bulk` – Bulk create 2-50 items (admin, analyst)
- `PUT /vulnerabilities/:id` – Update vulnerability (admin, analyst)
- `DELETE /vulnerabilities/:id` – Delete vulnerability (admin only)
- `GET /vulnerabilities/nearby` – Geospatial proximity search

#### Remediation Steps (Sub-documents)
- `GET /vulnerabilities/:id/remediation-steps` – List all steps
- `GET /vulnerabilities/:id/remediation-steps/:step_id` – Get single step
- `POST /vulnerabilities/:id/remediation-steps` – Add step (`$push`)
- `PUT /vulnerabilities/:id/remediation-steps/:step_id` – Update step
- `DELETE /vulnerabilities/:id/remediation-steps/:step_id` – Remove step (`$pull`)

#### Activity Log (Sub-documents)
- `GET /vulnerabilities/:id/activity-log` – List all entries
- `GET /vulnerabilities/:id/activity-log/:log_id` – Get single entry
- `POST /vulnerabilities/:id/activity-log` – Add entry (`$push`)
- `DELETE /vulnerabilities/:id/activity-log/:log_id` – Delete entry (admin)

#### Analytics (Aggregation Pipelines)
- `GET /analytics/severity-distribution` – Group by severity
- `GET /analytics/department-risk` – Risk by department
- `GET /analytics/overdue-patches` – Overdue items report
- `GET /analytics/patch-compliance` – Compliance metrics
- `GET /analytics/vulnerability-trends` – Trends by month
- `GET /analytics/top-affected-assets` – Most affected assets
- `GET /analytics/mean-time-to-remediation` – Average fix time
- `GET /analytics/risk-scores` – Calculated risk scores
- `GET /analytics/summary` – Dashboard KPIs
- `POST /analytics/generate-report` – Persist report (`$out`)
- `GET /analytics/reports` – Read persisted reports

#### Admin (`/admin`)
- `GET /admin/users` – List all users (admin)
- `GET /admin/users/:id` – Get user details (admin)
- `PUT /admin/users/:id/role` – Update user role (admin)
- `PUT /admin/users/:id/status` – Activate/deactivate (admin)
- `DELETE /admin/users/:id` – Delete user (admin)

### Query Parameters (GET /vulnerabilities)

| Parameter | Type | Description | Example |
|-----------|------|-------------|---------|
| `page` | int | Page number (default: 1) | `?page=2` |
| `per_page` | int | Items per page (max 100) | `?per_page=25` |
| `after` | ObjectId | Cursor-based pagination | `?after=507f1f77bcf86cd799439011` |
| `sort_by` | string | Sort field | `?sort_by=cvss_score` |
| `sort_order` | asc/desc | Sort direction | `?sort_order=desc` |
| `severity` | string | Exact match | `?severity=Critical` |
| `severity_in` | string | Multiple values (`$in`) | `?severity_in=Critical,High` |
| `status_in` | string | Multiple statuses (`$in`) | `?status_in=Open,In Progress` |
| `title_regex` | string | Pattern matching (`$regex`) | `?title_regex=SQL.*Injection` |
| `search` | string | Full-text search (`$text`) | `?search=buffer overflow` |
| `min_cvss` | float | Minimum CVSS score | `?min_cvss=7.0` |
| `max_cvss` | float | Maximum CVSS score | `?max_cvss=10.0` |
| `or_severity` | string | OR condition | `?or_severity=Critical&or_status=Open` |
| `or_status` | string | OR condition | Combined with other `or_*` params |
| `or_min_cvss` | float | OR condition | `?or_min_cvss=9.0` |
| `or_department` | string | OR condition | `?or_department=Engineering` |

### Response Format

#### Success Response
```json
{
  "status": "success",
  "data": { ... },
  "pagination": {
    "page": 1,
    "per_page": 10,
    "total": 109,
    "pages": 11,
    "next_after": "507f1f77bcf86cd799439011"
  }
}
```

#### Error Response
```json
{
  "status": "error",
  "message": "Detailed error message",
  "code": 400
}
```

## 🧪 Testing

### Database Seeding

The seed script creates a complete test environment:

```bash
cd backend
python -m seeds.seed_data

# Optionally reseed (drops existing data)
python -m seeds.seed_data --reseed
```

**Seeded Data:**
- **3 users** (admin, analyst, guest) with bcrypt-hashed passwords
- **109 vulnerabilities** with varied severity levels, statuses, and CVSS scores
- **Remediation steps** attached to vulnerabilities
- **Activity log entries** for audit trail
- **GeoJSON locations** for geospatial queries (10 real-world coordinates)
- **Indexes:** single-field, compound, text, 2dsphere, TTL

### Bash Test Suite

Comprehensive test suite covering all features:

```bash
cd backend/tests
bash test_new_features.sh
```

**Test Coverage (37 tests):**
- Authentication (login, logout, token validation)
- CRUD operations (create, read, update, delete)
- Bulk operations (`insert_many`)
- Advanced filters (`$in`, `$regex`, `$or`, `$text`)
- Geospatial queries (`$geoNear`)
- Sub-document operations (remediation steps, activity logs)
- Aggregation pipelines (all 11 analytics endpoints)
- Report generation (`$out`)
- Role-based access control
- Error handling (validation, authorization)

**Expected Output:** ✅ **37/37 tests passing**

### Postman Collection

Comprehensive API test collection with 81 automated requests:

```bash
# Import collections into Postman:
backend/tests/postman/VulnGuard.postman_collection.json
backend/tests/postman/VulnGuard.postman_environment.json

# Or run via Newman CLI:
npm install -g newman
newman run backend/tests/postman/VulnGuard.postman_collection.json \
  -e backend/tests/postman/VulnGuard.postman_environment.json
```

**Collection Features:**
- Organised into 9 folders matching API structure
- Pre-request scripts for token management
- Comprehensive test assertions
- Environment variables for dynamic values
- Tests both happy paths and error scenarios
- Validates response structure, status codes, and data integrity

### Endpoint Verification

Quick smoke test of all endpoints:

```bash
cd backend/tests
bash verify_endpoints.sh
```

This script tests basic functionality of all major endpoints to ensure the API is running correctly.

## 🗄️ Database Schema

### Vulnerability Document

```json
{
  "_id": "ObjectId",
  "cve_id": "CVE-2024-12345",
  "vulnerability_title": "SQL Injection in Login Form",
  "description": "Detailed vulnerability description",
  "severity": "Critical | High | Medium | Low",
  "cvss_score": 9.8,
  "status": "Open | In Progress | Patched | Accepted Risk",
  "vulnerability_type": "Software | Configuration | Access Control",
  "discovery_method": "Scan | Audit | Manual",
  "affected_product": "Product Name v1.0",
  "department": "Engineering",
  "asset_type": "Server | Workstation | Network Device | ...",
  "attack_vector": "Network | Adjacent | Local | Physical",
  "exploitability": "Active | Proof of Concept | Theoretical | Unproven",
  "patch_due_date": "2025-06-01T00:00:00Z",
  "location": {
    "type": "Point",
    "coordinates": [-1.4746, 53.3811]
  },
  "remediation_steps": [
    {
      "step_id": "ObjectId",
      "step_number": 1,
      "step_description": "Apply security patch",
      "priority": "Critical | High | Medium | Low",
      "status": "Pending | In Progress | Completed | Verified",
      "recommended_by": "analyst",
      "added_at": "2025-01-15T10:30:00Z"
    }
  ],
  "activity_log": [
    {
      "log_id": "ObjectId",
      "user": "admin",
      "action": "Status changed to In Progress",
      "performed_at": "2025-01-15T10:30:00Z"
    }
  ],
  "created_at": "2025-01-01T00:00:00Z",
  "updated_at": "2025-01-15T10:30:00Z"
}
```

### User Document

```json
{
  "_id": "ObjectId",
  "username": "admin",
  "email": "admin@vulnguard.test",
  "password": "$2b$12$...",  // bcrypt hash
  "role": "admin | analyst | guest",
  "is_active": true,
  "created_at": "2025-01-01T00:00:00Z"
}
```

### Indexes

| Collection | Index | Type | Purpose |
|------------|-------|------|---------|
| `vulnerabilities` | `cve_id` | Single | Unique CVE lookup |
| `vulnerabilities` | `severity, status, created_at` | Compound | Filtered queries |
| `vulnerabilities` | `vulnerability_title, description` | Text | Full-text search |
| `vulnerabilities` | `location` | 2dsphere | Geospatial queries |
| `users` | `email` | Single, Unique | User authentication |
| `users` | `username` | Single, Unique | User lookup |
| `blacklist` | `token` | Single, Unique | Token revocation |
| `blacklist` | `blacklisted_at` | TTL (24h) | Auto-cleanup |

## 🔒 Security Features

- **Password Hashing:** bcrypt with salt rounds (12)
- **JWT Tokens:** HS256 signed with secret key, unique `jti` claims
- **Token Blacklisting:** Logged-out tokens stored in TTL-indexed collection
- **Role-Based Access Control:** Three-tier permission system
- **Input Validation:** Comprehensive type/range/enum/regex validation
- **SQL Injection Prevention:** MongoDB native (no SQL)
- **Error Handling:** No sensitive info leakage in error responses
- **CORS Configuration:** Configurable allowed origins

## 🎓 COM661 Coursework Alignment

This project demonstrates all required MongoDB operations and advanced features:

### Required Operations ✅
- [x] Full CRUD on main documents
- [x] Sub-document CRUD (`$push`, `$pull`, positional `$`)
- [x] Multiple aggregation pipelines (`$group`, `$match`, `$project`, `$unwind`, `$facet`, `$sort`, `$limit`)
- [x] Advanced filtering (`$in`, `$regex`, `$or`, `$text`, `$gte`, `$lte`)
- [x] Indexes (single, compound, text, geospatial, TTL)
- [x] Geospatial queries (`2dsphere`, `$geoNear`)
- [x] `$out` aggregation stage (persist reports)
- [x] Bulk operations (`insert_many`)
- [x] Two pagination strategies (skip/limit and cursor-based)
- [x] JWT authentication with blacklisting
- [x] Three-tier RBAC system
- [x] Comprehensive validation and error handling
- [x] Extensive testing (37 bash tests + 81 Postman requests)

### Project Complexity
VulnGuard significantly exceeds the Biz Directory demonstration application by implementing:
- **Nested sub-documents** with complex CRUD operations
- **11 aggregation pipeline endpoints** with multi-stage pipelines
- **Geospatial features** with location-based queries
- **Advanced search** with multiple filter combinations and full-text search
- **Activity audit trail** for compliance and tracking
- **Report generation** with `$out` aggregation persistence
- **Bulk operations** for efficient data import
- **Two pagination strategies** for scalability
- **Token blacklisting** with TTL auto-cleanup
- **Comprehensive testing** with automated test suites

## 📚 Additional Documentation

Detailed documentation is available in the project:

- **[backend/README.md](backend/README.md)** – Complete backend API documentation
- **[backend/routes/README.md](backend/routes/README.md)** – Blueprint architecture
- **[backend/middleware/README.md](backend/middleware/README.md)** – Middleware details
- **[backend/routes/auth/README.md](backend/routes/auth/README.md)** – Authentication endpoints
- **[backend/routes/vulnerabilities/README.md](backend/routes/vulnerabilities/README.md)** – Vulnerability CRUD
- **[backend/tests/README.md](backend/tests/README.md)** – Testing strategy
- **[docs/](docs/)** – Original detailed specifications (PRD, API spec, architecture)

## 🤝 Contributing

This is a coursework project for COM661. The original documentation in the `/docs` folder has been preserved for reference, but all essential information has been consolidated into the README files throughout the project.

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- COM661 module materials and Biz Directory demonstration
- Flask and MongoDB documentation
- OWASP CVSS scoring methodology
- CISA Known Exploited Vulnerabilities (KEV) catalog

---

**For detailed API specifications, see [backend/README.md](backend/README.md)**  
**For testing instructions, see [backend/tests/README.md](backend/tests/README.md)**
