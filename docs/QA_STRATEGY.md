# VulnGuard – Quality Assurance & Automated Testing Strategy

**Version:** 1.0  
**Last Updated:** 4 March 2026  
**Module:** COM661 – Full Stack Strategies and Development  
**Purpose:** Define a comprehensive testing strategy covering backend API testing (Postman/Newman), frontend unit testing (Karma/Jasmine), and end-to-end testing (Cypress) to ensure submission-ready quality and evidence generation.

---

## Table of Contents

1. [Testing Philosophy & Coverage Targets](#1-testing-philosophy--coverage-targets)
2. [Backend Testing – Postman Collection Strategy](#2-backend-testing--postman-collection-strategy)
3. [Postman Pre-Request Scripts](#3-postman-pre-request-scripts)
4. [Postman Test Scripts](#4-postman-test-scripts)
5. [Newman CLI Automation](#5-newman-cli-automation)
6. [Frontend Testing – Angular Unit Tests](#6-frontend-testing--angular-unit-tests)
7. [Frontend Testing – End-to-End (Cypress)](#7-frontend-testing--end-to-end-cypress)
8. [Evidence Requirements for Submission](#8-evidence-requirements-for-submission)
9. [Test Data Management](#9-test-data-management)
10. [Continuous Quality Checklist](#10-continuous-quality-checklist)

---

## 1. Testing Philosophy & Coverage Targets

### 1.1 Testing Pyramid

```
         ╔═══════════╗
         ║   E2E     ║  ← Cypress (key user journeys)
         ║  Tests    ║
        ╔╩═══════════╩╗
        ║ Integration  ║  ← Postman/Newman (API contract testing)
        ║    Tests     ║
       ╔╩══════════════╩╗
       ║   Unit Tests    ║  ← Karma/Jasmine (Angular) + Validation logic
       ╚════════════════╝
```

### 1.2 Coverage Targets

| Test Type | Target Coverage | Tool | Priority |
|-----------|:--------------:|------|:--------:|
| Backend API Integration | 100% of endpoints | Postman + Newman | **Must Have** |
| Backend Validation Logic | 100% of validation rules | Postman negative tests | **Must Have** |
| Backend Auth/RBAC | 100% of role permutations | Postman auth tests | **Must Have** |
| Angular Services | ≥ 90% | Karma + Jasmine | **Must Have** |
| Angular Components | ≥ 80% | Karma + Jasmine | **Must Have** |
| Angular Guards | 100% | Karma + Jasmine | **Must Have** |
| Angular Interceptors | 100% | Karma + Jasmine | **Must Have** |
| E2E Critical Paths | Top 5 user journeys | Cypress | **Should Have** |

---

## 2. Backend Testing – Postman Collection Strategy

### 2.1 Collection Folder Structure

The Postman collection must be organised into logical folders matching the API structure:

```
VulnGuard API Tests/
├── 📁 Environment Setup
│   ├── Health Check
│   └── Seed Test Data
│
├── 📁 Authentication
│   ├── Register – Valid User (Admin)
│   ├── Register – Valid User (Analyst)
│   ├── Register – Valid User (Guest)
│   ├── Register – Duplicate Email (400)
│   ├── Register – Missing Fields (400)
│   ├── Register – Weak Password (422)
│   ├── Login – Valid Credentials (Admin)
│   ├── Login – Valid Credentials (Analyst)
│   ├── Login – Invalid Password (401)
│   ├── Login – Non-existent Email (401)
│   ├── Get Profile – Authenticated (200)
│   ├── Get Profile – No Token (401)
│   ├── Change Password – Valid (200)
│   └── Change Password – Wrong Current (400)
│
├── 📁 Vulnerability CRUD
│   ├── Create Vulnerability – Valid (201)
│   ├── Create Vulnerability – Missing Required Fields (400)
│   ├── Create Vulnerability – Invalid CVSS Score (422)
│   ├── Create Vulnerability – Invalid Severity Enum (422)
│   ├── Create Vulnerability – Invalid Status Enum (422)
│   ├── Create Vulnerability – No Auth Token (401)
│   ├── Create Vulnerability – Guest Role (403)
│   ├── Get All Vulnerabilities – No Filter (200)
│   ├── Get All Vulnerabilities – Filter by Severity (200)
│   ├── Get All Vulnerabilities – Filter by Status (200)
│   ├── Get All Vulnerabilities – Filter by Department (200)
│   ├── Get All Vulnerabilities – Combined Filters (200)
│   ├── Get All Vulnerabilities – Sort by CVSS Descending (200)
│   ├── Get All Vulnerabilities – Sort by Patch Deadline (200)
│   ├── Get All Vulnerabilities – Pagination Page 1 (200)
│   ├── Get All Vulnerabilities – Pagination Page 2 (200)
│   ├── Get All Vulnerabilities – Text Search (200)
│   ├── Get Single Vulnerability – Valid ID (200)
│   ├── Get Single Vulnerability – Invalid ID Format (422)
│   ├── Get Single Vulnerability – Non-existent ID (404)
│   ├── Update Vulnerability – Valid (200)
│   ├── Update Vulnerability – Invalid CVSS (422)
│   ├── Update Vulnerability – Non-existent ID (404)
│   ├── Update Vulnerability – No Auth (401)
│   ├── Delete Vulnerability – Admin (204)
│   ├── Delete Vulnerability – Analyst Forbidden (403)
│   ├── Delete Vulnerability – Non-existent ID (404)
│   └── Delete Vulnerability – No Auth (401)
│
├── 📁 Remediation Steps (Sub-Document CRUD)
│   ├── Add Remediation Step – Valid (201)
│   ├── Add Remediation Step – Missing Required Fields (400)
│   ├── Add Remediation Step – Invalid Status Enum (422)
│   ├── Add Remediation Step – No Auth (401)
│   ├── Get All Remediation Steps (200)
│   ├── Get Single Remediation Step – Valid (200)
│   ├── Get Single Remediation Step – Not Found (404)
│   ├── Update Remediation Step – Valid (200)
│   ├── Update Remediation Step – Mark Completed (200)
│   ├── Update Remediation Step – Invalid Data (422)
│   ├── Delete Remediation Step – Valid (204)
│   └── Delete Remediation Step – Not Found (404)
│
├── 📁 Activity Log (Sub-Document CRUD)
│   ├── Add Activity Log Entry – Valid (201)
│   ├── Add Activity Log Entry – Missing Fields (400)
│   ├── Add Activity Log Entry – No Auth (401)
│   ├── Get All Activity Log Entries (200)
│   ├── Get Single Activity Log Entry (200)
│   ├── Delete Activity Log Entry – Admin (204)
│   ├── Delete Activity Log Entry – Analyst Forbidden (403)
│   └── Delete Activity Log Entry – Not Found (404)
│
├── 📁 Analytics
│   ├── Severity Distribution (200)
│   ├── Department Risk Exposure (200)
│   ├── Overdue Patches (200)
│   ├── Patch Compliance Rate (200)
│   ├── Vulnerability Trends (200)
│   ├── Top Affected Assets (200)
│   ├── Mean Time to Remediation (200)
│   ├── Risk Scores (200)
│   ├── Dashboard Summary (200)
│   ├── Analytics – No Auth (401)
│   └── Risk Scores – Guest Forbidden (403)
│
├── 📁 Admin Management
│   ├── List Users – Admin (200)
│   ├── List Users – Non-Admin (403)
│   ├── Get User Details – Admin (200)
│   ├── Update User Role – Valid (200)
│   ├── Update User Role – Invalid Role (422)
│   ├── Deactivate User – Admin (200)
│   ├── Delete User – Admin (204)
│   └── Delete User – Non-Admin (403)
│
└── 📁 Cleanup
    ├── Delete Test Vulnerabilities
    └── Delete Test Users
```

### 2.2 Postman Environment Variables

```json
{
  "id": "vulnguard-env",
  "name": "VulnGuard Development",
  "values": [
    { "key": "base_url", "value": "http://localhost:5000/api/v1", "enabled": true },
    { "key": "admin_token", "value": "", "enabled": true },
    { "key": "analyst_token", "value": "", "enabled": true },
    { "key": "guest_token", "value": "", "enabled": true },
    { "key": "test_vuln_id", "value": "", "enabled": true },
    { "key": "test_step_id", "value": "", "enabled": true },
    { "key": "test_log_id", "value": "", "enabled": true },
    { "key": "test_user_id", "value": "", "enabled": true },
    { "key": "admin_email", "value": "admin@vulnguard.test", "enabled": true },
    { "key": "admin_password", "value": "Admin@Secure123!", "enabled": true },
    { "key": "analyst_email", "value": "analyst@vulnguard.test", "enabled": true },
    { "key": "analyst_password", "value": "Analyst@Secure123!", "enabled": true },
    { "key": "guest_email", "value": "guest@vulnguard.test", "enabled": true },
    { "key": "guest_password", "value": "Guest@Secure123!", "enabled": true }
  ]
}
```

---

## 3. Postman Pre-Request Scripts

### 3.1 Automatic JWT Token Injection (Collection-Level)

This pre-request script runs before **every request** in the collection. It automatically logs in and stores the token if it is missing or expired.

```javascript
// Collection-level Pre-request Script

const baseUrl = pm.environment.get("base_url");

// Determine which token to use based on folder name or request name
const requestName = pm.info.requestName.toLowerCase();

let tokenKey = "admin_token";
let email = pm.environment.get("admin_email");
let password = pm.environment.get("admin_password");

if (requestName.includes("analyst")) {
    tokenKey = "analyst_token";
    email = pm.environment.get("analyst_email");
    password = pm.environment.get("analyst_password");
} else if (requestName.includes("guest")) {
    tokenKey = "guest_token";
    email = pm.environment.get("guest_email");
    password = pm.environment.get("guest_password");
}

// Skip token logic for auth endpoints (login/register)
const isAuthEndpoint = pm.request.url.toString().includes("/auth/login") ||
                       pm.request.url.toString().includes("/auth/register");

if (!isAuthEndpoint) {
    const currentToken = pm.environment.get(tokenKey);

    // Check if token exists and is not expired
    let needsRefresh = !currentToken;

    if (currentToken && !needsRefresh) {
        try {
            const payload = JSON.parse(atob(currentToken.split('.')[1]));
            const expiry = payload.exp * 1000;
            needsRefresh = Date.now() >= expiry - 60000; // Refresh 1 min before expiry
        } catch (e) {
            needsRefresh = true;
        }
    }

    if (needsRefresh) {
        pm.sendRequest({
            url: `${baseUrl}/auth/login`,
            method: "POST",
            header: { "Content-Type": "application/json" },
            body: {
                mode: "raw",
                raw: JSON.stringify({ email: email, password: password })
            }
        }, function (err, response) {
            if (!err && response.code === 200) {
                const token = response.json().data.token;
                pm.environment.set(tokenKey, token);
                console.log(`✅ ${tokenKey} refreshed successfully`);
            } else {
                console.error(`❌ Failed to refresh ${tokenKey}:`, err || response.json());
            }
        });
    }
}
```

### 3.2 Request-Level Pre-Request Script (Token Attachment)

For individual requests requiring auth, add this in the Authorization tab:

- **Type:** Bearer Token
- **Token:** `{{admin_token}}` (or `{{analyst_token}}` / `{{guest_token}}`)

### 3.3 Dynamic Test Data Generation

```javascript
// Pre-request script for Create Vulnerability test

const timestamp = Date.now();

pm.variables.set("dynamic_title", `Test Vulnerability ${timestamp}`);
pm.variables.set("dynamic_cvss", (Math.random() * 10).toFixed(1));
pm.variables.set("dynamic_department", ["Engineering", "Finance", "Operations", "IT", "HR"][Math.floor(Math.random() * 5)]);

const futureDate = new Date();
futureDate.setDate(futureDate.getDate() + 30);
pm.variables.set("dynamic_deadline", futureDate.toISOString());
```

---

## 4. Postman Test Scripts

### 4.1 Status Code Validation

```javascript
// Test: GET /vulnerabilities returns 200
pm.test("Status code is 200 OK", function () {
    pm.response.to.have.status(200);
});

// Test: POST /vulnerabilities returns 201
pm.test("Status code is 201 Created", function () {
    pm.response.to.have.status(201);
});

// Test: DELETE /vulnerabilities/{id} returns 204
pm.test("Status code is 204 No Content", function () {
    pm.response.to.have.status(204);
});

// Test: Invalid input returns 422
pm.test("Status code is 422 Unprocessable Entity", function () {
    pm.response.to.have.status(422);
});
```

### 4.2 Response Schema Validation

```javascript
// Test: Vulnerability list response schema
pm.test("Response has correct schema", function () {
    const response = pm.response.json();

    pm.expect(response).to.have.property("status", "success");
    pm.expect(response).to.have.property("data");
    pm.expect(response).to.have.property("pagination");
    pm.expect(response.data).to.be.an("array");
    pm.expect(response.pagination).to.have.property("page");
    pm.expect(response.pagination).to.have.property("per_page");
    pm.expect(response.pagination).to.have.property("total");
    pm.expect(response.pagination).to.have.property("pages");
});

// Test: Single vulnerability response schema
pm.test("Vulnerability has required fields", function () {
    const vuln = pm.response.json().data;

    pm.expect(vuln).to.have.property("_id");
    pm.expect(vuln).to.have.property("title");
    pm.expect(vuln).to.have.property("severity");
    pm.expect(vuln).to.have.property("status");
    pm.expect(vuln).to.have.property("cvss_score");
    pm.expect(vuln).to.have.property("asset_name");
    pm.expect(vuln).to.have.property("asset_type");
    pm.expect(vuln).to.have.property("department");
    pm.expect(vuln).to.have.property("remediation_steps");
    pm.expect(vuln).to.have.property("activity_log");
    pm.expect(vuln.remediation_steps).to.be.an("array");
    pm.expect(vuln.activity_log).to.be.an("array");
});

// Test: Error response schema
pm.test("Error response has correct structure", function () {
    const response = pm.response.json();

    pm.expect(response).to.have.property("status", "error");
    pm.expect(response).to.have.property("message");
    pm.expect(response).to.have.property("code");
    pm.expect(response.message).to.be.a("string");
    pm.expect(response.code).to.be.a("number");
});
```

### 4.3 Response Data Validation

```javascript
// Test: CVSS score is within valid range
pm.test("CVSS score is between 0 and 10", function () {
    const vuln = pm.response.json().data;
    pm.expect(vuln.cvss_score).to.be.at.least(0);
    pm.expect(vuln.cvss_score).to.be.at.most(10);
});

// Test: Severity is valid enum value
pm.test("Severity is a valid value", function () {
    const vuln = pm.response.json().data;
    const validSeverities = ["Critical", "High", "Medium", "Low", "Informational"];
    pm.expect(validSeverities).to.include(vuln.severity);
});

// Test: Pagination returns correct number of items
pm.test("Pagination returns correct page size", function () {
    const response = pm.response.json();
    pm.expect(response.data.length).to.be.at.most(response.pagination.per_page);
});

// Test: Filtering returns only matching results
pm.test("All returned vulnerabilities are Critical severity", function () {
    const vulnerabilities = pm.response.json().data;
    vulnerabilities.forEach(function (vuln) {
        pm.expect(vuln.severity).to.equal("Critical");
    });
});

// Test: Sorting is applied correctly (CVSS descending)
pm.test("Results are sorted by CVSS score descending", function () {
    const vulnerabilities = pm.response.json().data;
    for (let i = 1; i < vulnerabilities.length; i++) {
        pm.expect(vulnerabilities[i - 1].cvss_score).to.be.at.least(vulnerabilities[i].cvss_score);
    }
});
```

### 4.4 Response Time Validation

```javascript
// Test: API responds within acceptable time
pm.test("Response time is less than 500ms", function () {
    pm.expect(pm.response.responseTime).to.be.below(500);
});

// Test: Analytics endpoint responds within acceptable time
pm.test("Aggregation response time is less than 1000ms", function () {
    pm.expect(pm.response.responseTime).to.be.below(1000);
});
```

### 4.5 Authentication & RBAC Tests

```javascript
// Test: Protected endpoint returns 401 without token
pm.test("Returns 401 when no token provided", function () {
    pm.response.to.have.status(401);
    const response = pm.response.json();
    pm.expect(response.status).to.equal("error");
    pm.expect(response.message).to.include("token");
});

// Test: Admin-only endpoint returns 403 for analyst
pm.test("Returns 403 when analyst accesses admin endpoint", function () {
    pm.response.to.have.status(403);
    const response = pm.response.json();
    pm.expect(response.status).to.equal("error");
    pm.expect(response.message).to.include("permission");
});

// Test: Login returns valid JWT token
pm.test("Login returns JWT token", function () {
    const response = pm.response.json();
    pm.expect(response.status).to.equal("success");
    pm.expect(response.data).to.have.property("token");
    pm.expect(response.data.token).to.be.a("string");
    pm.expect(response.data.token.split(".")).to.have.lengthOf(3);

    // Store token for subsequent requests
    pm.environment.set("admin_token", response.data.token);
});
```

### 4.6 Sub-Document Test Scripts

```javascript
// Test: Remediation step added successfully
pm.test("Remediation step added to vulnerability", function () {
    pm.response.to.have.status(201);
    const response = pm.response.json();
    pm.expect(response.status).to.equal("success");
    pm.expect(response.data).to.have.property("_id");
    pm.expect(response.data).to.have.property("step_number");
    pm.expect(response.data).to.have.property("action");
    pm.expect(response.data).to.have.property("status");

    // Store step_id for subsequent tests
    pm.environment.set("test_step_id", response.data._id);
});

// Test: Activity log entry created with auto-populated fields
pm.test("Activity log has auto-populated timestamp and performer", function () {
    const logEntry = pm.response.json().data;
    pm.expect(logEntry).to.have.property("timestamp");
    pm.expect(logEntry).to.have.property("performed_by");
    pm.expect(logEntry.timestamp).to.not.be.null;
});
```

### 4.7 Analytics Test Scripts

```javascript
// Test: Severity distribution returns expected structure
pm.test("Severity distribution has correct structure", function () {
    const data = pm.response.json().data;
    pm.expect(data).to.be.an("array");
    data.forEach(function (item) {
        pm.expect(item).to.have.property("severity");
        pm.expect(item).to.have.property("count");
        pm.expect(item).to.have.property("avg_cvss");
        pm.expect(item.count).to.be.a("number");
        pm.expect(item.avg_cvss).to.be.a("number");
    });
});

// Test: Patch compliance rate is valid percentage
pm.test("Compliance rate is a valid percentage", function () {
    const data = pm.response.json().data;
    pm.expect(data).to.have.property("compliance_rate");
    pm.expect(data.compliance_rate).to.be.at.least(0);
    pm.expect(data.compliance_rate).to.be.at.most(100);
});

// Test: Dashboard summary has all required KPIs
pm.test("Dashboard summary has all KPI fields", function () {
    const data = pm.response.json().data;
    pm.expect(data).to.have.property("total_vulnerabilities");
    pm.expect(data).to.have.property("open_count");
    pm.expect(data).to.have.property("in_progress_count");
    pm.expect(data).to.have.property("resolved_count");
    pm.expect(data).to.have.property("closed_count");
    pm.expect(data).to.have.property("critical_count");
    pm.expect(data).to.have.property("compliance_rate");
    pm.expect(data).to.have.property("overdue_count");
});
```

### 4.8 Chaining Test Data Between Requests

```javascript
// After POST /vulnerabilities – store created ID
pm.test("Store created vulnerability ID", function () {
    const response = pm.response.json();
    if (response.data && response.data._id) {
        pm.environment.set("test_vuln_id", response.data._id);
        console.log("Stored test_vuln_id:", response.data._id);
    }
});

// After POST /remediation-steps – store created step ID
pm.test("Store created step ID", function () {
    const response = pm.response.json();
    if (response.data && response.data._id) {
        pm.environment.set("test_step_id", response.data._id);
        console.log("Stored test_step_id:", response.data._id);
    }
});
```

---

## 5. Newman CLI Automation

### 5.1 Installation

```bash
npm install -g newman
npm install -g newman-reporter-htmlextra
```

### 5.2 Running the Collection

```bash
# Basic execution
newman run tests/postman/VulnGuard.postman_collection.json \
  -e tests/postman/VulnGuard.postman_environment.json \
  --reporters cli,htmlextra \
  --reporter-htmlextra-export tests/reports/vulnguard-test-report.html \
  --reporter-htmlextra-title "VulnGuard API Test Report" \
  --reporter-htmlextra-browserTitle "VulnGuard Tests"
```

### 5.3 Newman with Detailed Output

```bash
# With iteration data and delay between requests
newman run tests/postman/VulnGuard.postman_collection.json \
  -e tests/postman/VulnGuard.postman_environment.json \
  --reporters cli,htmlextra,json \
  --reporter-htmlextra-export tests/reports/vulnguard-test-report.html \
  --reporter-json-export tests/reports/vulnguard-test-results.json \
  --delay-request 100 \
  --timeout-request 10000 \
  --bail \
  --color on
```

### 5.4 NPM Script Integration

Add to `backend/package.json` (or create a simple one):

```json
{
  "scripts": {
    "test:api": "newman run tests/postman/VulnGuard.postman_collection.json -e tests/postman/VulnGuard.postman_environment.json --reporters cli,htmlextra --reporter-htmlextra-export tests/reports/vulnguard-test-report.html",
    "test:api:verbose": "newman run tests/postman/VulnGuard.postman_collection.json -e tests/postman/VulnGuard.postman_environment.json --reporters cli --verbose"
  }
}
```

### 5.5 Expected Newman Output

```
VulnGuard API Tests

→ Authentication / Register – Valid User (Admin)
  POST http://localhost:5000/api/v1/auth/register [201 Created, 256B, 145ms]
  ✓ Status code is 201 Created
  ✓ Response has correct schema
  ✓ User ID is returned

→ Authentication / Login – Valid Credentials (Admin)
  POST http://localhost:5000/api/v1/auth/login [200 OK, 512B, 98ms]
  ✓ Status code is 200 OK
  ✓ Login returns JWT token
  ✓ Response time is less than 500ms

→ Vulnerability CRUD / Create Vulnerability – Valid (201)
  POST http://localhost:5000/api/v1/vulnerabilities [201 Created, 1.2KB, 87ms]
  ✓ Status code is 201 Created
  ✓ Vulnerability has required fields
  ✓ Store created vulnerability ID

... (continues for all test requests)

┌─────────────────────────┬────────────────────┬───────────────────┐
│                         │           executed  │            failed │
├─────────────────────────┼────────────────────┼───────────────────┤
│              iterations │                  1 │                 0 │
├─────────────────────────┼────────────────────┼───────────────────┤
│                requests │                 68 │                 0 │
├─────────────────────────┼────────────────────┼───────────────────┤
│            test-scripts │                136 │                 0 │
├─────────────────────────┼────────────────────┼───────────────────┤
│      prerequest-scripts │                 68 │                 0 │
├─────────────────────────┼────────────────────┼───────────────────┤
│              assertions │                204 │                 0 │
├─────────────────────────┼────────────────────┼───────────────────┤
│ total run duration: 12.4s                                       │
├─────────────────────────┼────────────────────┼───────────────────┤
│ total data received: 45.2KB                                     │
├─────────────────────────┼────────────────────┼───────────────────┤
│ average response time: 127ms                                    │
└─────────────────────────┴────────────────────┴───────────────────┘
```

---

## 6. Frontend Testing – Angular Unit Tests

### 6.1 Testing Framework Configuration

Angular projects include Karma and Jasmine by default. Ensure the test configuration is correct:

```json
// angular.json (test configuration)
{
  "test": {
    "builder": "@angular-devkit/build-angular:karma",
    "options": {
      "codeCoverage": true,
      "codeCoverageExclude": [
        "src/environments/**",
        "src/**/*.spec.ts"
      ]
    }
  }
}
```

### 6.2 Service Unit Tests

```typescript
// services/vulnerability.service.spec.ts

import { TestBed } from '@angular/core/testing';
import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import { VulnerabilityService } from './vulnerability.service';
import { Vulnerability, Severity, VulnerabilityStatus } from '../models/vulnerability.model';

describe('VulnerabilityService', () => {
  let service: VulnerabilityService;
  let httpMock: HttpTestingController;

  const mockVulnerability: Vulnerability = {
    _id: '65fa123456789abcdef01234',
    title: 'Test SQL Injection',
    description: 'Test description for SQL injection vulnerability',
    severity: Severity.Critical,
    status: VulnerabilityStatus.Open,
    cvss_score: 9.8,
    asset_name: 'web-app-01',
    asset_type: 'Application' as any,
    department: 'Engineering',
    affected_versions: ['1.0'],
    attack_vector: 'Network' as any,
    exploitability: 'Functional' as any,
    patch_deadline: '2026-03-15T00:00:00Z',
    patch_applied: false,
    reported_by: 'tester',
    risk_score: 47.2,
    remediation_steps: [],
    activity_log: [],
    created_at: '2026-02-20T10:30:00Z',
    updated_at: '2026-02-20T10:30:00Z',
    created_by: 'tester'
  };

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [HttpClientTestingModule],
      providers: [VulnerabilityService]
    });
    service = TestBed.inject(VulnerabilityService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify(); // Ensure no outstanding HTTP requests
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should retrieve paginated vulnerabilities', () => {
    const mockResponse = {
      status: 'success',
      data: [mockVulnerability],
      pagination: { page: 1, per_page: 10, total: 1, pages: 1 }
    };

    service.getVulnerabilities({ page: 1, per_page: 10 }).subscribe(response => {
      expect(response.data.length).toBe(1);
      expect(response.pagination.total).toBe(1);
    });

    const req = httpMock.expectOne(req =>
      req.url.includes('/vulnerabilities') && req.method === 'GET'
    );
    req.flush(mockResponse);
  });

  it('should retrieve a single vulnerability by ID', () => {
    const mockResponse = { status: 'success', data: mockVulnerability };

    service.getVulnerabilityById('65fa123456789abcdef01234').subscribe(response => {
      expect(response.data._id).toBe('65fa123456789abcdef01234');
      expect(response.data.title).toBe('Test SQL Injection');
    });

    const req = httpMock.expectOne(req =>
      req.url.includes('/vulnerabilities/65fa123456789abcdef01234')
    );
    expect(req.request.method).toBe('GET');
    req.flush(mockResponse);
  });

  it('should create a new vulnerability', () => {
    const newVuln = {
      title: 'New Vulnerability',
      severity: 'Critical',
      cvss_score: 8.5,
      status: 'Open',
      asset_name: 'test-server',
      asset_type: 'Server',
      department: 'IT',
      reported_by: 'tester'
    };

    service.createVulnerability(newVuln as any).subscribe(response => {
      expect(response.status).toBe('success');
    });

    const req = httpMock.expectOne(req =>
      req.url.includes('/vulnerabilities') && req.method === 'POST'
    );
    expect(req.request.body).toEqual(newVuln);
    req.flush({ status: 'success', data: { ...newVuln, _id: 'new-id' }, message: 'Vulnerability created successfully' });
  });

  it('should update an existing vulnerability', () => {
    const updates = { status: 'In Progress' };

    service.updateVulnerability('65fa123456789abcdef01234', updates as any).subscribe(response => {
      expect(response.status).toBe('success');
    });

    const req = httpMock.expectOne(req =>
      req.url.includes('/vulnerabilities/65fa123456789abcdef01234') && req.method === 'PUT'
    );
    req.flush({ status: 'success', data: { ...mockVulnerability, status: 'In Progress' } });
  });

  it('should delete a vulnerability', () => {
    service.deleteVulnerability('65fa123456789abcdef01234').subscribe(() => {
      // Success — no content expected
    });

    const req = httpMock.expectOne(req =>
      req.url.includes('/vulnerabilities/65fa123456789abcdef01234') && req.method === 'DELETE'
    );
    req.flush(null, { status: 204, statusText: 'No Content' });
  });

  it('should include query parameters for filtering', () => {
    service.getVulnerabilities({
      page: 1,
      per_page: 10,
      severity: 'Critical',
      status: 'Open',
      sort_by: 'cvss_score',
      sort_order: 'desc'
    }).subscribe();

    const req = httpMock.expectOne(req => {
      return req.params.get('severity') === 'Critical'
        && req.params.get('status') === 'Open'
        && req.params.get('sort_by') === 'cvss_score'
        && req.params.get('sort_order') === 'desc';
    });
    req.flush({ status: 'success', data: [], pagination: { page: 1, per_page: 10, total: 0, pages: 0 } });
  });
});
```

### 6.3 Auth Service Tests

```typescript
// services/auth.service.spec.ts

describe('AuthService', () => {
  let service: AuthService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [HttpClientTestingModule],
      providers: [AuthService]
    });
    service = TestBed.inject(AuthService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  it('should login and store token', () => {
    const mockLoginResponse = {
      status: 'success',
      data: {
        token: 'mock.jwt.token',
        user: { username: 'admin', role: 'admin' }
      }
    };

    service.login('admin@test.com', 'password123').subscribe(response => {
      expect(response.data.token).toBe('mock.jwt.token');
      expect(service.isAuthenticated()).toBeTrue();
    });

    const req = httpMock.expectOne(req => req.url.includes('/auth/login'));
    req.flush(mockLoginResponse);
  });

  it('should return false for isAuthenticated when no token exists', () => {
    expect(service.isAuthenticated()).toBeFalse();
  });

  it('should clear token on logout', () => {
    // Simulate having a token
    sessionStorage.setItem('token', 'mock.jwt.token');
    service.logout();
    expect(service.isAuthenticated()).toBeFalse();
  });

  it('should decode user role from JWT token', () => {
    // Mock JWT with admin role
    const mockPayload = btoa(JSON.stringify({ role: 'admin', exp: Date.now() / 1000 + 3600 }));
    const mockToken = `header.${mockPayload}.signature`;
    sessionStorage.setItem('token', mockToken);

    expect(service.getUserRole()).toBe('admin');
  });
});
```

### 6.4 Route Guard Tests

```typescript
// guards/auth.guard.spec.ts

describe('authGuard', () => {
  let authService: jasmine.SpyObj<AuthService>;
  let router: jasmine.SpyObj<Router>;

  beforeEach(() => {
    authService = jasmine.createSpyObj('AuthService', ['isAuthenticated']);
    router = jasmine.createSpyObj('Router', ['navigate']);

    TestBed.configureTestingModule({
      providers: [
        { provide: AuthService, useValue: authService },
        { provide: Router, useValue: router }
      ]
    });
  });

  it('should allow access when user is authenticated', () => {
    authService.isAuthenticated.and.returnValue(true);

    const result = TestBed.runInInjectionContext(() =>
      authGuard({} as any, { url: '/dashboard' } as any)
    );

    expect(result).toBeTrue();
  });

  it('should redirect to login when user is not authenticated', () => {
    authService.isAuthenticated.and.returnValue(false);

    const result = TestBed.runInInjectionContext(() =>
      authGuard({} as any, { url: '/dashboard' } as any)
    );

    expect(result).toBeFalse();
    expect(router.navigate).toHaveBeenCalledWith(
      ['/login'],
      jasmine.objectContaining({ queryParams: { returnUrl: '/dashboard' } })
    );
  });
});

// guards/role.guard.spec.ts

describe('roleGuard', () => {
  let authService: jasmine.SpyObj<AuthService>;
  let router: jasmine.SpyObj<Router>;

  beforeEach(() => {
    authService = jasmine.createSpyObj('AuthService', ['getUserRole']);
    router = jasmine.createSpyObj('Router', ['navigate']);

    TestBed.configureTestingModule({
      providers: [
        { provide: AuthService, useValue: authService },
        { provide: Router, useValue: router }
      ]
    });
  });

  it('should allow admin to access admin routes', () => {
    authService.getUserRole.and.returnValue('admin');

    const mockRoute = { data: { roles: ['admin'] } } as any;
    const result = TestBed.runInInjectionContext(() =>
      roleGuard(mockRoute, {} as any)
    );

    expect(result).toBeTrue();
  });

  it('should deny analyst access to admin-only routes', () => {
    authService.getUserRole.and.returnValue('analyst');

    const mockRoute = { data: { roles: ['admin'] } } as any;
    const result = TestBed.runInInjectionContext(() =>
      roleGuard(mockRoute, {} as any)
    );

    expect(result).toBeFalse();
    expect(router.navigate).toHaveBeenCalledWith(['/unauthorized']);
  });

  it('should allow analyst access to analyst routes', () => {
    authService.getUserRole.and.returnValue('analyst');

    const mockRoute = { data: { roles: ['admin', 'analyst'] } } as any;
    const result = TestBed.runInInjectionContext(() =>
      roleGuard(mockRoute, {} as any)
    );

    expect(result).toBeTrue();
  });
});
```

### 6.5 HTTP Interceptor Tests

```typescript
// interceptors/auth.interceptor.spec.ts

describe('authInterceptor', () => {
  let httpClient: HttpClient;
  let httpMock: HttpTestingController;
  let authService: jasmine.SpyObj<AuthService>;

  beforeEach(() => {
    authService = jasmine.createSpyObj('AuthService', ['getToken']);

    TestBed.configureTestingModule({
      imports: [HttpClientTestingModule],
      providers: [
        { provide: AuthService, useValue: authService },
        provideHttpClient(withInterceptors([authInterceptor]))
      ]
    });

    httpClient = TestBed.inject(HttpClient);
    httpMock = TestBed.inject(HttpTestingController);
  });

  it('should add Authorization header when token exists', () => {
    authService.getToken.and.returnValue('mock-jwt-token');

    httpClient.get('/api/test').subscribe();

    const req = httpMock.expectOne('/api/test');
    expect(req.request.headers.get('Authorization')).toBe('Bearer mock-jwt-token');
    req.flush({});
  });

  it('should NOT add Authorization header when no token', () => {
    authService.getToken.and.returnValue(null);

    httpClient.get('/api/test').subscribe();

    const req = httpMock.expectOne('/api/test');
    expect(req.request.headers.has('Authorization')).toBeFalse();
    req.flush({});
  });
});

// interceptors/error.interceptor.spec.ts

describe('errorInterceptor', () => {
  let httpClient: HttpClient;
  let httpMock: HttpTestingController;
  let router: jasmine.SpyObj<Router>;

  beforeEach(() => {
    router = jasmine.createSpyObj('Router', ['navigate']);

    TestBed.configureTestingModule({
      imports: [HttpClientTestingModule],
      providers: [
        { provide: Router, useValue: router },
        provideHttpClient(withInterceptors([errorInterceptor]))
      ]
    });

    httpClient = TestBed.inject(HttpClient);
    httpMock = TestBed.inject(HttpTestingController);
  });

  it('should redirect to login on 401 response', () => {
    httpClient.get('/api/test').subscribe({
      error: () => {
        expect(router.navigate).toHaveBeenCalledWith(['/login']);
      }
    });

    const req = httpMock.expectOne('/api/test');
    req.flush({ status: 'error', message: 'Unauthorized', code: 401 },
      { status: 401, statusText: 'Unauthorized' });
  });

  it('should redirect to unauthorized on 403 response', () => {
    httpClient.get('/api/admin/test').subscribe({
      error: () => {
        expect(router.navigate).toHaveBeenCalledWith(['/unauthorized']);
      }
    });

    const req = httpMock.expectOne('/api/admin/test');
    req.flush({ status: 'error', message: 'Forbidden', code: 403 },
      { status: 403, statusText: 'Forbidden' });
  });
});
```

### 6.6 Component Tests (Example: Vulnerability Form)

```typescript
// pages/vulnerability-form/vulnerability-form.component.spec.ts

describe('VulnerabilityFormComponent', () => {
  let component: VulnerabilityFormComponent;
  let fixture: ComponentFixture<VulnerabilityFormComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ReactiveFormsModule, VulnerabilityFormComponent],
      providers: [
        { provide: VulnerabilityService, useValue: jasmine.createSpyObj('VulnerabilityService', ['createVulnerability']) },
        { provide: Router, useValue: jasmine.createSpyObj('Router', ['navigate']) }
      ]
    }).compileComponents();

    fixture = TestBed.createComponent(VulnerabilityFormComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create the component', () => {
    expect(component).toBeTruthy();
  });

  it('should initialise form with empty values', () => {
    expect(component.vulnerabilityForm).toBeDefined();
    expect(component.vulnerabilityForm.get('title')?.value).toBe('');
    expect(component.vulnerabilityForm.get('cvss_score')?.value).toBe(0);
  });

  it('should mark form as invalid when required fields are empty', () => {
    expect(component.vulnerabilityForm.valid).toBeFalse();
  });

  it('should validate title minimum length', () => {
    const titleControl = component.vulnerabilityForm.get('title');
    titleControl?.setValue('Hi');
    expect(titleControl?.hasError('minlength')).toBeTrue();
  });

  it('should validate CVSS score range (max 10)', () => {
    const cvssControl = component.vulnerabilityForm.get('cvss_score');
    cvssControl?.setValue(15);
    expect(cvssControl?.hasError('max')).toBeTrue();
  });

  it('should validate CVSS score range (min 0)', () => {
    const cvssControl = component.vulnerabilityForm.get('cvss_score');
    cvssControl?.setValue(-1);
    expect(cvssControl?.hasError('min')).toBeTrue();
  });

  it('should accept valid CVSS score', () => {
    const cvssControl = component.vulnerabilityForm.get('cvss_score');
    cvssControl?.setValue(7.5);
    expect(cvssControl?.valid).toBeTrue();
  });

  it('should mark form as valid when all required fields are filled', () => {
    component.vulnerabilityForm.patchValue({
      title: 'Valid Vulnerability Title',
      description: 'A valid description that meets minimum length',
      severity: 'Critical',
      status: 'Open',
      cvss_score: 9.8,
      asset_name: 'test-server',
      asset_type: 'Server',
      department: 'Engineering',
      reported_by: 'tester'
    });
    expect(component.vulnerabilityForm.valid).toBeTrue();
  });
});
```

### 6.7 Running Angular Tests

```bash
# Run all unit tests
ng test

# Run tests with code coverage
ng test --code-coverage

# Run tests once (CI mode)
ng test --watch=false --browsers=ChromeHeadless

# Generate coverage report
ng test --code-coverage --watch=false
# Coverage report output: coverage/vulnguard/index.html
```

---

## 7. Frontend Testing – End-to-End (Cypress)

### 7.1 Cypress Setup

```bash
# Install Cypress
npm install cypress --save-dev

# Add to package.json scripts
{
  "scripts": {
    "cy:open": "cypress open",
    "cy:run": "cypress run"
  }
}
```

### 7.2 Key E2E Test Scenarios

```typescript
// cypress/e2e/auth.cy.ts

describe('Authentication', () => {
  it('should login with valid credentials and redirect to dashboard', () => {
    cy.visit('/login');
    cy.get('[data-cy=email-input]').type('admin@vulnguard.test');
    cy.get('[data-cy=password-input]').type('Admin@Secure123!');
    cy.get('[data-cy=login-button]').click();
    cy.url().should('include', '/dashboard');
    cy.get('[data-cy=welcome-message]').should('contain', 'admin');
  });

  it('should show error message for invalid credentials', () => {
    cy.visit('/login');
    cy.get('[data-cy=email-input]').type('wrong@email.com');
    cy.get('[data-cy=password-input]').type('wrongpassword');
    cy.get('[data-cy=login-button]').click();
    cy.get('[data-cy=error-message]').should('be.visible');
    cy.url().should('include', '/login');
  });

  it('should prevent access to protected routes when not logged in', () => {
    cy.visit('/dashboard');
    cy.url().should('include', '/login');
  });
});

// cypress/e2e/vulnerabilities.cy.ts

describe('Vulnerability Management', () => {
  beforeEach(() => {
    // Login as analyst before each test
    cy.login('analyst@vulnguard.test', 'Analyst@Secure123!');
  });

  it('should display vulnerability list with pagination', () => {
    cy.visit('/vulnerabilities');
    cy.get('[data-cy=vulnerability-card]').should('have.length.at.least', 1);
    cy.get('[data-cy=pagination]').should('be.visible');
  });

  it('should filter vulnerabilities by severity', () => {
    cy.visit('/vulnerabilities');
    cy.get('[data-cy=severity-filter]').select('Critical');
    cy.get('[data-cy=vulnerability-card]').each(($card) => {
      cy.wrap($card).find('[data-cy=severity-badge]').should('contain', 'Critical');
    });
  });

  it('should create a new vulnerability', () => {
    cy.visit('/vulnerabilities/new');
    cy.get('[data-cy=title-input]').type('E2E Test Vulnerability');
    cy.get('[data-cy=description-input]').type('This vulnerability was created by an E2E test');
    cy.get('[data-cy=severity-select]').select('High');
    cy.get('[data-cy=cvss-input]').clear().type('7.5');
    cy.get('[data-cy=asset-name-input]').type('test-server');
    cy.get('[data-cy=asset-type-select]').select('Server');
    cy.get('[data-cy=department-input]').type('Engineering');
    cy.get('[data-cy=reported-by-input]').type('e2e-tester');
    cy.get('[data-cy=submit-button]').click();
    cy.get('[data-cy=success-toast]').should('be.visible');
    cy.url().should('include', '/vulnerabilities/');
  });

  it('should validate form inputs and show errors', () => {
    cy.visit('/vulnerabilities/new');
    cy.get('[data-cy=submit-button]').click();
    cy.get('[data-cy=title-error]').should('be.visible');
    cy.get('[data-cy=severity-error]').should('be.visible');
    cy.get('[data-cy=cvss-input]').clear().type('15');
    cy.get('[data-cy=cvss-error]').should('contain', 'must be between 0 and 10');
  });
});

// cypress/e2e/dashboard.cy.ts

describe('Analytics Dashboard', () => {
  beforeEach(() => {
    cy.login('analyst@vulnguard.test', 'Analyst@Secure123!');
  });

  it('should display dashboard with charts', () => {
    cy.visit('/dashboard');
    cy.get('[data-cy=severity-chart]').should('be.visible');
    cy.get('[data-cy=trend-chart]').should('be.visible');
    cy.get('[data-cy=department-chart]').should('be.visible');
    cy.get('[data-cy=compliance-indicator]').should('be.visible');
  });

  it('should display KPI summary cards', () => {
    cy.visit('/dashboard');
    cy.get('[data-cy=kpi-total]').should('be.visible');
    cy.get('[data-cy=kpi-critical]').should('be.visible');
    cy.get('[data-cy=kpi-overdue]').should('be.visible');
    cy.get('[data-cy=kpi-compliance]').should('be.visible');
  });
});
```

### 7.3 Cypress Custom Commands

```typescript
// cypress/support/commands.ts

Cypress.Commands.add('login', (email: string, password: string) => {
  cy.request({
    method: 'POST',
    url: 'http://localhost:5000/api/v1/auth/login',
    body: { email, password }
  }).then((response) => {
    window.sessionStorage.setItem('token', response.body.data.token);
  });
});
```

---

## 8. Evidence Requirements for Submission

### 8.1 Backend Testing Evidence (CW1)

| Evidence Item | Format | Description |
|---------------|--------|-------------|
| Postman Collection Export | `.json` file | Complete collection with all test folders, pre-request scripts, and test scripts |
| Postman Environment Export | `.json` file | Environment variables configuration |
| Collection Runner Screenshot | `.png` / `.pdf` | Screenshot showing all tests passing in Postman Collection Runner |
| Newman CLI Output | Terminal screenshot / `.html` report | Newman execution output showing pass/fail summary |
| Newman HTML Report | `.html` file | Generated by `newman-reporter-htmlextra` showing detailed test results |
| Individual Test Screenshots | `.png` files | At least 5 screenshots showing specific test successes/failures |

### 8.2 Frontend Testing Evidence (CW2)

| Evidence Item | Format | Description |
|---------------|--------|-------------|
| `ng test` Output | Terminal screenshot | Karma test runner output showing all tests passing |
| Code Coverage Report | `.html` report / screenshot | Coverage summary from `istanbul` showing ≥ 80% coverage |
| Component Test Evidence | Screenshots | At least 3 component test runs showing form validation testing |
| Service Test Evidence | Screenshots | At least 2 service test runs showing HTTP mock testing |
| Guard Test Evidence | Screenshots | Auth guard and role guard test results |
| Interceptor Test Evidence | Screenshots | Auth interceptor and error interceptor test results |

### 8.3 Evidence Collection Script

```bash
#!/bin/bash
# generate-test-evidence.sh

echo "=== VulnGuard Test Evidence Generator ==="

# Backend: Run Newman and generate reports
echo "Running Postman tests via Newman..."
newman run tests/postman/VulnGuard.postman_collection.json \
  -e tests/postman/VulnGuard.postman_environment.json \
  --reporters cli,htmlextra,json \
  --reporter-htmlextra-export evidence/backend/newman-report.html \
  --reporter-json-export evidence/backend/newman-results.json \
  2>&1 | tee evidence/backend/newman-output.txt

echo "Newman report generated at evidence/backend/newman-report.html"

# Frontend: Run Angular tests with coverage
echo "Running Angular unit tests..."
cd frontend
ng test --watch=false --browsers=ChromeHeadless --code-coverage \
  2>&1 | tee ../evidence/frontend/karma-output.txt

echo "Coverage report at frontend/coverage/vulnguard/index.html"
cp -r coverage/vulnguard ../evidence/frontend/coverage-report

echo "=== Evidence generation complete ==="
```

---

## 9. Test Data Management

### 9.1 Seed Data Script

```python
# seeds/seed_data.py

"""
Database seeding script for VulnGuard.
Populates the database with realistic test data for development and testing.
"""

import random
from datetime import datetime, timedelta
from bson import ObjectId
import bcrypt

def seed_database(db):
    """Seed the database with test data."""

    # Clear existing data
    db.vulnerabilities.drop()
    db.users.drop()

    # Seed users
    users = [
        {
            "_id": ObjectId(),
            "username": "admin",
            "email": "admin@vulnguard.test",
            "password_hash": bcrypt.hashpw("Admin@Secure123!".encode(), bcrypt.gensalt()).decode(),
            "role": "admin",
            "is_active": True,
            "created_at": datetime.utcnow()
        },
        {
            "_id": ObjectId(),
            "username": "analyst1",
            "email": "analyst@vulnguard.test",
            "password_hash": bcrypt.hashpw("Analyst@Secure123!".encode(), bcrypt.gensalt()).decode(),
            "role": "analyst",
            "is_active": True,
            "created_at": datetime.utcnow()
        },
        {
            "_id": ObjectId(),
            "username": "guest1",
            "email": "guest@vulnguard.test",
            "password_hash": bcrypt.hashpw("Guest@Secure123!".encode(), bcrypt.gensalt()).decode(),
            "role": "guest",
            "is_active": True,
            "created_at": datetime.utcnow()
        }
    ]
    db.users.insert_many(users)

    # Seed vulnerabilities (25+ documents with sub-documents)
    severities = ["Critical", "High", "Medium", "Low", "Informational"]
    statuses = ["Open", "In Progress", "Resolved", "Closed", "Deferred"]
    asset_types = ["Server", "Workstation", "Network Device", "Application", "Database", "Cloud Service", "IoT Device"]
    departments = ["Engineering", "Finance", "Operations", "IT", "HR", "Marketing", "Legal"]
    attack_vectors = ["Network", "Adjacent", "Local", "Physical"]
    exploitabilities = ["Unproven", "Proof-of-Concept", "Functional", "High"]

    vulnerabilities = []
    for i in range(30):
        severity = random.choice(severities)
        cvss = round(random.uniform(0, 10), 1)
        status = random.choice(statuses)
        created = datetime.utcnow() - timedelta(days=random.randint(1, 180))

        vuln = {
            "_id": ObjectId(),
            "title": f"Vulnerability {i + 1}: {random.choice(['SQL Injection', 'XSS', 'CSRF', 'RCE', 'Buffer Overflow', 'Path Traversal', 'SSRF', 'XXE', 'Insecure Deserialization', 'Broken Auth'])}",
            "description": f"Detailed description of vulnerability {i + 1} affecting the target system.",
            "cve_id": f"CVE-2025-{10000 + i}",
            "severity": severity,
            "status": status,
            "cvss_score": cvss,
            "asset_name": f"asset-{random.randint(1, 20):02d}.example.com",
            "asset_type": random.choice(asset_types),
            "department": random.choice(departments),
            "affected_versions": [f"{random.randint(1, 5)}.{random.randint(0, 9)}.{random.randint(0, 9)}"],
            "attack_vector": random.choice(attack_vectors),
            "exploitability": random.choice(exploitabilities),
            "patch_deadline": (created + timedelta(days=random.randint(7, 90))).isoformat(),
            "patch_applied": status in ["Resolved", "Closed"],
            "assigned_to": random.choice(["j.smith", "a.jones", "m.chen", "s.patel", None]),
            "reported_by": random.choice(["security-scanner", "analyst1", "pentest-team", "bug-bounty"]),
            "risk_score": round(cvss * random.uniform(1.0, 5.0), 2),
            "remediation_steps": [
                {
                    "_id": ObjectId(),
                    "step_number": 1,
                    "action": f"Apply security patch for vulnerability {i + 1}",
                    "assigned_to": "j.smith",
                    "status": random.choice(["Pending", "In Progress", "Completed"]),
                    "due_date": (created + timedelta(days=random.randint(3, 30))).isoformat(),
                    "completed_date": None,
                    "notes": "Follow vendor advisory"
                },
                {
                    "_id": ObjectId(),
                    "step_number": 2,
                    "action": f"Verify patch deployment and run validation tests",
                    "assigned_to": "a.jones",
                    "status": "Pending",
                    "due_date": (created + timedelta(days=random.randint(14, 45))).isoformat(),
                    "completed_date": None,
                    "notes": "Requires staging environment testing"
                }
            ],
            "activity_log": [
                {
                    "_id": ObjectId(),
                    "timestamp": created.isoformat(),
                    "action": "Vulnerability discovered",
                    "performed_by": "security-scanner",
                    "details": f"Vulnerability {i + 1} identified during routine scan",
                    "previous_value": None,
                    "new_value": None
                }
            ],
            "created_at": created,
            "updated_at": created + timedelta(days=random.randint(0, 30)),
            "created_by": "security-scanner"
        }
        vulnerabilities.append(vuln)

    db.vulnerabilities.insert_many(vulnerabilities)

    print(f"✅ Seeded {len(users)} users and {len(vulnerabilities)} vulnerabilities")
```

### 9.2 Test Data Reset

Before each Postman collection run, the test data should be in a known state. Include a "Seed Test Data" request that calls a dedicated seeding endpoint (development only):

```python
# Only available in development mode
@app.route('/api/v1/dev/seed', methods=['POST'])
def seed_test_data():
    if not app.config.get('DEBUG'):
        return jsonify({"status": "error", "message": "Not available in production", "code": 403}), 403
    seed_database(db)
    return jsonify({"status": "success", "message": "Test data seeded successfully"}), 200
```

---

## 10. Continuous Quality Checklist

### Pre-Submission Quality Gate

Use this checklist before final submission:

#### Backend

- [ ] All 34 API endpoints implemented and functional
- [ ] All validation rules enforced (type, range, enum, required, date, ObjectId)
- [ ] All HTTP status codes used correctly (200, 201, 204, 400, 401, 403, 404, 422, 500)
- [ ] All error responses follow `{ status, message, code }` format
- [ ] JWT authentication working on all protected routes
- [ ] RBAC enforcement verified for Admin, Analyst, Guest
- [ ] Sub-document CRUD using `$push`, `$pull`, `$set`, positional operator
- [ ] All 9 analytics endpoints using aggregation pipelines
- [ ] Aggregation pipelines use `$match`, `$group`, `$project`, `$unwind`, `$sort`
- [ ] Pagination, filtering, sorting, and search working
- [ ] Postman collection has ≥ 60 test requests
- [ ] Postman collection has pre-request scripts for auto token injection
- [ ] Postman test scripts validate status codes, schemas, response times
- [ ] Newman CLI runs all tests successfully
- [ ] Newman HTML report generated

#### Frontend

- [ ] Angular 17+ with strict mode enabled
- [ ] All forms use Reactive Forms with validation
- [ ] Route Guards implemented (AuthGuard, RoleGuard, GuestGuard)
- [ ] HTTP Interceptor attaching JWT tokens
- [ ] Error Interceptor handling 401/403
- [ ] Chart.js dashboard with ≥ 4 chart types
- [ ] Vulnerability list with pagination, filtering, sorting, search
- [ ] Sub-document management UI (remediation steps, activity log)
- [ ] Admin panel with user management
- [ ] Unit tests passing for services, guards, interceptors, components
- [ ] Code coverage ≥ 80%
- [ ] TypeScript interfaces for all data models
- [ ] `data-cy` attributes on all testable elements

#### Documentation

- [ ] PRD.md complete and aligned with rubric
- [ ] AGENTS.md provides full context for AI assistants
- [ ] API_SPECIFICATION.md covers all 34 endpoints
- [ ] QA_STRATEGY.md defines testing approach with evidence requirements
- [ ] README.md includes setup instructions

---

*End of Quality Assurance & Automated Testing Strategy*
