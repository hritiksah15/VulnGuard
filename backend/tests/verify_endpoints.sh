#!/bin/bash
# VulnGuard API – Full Endpoint Verification Script
BASE="http://localhost:5001/api/v1"
PASS=0
FAIL=0
TOTAL=0

check() {
    local desc="$1"; shift
    local expected="$1"; shift
    local method="$1"; shift
    local url="$1"; shift
    TOTAL=$((TOTAL+1))
    local resp
    resp=$(curl -s -o /tmp/resp_body -w "%{http_code}" -X "$method" "$url" "$@")
    if [ "$resp" = "$expected" ]; then
        PASS=$((PASS+1))
        printf "  ✅ %-55s %s\n" "$desc" "$resp"
    else
        FAIL=$((FAIL+1))
        printf "  ❌ %-55s got %s (expected %s)\n" "$desc" "$resp" "$expected"
    fi
}

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  VulnGuard API – Full Endpoint Verification"
echo "═══════════════════════════════════════════════════════════"

# Tokens
ADMIN_TOKEN=$(curl -s -X POST "$BASE/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@vulnguard.test","password":"Admin@Secure123!"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['token'])")

ANALYST_TOKEN=$(curl -s -X POST "$BASE/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"analyst@vulnguard.test","password":"Analyst@Secure123!"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['token'])")

GUEST_TOKEN=$(curl -s -X POST "$BASE/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"guest@vulnguard.test","password":"Guest@Secure123!"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['token'])")

echo ""
echo "── Health (1) ──"
check "GET /health" 200 GET "$BASE/health"

echo ""
echo "── Authentication (6) ──"

TS=$(date +%s)
check "POST /auth/register" 201 POST "$BASE/auth/register" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"vtest_${TS}\",\"email\":\"vtest_${TS}@test.com\",\"password\":\"Test@Secure123!\"}"

check "POST /auth/login" 200 POST "$BASE/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@vulnguard.test","password":"Admin@Secure123!"}'

check "GET /auth/profile" 200 GET "$BASE/auth/profile" \
  -H "x-access-token: $ADMIN_TOKEN"

check "PUT /auth/profile" 200 PUT "$BASE/auth/profile" \
  -H "x-access-token: $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin_user"}'

check "POST /auth/refresh" 200 POST "$BASE/auth/refresh" \
  -H "x-access-token: $ADMIN_TOKEN"

check "PUT /auth/change-password (400)" 400 PUT "$BASE/auth/change-password" \
  -H "x-access-token: $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"current_password":"Wrong!","new_password":"New@Secure123!"}'

echo ""
echo "── Vulnerabilities (5) ──"

VULN_ID=$(curl -s -X POST "$BASE/vulnerabilities/" \
  -H "x-access-token: $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"vulnerability_title":"Endpoint Verification Test Vulnerability","description":"This vulnerability was created by the verification script to test all API endpoints","severity":"High","status":"Open","cvss_score":7.5,"asset_name":"test-server-01.internal","asset_type":"Server","vulnerability_type":"Software","discovery_method":"Scan","department":"IT","reported_by":"verify-script"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['_id'])" 2>/dev/null)

if [ -n "$VULN_ID" ]; then
  TOTAL=$((TOTAL+1)); PASS=$((PASS+1))
  printf "  ✅ %-55s %s\n" "POST /vulnerabilities" "201"
else
  TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
  printf "  ❌ %-55s %s\n" "POST /vulnerabilities" "FAIL"
fi

check "GET /vulnerabilities" 200 GET "$BASE/vulnerabilities/?page=1&per_page=5"

check "GET /vulnerabilities/:id" 200 GET "$BASE/vulnerabilities/$VULN_ID"

check "PUT /vulnerabilities/:id" 200 PUT "$BASE/vulnerabilities/$VULN_ID" \
  -H "x-access-token: $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"status":"In Progress"}'

# Delete tested at end

echo ""
echo "── Remediation Steps (5) ──"

STEP_ID=$(curl -s -X POST "$BASE/vulnerabilities/$VULN_ID/remediation-steps" \
  -H "x-access-token: $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"step_number":1,"step_description":"Patch it","recommended_by":"j.smith","status":"Pending","due_date":"2026-06-01T00:00:00Z"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['_id'])" 2>/dev/null)

if [ -n "$STEP_ID" ]; then
  TOTAL=$((TOTAL+1)); PASS=$((PASS+1))
  printf "  ✅ %-55s %s\n" "POST /remediation-steps" "201"
else
  TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
  printf "  ❌ %-55s %s\n" "POST /remediation-steps" "FAIL"
fi

check "GET /remediation-steps (all)" 200 GET "$BASE/vulnerabilities/$VULN_ID/remediation-steps" \
  -H "x-access-token: $ADMIN_TOKEN"

check "GET /remediation-steps/:sid" 200 GET "$BASE/vulnerabilities/$VULN_ID/remediation-steps/$STEP_ID" \
  -H "x-access-token: $ADMIN_TOKEN"

check "PUT /remediation-steps/:sid" 200 PUT "$BASE/vulnerabilities/$VULN_ID/remediation-steps/$STEP_ID" \
  -H "x-access-token: $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"status":"In Progress"}'

check "DELETE /remediation-steps/:sid" 204 DELETE "$BASE/vulnerabilities/$VULN_ID/remediation-steps/$STEP_ID" \
  -H "x-access-token: $ADMIN_TOKEN"

echo ""
echo "── Activity Log (4) ──"

LOG_ID=$(curl -s -X POST "$BASE/vulnerabilities/$VULN_ID/activity-log" \
  -H "x-access-token: $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"Test log","details":"Verification"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['_id'])" 2>/dev/null)

if [ -n "$LOG_ID" ]; then
  TOTAL=$((TOTAL+1)); PASS=$((PASS+1))
  printf "  ✅ %-55s %s\n" "POST /activity-log" "201"
else
  TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
  printf "  ❌ %-55s %s\n" "POST /activity-log" "FAIL"
fi

check "GET /activity-log (all)" 200 GET "$BASE/vulnerabilities/$VULN_ID/activity-log" \
  -H "x-access-token: $ADMIN_TOKEN"

check "GET /activity-log/:lid" 200 GET "$BASE/vulnerabilities/$VULN_ID/activity-log/$LOG_ID" \
  -H "x-access-token: $ADMIN_TOKEN"

check "DELETE /activity-log/:lid" 204 DELETE "$BASE/vulnerabilities/$VULN_ID/activity-log/$LOG_ID" \
  -H "x-access-token: $ADMIN_TOKEN"

echo ""
echo "── Analytics (9) ──"
check "GET /analytics/severity-distribution" 200 GET "$BASE/analytics/severity-distribution" -H "x-access-token: $ADMIN_TOKEN"
check "GET /analytics/department-risk" 200 GET "$BASE/analytics/department-risk" -H "x-access-token: $ADMIN_TOKEN"
check "GET /analytics/overdue-patches" 200 GET "$BASE/analytics/overdue-patches" -H "x-access-token: $ADMIN_TOKEN"
check "GET /analytics/patch-compliance" 200 GET "$BASE/analytics/patch-compliance" -H "x-access-token: $ADMIN_TOKEN"
check "GET /analytics/vulnerability-trends" 200 GET "$BASE/analytics/vulnerability-trends?months=6" -H "x-access-token: $ADMIN_TOKEN"
check "GET /analytics/top-affected-assets" 200 GET "$BASE/analytics/top-affected-assets?limit=5" -H "x-access-token: $ADMIN_TOKEN"
check "GET /analytics/mean-time-to-remediation" 200 GET "$BASE/analytics/mean-time-to-remediation" -H "x-access-token: $ADMIN_TOKEN"
check "GET /analytics/risk-scores" 200 GET "$BASE/analytics/risk-scores" -H "x-access-token: $ADMIN_TOKEN"
check "GET /analytics/summary" 200 GET "$BASE/analytics/summary" -H "x-access-token: $ADMIN_TOKEN"

echo ""
echo "── Admin (5) ──"
check "GET /admin/users" 200 GET "$BASE/admin/users" -H "x-access-token: $ADMIN_TOKEN"

TEST_UID=$(curl -s "$BASE/admin/users?per_page=100" \
  -H "x-access-token: $ADMIN_TOKEN" \
  | python3 -c "
import sys,json
for u in json.load(sys.stdin)['data']:
    if 'vtest_' in u.get('username',''):
        print(u['_id']); break
" 2>/dev/null)

if [ -n "$TEST_UID" ]; then
  check "GET /admin/users/:id" 200 GET "$BASE/admin/users/$TEST_UID" -H "x-access-token: $ADMIN_TOKEN"
  check "PUT /admin/users/:id/role" 200 PUT "$BASE/admin/users/$TEST_UID/role" -H "x-access-token: $ADMIN_TOKEN" -H "Content-Type: application/json" -d '{"role":"guest"}'
  check "PUT /admin/users/:id/status" 200 PUT "$BASE/admin/users/$TEST_UID/status" -H "x-access-token: $ADMIN_TOKEN" -H "Content-Type: application/json" -d '{"is_active":false}'
  check "DELETE /admin/users/:id" 204 DELETE "$BASE/admin/users/$TEST_UID" -H "x-access-token: $ADMIN_TOKEN"
else
  echo "  ⚠️  Test user not found — skipping admin detail tests"
  TOTAL=$((TOTAL+4)); FAIL=$((FAIL+4))
fi

echo ""
echo "── Cleanup ──"
check "DELETE /vulnerabilities/:id" 204 DELETE "$BASE/vulnerabilities/$VULN_ID" -H "x-access-token: $ADMIN_TOKEN"

echo ""
echo "═══════════════════════════════════════════════════════════"
printf "  Results: %d/%d passed" "$PASS" "$TOTAL"
[ "$FAIL" -gt 0 ] && printf " (%d FAILED)" "$FAIL"
echo ""
echo "═══════════════════════════════════════════════════════════"
