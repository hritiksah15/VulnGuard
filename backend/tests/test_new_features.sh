#!/usr/bin/env bash
# ── VulnGuard New Feature Test Suite ────────────────────────────────────
# Tests all features added in the improvement round:
#   1. Login & get tokens
#   2. Logout + token blacklist
#   3. x-access-token header support
#   4. Advanced filters ($in, $regex)
#   5. Cursor-based pagination
#   6. Geospatial /nearby endpoint
#   7. $out generate-report endpoint
#   8. Get reports endpoint
set -euo pipefail
BASE="http://localhost:5001/api/v1"
PASS=0
FAIL=0
TOTAL=0

ok()   { PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); echo "  ✅ PASS: $1"; }
fail() { FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); echo "  ❌ FAIL: $1 (got $2)"; }

check_status() {
    local label="$1" expected="$2" actual="$3"
    if [ "$actual" = "$expected" ]; then ok "$label"; else fail "$label" "status=$actual expected=$expected"; fi
}

check_json() {
    local label="$1" expected="$2" actual="$3"
    if echo "$actual" | grep -q "$expected"; then ok "$label"; else fail "$label" "$actual"; fi
}

echo ""
echo "═══════════════════════════════════════════════"
echo "  VulnGuard – New Feature Test Suite"
echo "═══════════════════════════════════════════════"

# ── 1. Login ────────────────────────────────────────────────────────────
echo ""
echo "▸ 1. Login (get admin token)"
RESP=$(curl -s -w "\n%{http_code}" -X POST "$BASE/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@vulnguard.test","password":"Admin@Secure123!"}')
STATUS=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
check_status "Admin login returns 200" "200" "$STATUS"
TOKEN=$(echo "$BODY" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['token'])" 2>/dev/null || echo "")
if [ -n "$TOKEN" ]; then ok "Token extracted"; else fail "Token extraction" "empty"; fi

echo ""
echo "▸ 1b. Login analyst"
RESP=$(curl -s -w "\n%{http_code}" -X POST "$BASE/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"analyst@vulnguard.test","password":"Analyst@Secure123!"}')
ANALYST_TOKEN=$(echo "$RESP" | sed '$d' | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['token'])" 2>/dev/null || echo "")

# ── 2. x-access-token header ───────────────────────────────────────────
echo ""
echo "▸ 2. x-access-token header support"
RESP=$(curl -s -w "\n%{http_code}" -X GET "$BASE/auth/profile" \
  -H "x-access-token: $TOKEN")
STATUS=$(echo "$RESP" | tail -1)
check_status "Profile via x-access-token returns 200" "200" "$STATUS"
check_json "Response has username" '"username"' "$(echo "$RESP" | sed '$d')"

# ── 3. Logout + Blacklist ──────────────────────────────────────────────
echo ""
echo "▸ 3. Logout & token blacklist"
# Get a fresh token for logout testing
RESP=$(curl -s -w "\n%{http_code}" -X POST "$BASE/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@vulnguard.test","password":"Admin@Secure123!"}')
LOGOUT_TOKEN=$(echo "$RESP" | sed '$d' | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['token'])" 2>/dev/null)

RESP=$(curl -s -w "\n%{http_code}" -X POST "$BASE/auth/logout" \
  -H "x-access-token: $LOGOUT_TOKEN")
STATUS=$(echo "$RESP" | tail -1)
check_status "Logout returns 200" "200" "$STATUS"
check_json "Logout message" "Logged out successfully" "$(echo "$RESP" | sed '$d')"

# Try using the blacklisted token
RESP=$(curl -s -w "\n%{http_code}" -X GET "$BASE/auth/profile" \
  -H "x-access-token: $LOGOUT_TOKEN")
STATUS=$(echo "$RESP" | tail -1)
check_status "Blacklisted token returns 401" "401" "$STATUS"
check_json "Blacklist message" "Token has been cancelled" "$(echo "$RESP" | sed '$d')"

# ── 4. Advanced Filters ────────────────────────────────────────────────
echo ""
echo "▸ 3b. Re-login admin (token was blacklisted)"
RESP=$(curl -s -w "\n%{http_code}" -X POST "$BASE/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@vulnguard.test","password":"Admin@Secure123!"}')
TOKEN=$(echo "$RESP" | sed '$d' | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['token'])" 2>/dev/null)
check_status "Re-login returns 200" "200" "$(echo "$RESP" | tail -1)"

echo ""
echo "▸ 4. Advanced filters"

# $in filter: severity_in=Critical,High
RESP=$(curl -s -w "\n%{http_code}" "$BASE/vulnerabilities/?severity_in=Critical,High&per_page=5")
STATUS=$(echo "$RESP" | tail -1)
check_status "severity_in filter returns 200" "200" "$STATUS"

# $regex filter
RESP=$(curl -s -w "\n%{http_code}" "$BASE/vulnerabilities/?title_regex=SQL.*Injection")
STATUS=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
check_status "title_regex filter returns 200" "200" "$STATUS"
check_json "Regex matches SQL Injection" "SQL Injection" "$BODY"

# $in with status_in
RESP=$(curl -s -w "\n%{http_code}" "$BASE/vulnerabilities/?status_in=Open,In%20Progress&per_page=3")
STATUS=$(echo "$RESP" | tail -1)
check_status "status_in filter returns 200" "200" "$STATUS"

# ── 5. Cursor-based Pagination ─────────────────────────────────────────
echo ""
echo "▸ 5. Cursor-based pagination"

# Get first page
RESP=$(curl -s "$BASE/vulnerabilities/?per_page=3&sort_order=desc")
FIRST_IDS=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin)['data']; [print(i['_id']) for i in d]" 2>/dev/null)
LAST_ID=$(echo "$FIRST_IDS" | tail -1)

# Get next page using ?after=
RESP=$(curl -s -w "\n%{http_code}" "$BASE/vulnerabilities/?per_page=3&sort_order=desc&after=$LAST_ID")
STATUS=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
check_status "Cursor pagination returns 200" "200" "$STATUS"
check_json "Has next_after field" "next_after" "$BODY"

# Verify no overlap
SECOND_IDS=$(echo "$BODY" | python3 -c "import sys,json; d=json.load(sys.stdin)['data']; [print(i['_id']) for i in d]" 2>/dev/null)
OVERLAP=$(comm -12 <(echo "$FIRST_IDS" | sort) <(echo "$SECOND_IDS" | sort) | wc -l | tr -d ' ')
if [ "$OVERLAP" = "0" ]; then ok "No duplicate IDs between pages"; else fail "Duplicate IDs found" "$OVERLAP overlaps"; fi

# ── 6. Geospatial /nearby ──────────────────────────────────────────────
echo ""
echo "▸ 6. Geospatial nearby endpoint"

# Belfast coordinates
RESP=$(curl -s -w "\n%{http_code}" "$BASE/vulnerabilities/nearby?lng=-5.93&lat=54.60&radius=100&limit=5")
STATUS=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
check_status "Nearby returns 200" "200" "$STATUS"
check_json "Has distance_km" "distance_km" "$BODY"

# Wide search to get results
RESP=$(curl -s "$BASE/vulnerabilities/nearby?lng=-5.93&lat=54.60&radius=5000&limit=3")
COUNT=$(echo "$RESP" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['data']))" 2>/dev/null || echo "0")
if [ "$COUNT" -gt "0" ]; then ok "Nearby returns $COUNT results with wide radius"; else fail "Nearby returns no results" "count=$COUNT"; fi

# Missing params → 400
RESP=$(curl -s -w "\n%{http_code}" "$BASE/vulnerabilities/nearby?lng=-5.93")
STATUS=$(echo "$RESP" | tail -1)
check_status "Nearby without lat returns 400" "400" "$STATUS"

# ── 6b. $or Filter ─────────────────────────────────────────────────────
echo ""
echo "▸ 6b. \$or filter"

RESP=$(curl -s -w "\n%{http_code}" "$BASE/vulnerabilities/?or_severity=Critical&or_status=Open&per_page=5")
STATUS=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
check_status "\$or filter returns 200" "200" "$STATUS"
OR_COUNT=$(echo "$BODY" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['data']))" 2>/dev/null || echo "0")
if [ "$OR_COUNT" -gt "0" ]; then ok "\$or filter returns $OR_COUNT results"; else fail "\$or filter returns no results" "count=$OR_COUNT"; fi

# Verify results match $or condition
VALID=$(echo "$BODY" | python3 -c "
import sys,json
items = json.load(sys.stdin)['data']
print('yes' if all(i['severity']=='Critical' or i['status']=='Open' for i in items) else 'no')
" 2>/dev/null || echo "no")
if [ "$VALID" = "yes" ]; then ok "\$or results all match condition"; else fail "\$or results include non-matching items" "$VALID"; fi

# ── 6c. Bulk Create (insert_many) ──────────────────────────────────────
echo ""
echo "▸ 6c. Bulk create (insert_many)"

RESP=$(curl -s -w "\n%{http_code}" -X POST "$BASE/vulnerabilities/bulk" \
  -H "x-access-token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerabilities": [
      {"title":"Bulk Test Alpha","description":"First bulk item for testing.","severity":"High","status":"Open","cvss_score":7.5,"asset_name":"bulk-srv-1","asset_type":"Server","department":"QA","reported_by":"test-runner"},
      {"title":"Bulk Test Beta","description":"Second bulk item for testing.","severity":"Low","status":"Open","cvss_score":3.2,"asset_name":"bulk-srv-2","asset_type":"Server","department":"QA","reported_by":"test-runner"}
    ]
  }')
STATUS=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
check_status "Bulk create returns 201" "201" "$STATUS"
BULK_COUNT=$(echo "$BODY" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['data']))" 2>/dev/null || echo "0")
if [ "$BULK_COUNT" = "2" ]; then ok "Bulk create returned 2 documents"; else fail "Bulk create count wrong" "got=$BULK_COUNT"; fi
check_json "Bulk create message has count" "2 vulnerabilities created" "$BODY"

# Bulk create - too few items → 400
RESP=$(curl -s -w "\n%{http_code}" -X POST "$BASE/vulnerabilities/bulk" \
  -H "x-access-token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"vulnerabilities":[{"title":"Only One","description":"Should fail min 2.","severity":"Low","status":"Open","cvss_score":1.0,"asset_name":"x","asset_type":"Server","department":"IT","reported_by":"t"}]}')
STATUS=$(echo "$RESP" | tail -1)
check_status "Bulk create <2 items returns 400" "400" "$STATUS"

# Bulk create - validation error → 422
RESP=$(curl -s -w "\n%{http_code}" -X POST "$BASE/vulnerabilities/bulk" \
  -H "x-access-token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"vulnerabilities":[{"title":"Good","description":"Valid item here.","severity":"High","status":"Open","cvss_score":7.0,"asset_name":"srv","asset_type":"Server","department":"IT","reported_by":"t"},{"title":"Bad"}]}')
STATUS=$(echo "$RESP" | tail -1)
check_status "Bulk create with invalid item returns 422" "422" "$STATUS"

# ── 7. Generate Report ($out) ──────────────────────────────────────────
echo ""
echo "▸ 7. Generate report (\$out aggregation)"

RESP=$(curl -s -w "\n%{http_code}" -X POST "$BASE/analytics/generate-report" \
  -H "x-access-token: $TOKEN")
STATUS=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
check_status "Generate report returns 201" "201" "$STATUS"
check_json "Report has department field" "department" "$BODY"
check_json "Report has severity field" "severity" "$BODY"
ROW_COUNT=$(echo "$BODY" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['data']))" 2>/dev/null || echo "0")
if [ "$ROW_COUNT" -gt "0" ]; then ok "Report has $ROW_COUNT rows"; else fail "Report has 0 rows" "empty"; fi

# ── 8. Get Reports ─────────────────────────────────────────────────────
echo ""
echo "▸ 8. Get reports collection"

RESP=$(curl -s -w "\n%{http_code}" "$BASE/analytics/reports" \
  -H "x-access-token: $TOKEN")
STATUS=$(echo "$RESP" | tail -1)
check_status "Get reports returns 200" "200" "$STATUS"

# ── 9. Existing features still work ────────────────────────────────────
echo ""
echo "▸ 9. Regression – existing features"

# Vulnerabilities list
RESP=$(curl -s -w "\n%{http_code}" "$BASE/vulnerabilities/?per_page=2")
STATUS=$(echo "$RESP" | tail -1)
check_status "GET vulnerabilities returns 200" "200" "$STATUS"

# Single vulnerability
VULN_ID=$(curl -s "$BASE/vulnerabilities/?per_page=1" | python3 -c "import sys,json; print(json.load(sys.stdin)['data'][0]['_id'])" 2>/dev/null)
RESP=$(curl -s -w "\n%{http_code}" "$BASE/vulnerabilities/$VULN_ID")
STATUS=$(echo "$RESP" | tail -1)
check_status "GET single vuln returns 200" "200" "$STATUS"

# Analytics
RESP=$(curl -s -w "\n%{http_code}" "$BASE/analytics/severity-distribution" \
  -H "x-access-token: $TOKEN")
STATUS=$(echo "$RESP" | tail -1)
check_status "Analytics severity-distribution returns 200" "200" "$STATUS"

RESP=$(curl -s -w "\n%{http_code}" "$BASE/analytics/summary" \
  -H "x-access-token: $TOKEN")
STATUS=$(echo "$RESP" | tail -1)
check_status "Analytics summary returns 200" "200" "$STATUS"

# ═══ Summary ════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════"
echo "  Results: $PASS passed, $FAIL failed, $TOTAL total"
echo "═══════════════════════════════════════════════"
echo ""

if [ "$FAIL" -gt 0 ]; then exit 1; fi
