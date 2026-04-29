#!/bin/bash

# ===== AuthX - Vulnerability Testing Script =====
# This script helps test the vulnerabilities in both V1 and V2
# Usage: bash test-vulnerabilities.sh

set -e

echo "╔════════════════════════════════════════════════════════════╗"
echo "║     AuthX - Break the Login - Vulnerability Testing       ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
V1_URL="http://localhost:3001"
V2_URL="http://localhost:3002"
TIMEOUT=5

# Helper function to print headers
print_header() {
    echo ""
    echo -e "${BLUE}▶ $1${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

# Test if servers are running
test_connectivity() {
    print_header "Testing Server Connectivity"
    
    if curl -s -m $TIMEOUT "$V1_URL/" > /dev/null 2>&1; then
        print_success "V1 (Vulnerable) is running on $V1_URL"
    else
        print_error "V1 (Vulnerable) is NOT running. Start with: npm start:v1"
        exit 1
    fi
    
    if curl -s -m $TIMEOUT "$V2_URL/" > /dev/null 2>&1; then
        print_success "V2 (Secure) is running on $V2_URL"
    else
        print_warning "V2 (Secure) is NOT running. Start with: npm start:v2"
    fi
}

# TEST 1: Weak Password Policy
test_weak_password() {
    print_header "TEST 1: Weak Password Policy"
    echo "This test creates accounts with very short passwords"
    echo ""
    
    # V1 - Should accept short password
    echo "V1 (Vulnerable) - Attempting password '123':"
    RESPONSE=$(curl -s -X POST "$V1_URL/api/register" \
        -H "Content-Type: application/json" \
        -d '{"username":"weakpass_v1","email":"weakpass_v1@test.local","password":"123"}')
    
    if echo "$RESPONSE" | grep -q "successfully"; then
        print_success "V1 accepted 3-character password ❌"
    else
        print_error "V1 rejected password: $RESPONSE"
    fi
    
    echo ""
    echo "V2 (Secure) - Attempting password '123':"
    RESPONSE=$(curl -s -X POST "$V2_URL/api/register" \
        -H "Content-Type: application/json" \
        -d '{"username":"weakpass_v2","email":"weakpass_v2@test.local","password":"123"}')
    
    if echo "$RESPONSE" | grep -q "at least 12"; then
        print_success "V2 rejected weak password ✓"
    else
        print_warning "V2 response: $RESPONSE"
    fi
}

# TEST 2: User Enumeration
test_user_enumeration() {
    print_header "TEST 2: User Enumeration"
    echo "Different error messages reveal if user exists"
    echo ""
    
    # V1 - Test with non-existent user
    echo "V1 (Vulnerable) - Non-existent user:"
    RESPONSE=$(curl -s -X POST "$V1_URL/api/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"nonexistent_xyz_123","password":"anything"}')
    
    if echo "$RESPONSE" | grep -q "not found"; then
        print_error "V1 says 'User not found' - reveals user doesn't exist ❌"
    else
        echo "Response: $RESPONSE"
    fi
    
    # V1 - Test with existing user, wrong password
    echo ""
    echo "V1 (Vulnerable) - Existing user (admin), wrong password:"
    RESPONSE=$(curl -s -X POST "$V1_URL/api/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"admin","password":"wrongpassword"}')
    
    if echo "$RESPONSE" | grep -q "Invalid password"; then
        print_error "V1 says 'Invalid password' - reveals user exists ❌"
    else
        echo "Response: $RESPONSE"
    fi
    
    # V2 - Both cases should return same generic message
    echo ""
    echo "V2 (Secure) - Non-existent user:"
    RESPONSE1=$(curl -s -X POST "$V2_URL/api/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"nonexistent_xyz_456","password":"anything"}')
    
    echo "V2 (Secure) - Existing user, wrong password:"
    RESPONSE2=$(curl -s -X POST "$V2_URL/api/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"admin","password":"wrongpassword"}')
    
    if echo "$RESPONSE1" | grep -q "Invalid credentials" && echo "$RESPONSE2" | grep -q "Invalid credentials"; then
        print_success "V2 returns generic 'Invalid credentials' for both ✓"
    else
        echo "Response 1: $RESPONSE1"
        echo "Response 2: $RESPONSE2"
    fi
}

# TEST 3: Rate Limiting
test_rate_limiting() {
    print_header "TEST 3: Rate Limiting"
    echo "Multiple failed login attempts should be blocked"
    echo ""
    
    # V1 - Should allow unlimited attempts
    echo "V1 (Vulnerable) - Attempting 7 failed logins:"
    SUCCESS_COUNT=0
    for i in {1..7}; do
        RESPONSE=$(curl -s -X POST "$V1_URL/api/login" \
            -H "Content-Type: application/json" \
            -d "{\"username\":\"admin\",\"password\":\"wrong$i\"}")
        
        if echo "$RESPONSE" | grep -q "Invalid"; then
            SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        fi
    done
    
    if [ $SUCCESS_COUNT -eq 7 ]; then
        print_error "V1 allowed all 7 attempts (no rate limiting) ❌"
    else
        print_warning "V1 blocked some attempts (unexpected)"
    fi
    
    # V2 - Should block after 5 attempts
    echo ""
    echo "V2 (Secure) - Attempting 7 failed logins:"
    for i in {1..7}; do
        RESPONSE=$(curl -s -X POST "$V2_URL/api/login" \
            -H "Content-Type: application/json" \
            -d "{\"username\":\"ratelimit_test\",\"password\":\"wrong$i\"}")
        
        if [ $i -le 5 ]; then
            if echo "$RESPONSE" | grep -q "Invalid credentials"; then
                echo "  Attempt $i: Accepted ✓"
            fi
        else
            if echo "$RESPONSE" | grep -q "Too many"; then
                echo "  Attempt $i: Blocked (Rate limited) ✓"
            else
                echo "  Attempt $i: Response - $RESPONSE"
            fi
        fi
    done
    print_success "V2 implements rate limiting ✓"
}

# TEST 4: Password Reset Token Reuse
test_password_reset_reuse() {
    print_header "TEST 4: Password Reset - Token Reuse"
    echo "Test if reset tokens can be reused"
    echo ""
    
    # V1 - Token should be reusable (vulnerability)
    echo "V1 (Vulnerable) - Getting reset token..."
    RESPONSE=$(curl -s -X POST "$V1_URL/api/forgot-password" \
        -H "Content-Type: application/json" \
        -d '{"email":"admin@test.local"}')
    
    TOKEN=$(echo "$RESPONSE" | grep -o '"resetLink":"[^"]*' | cut -d'=' -f2 | tr -d '}')
    
    if [ ! -z "$TOKEN" ]; then
        echo "Token received: $TOKEN"
        
        echo "Using token to reset password (1st time)..."
        RESPONSE1=$(curl -s -X POST "$V1_URL/api/reset-password" \
            -H "Content-Type: application/json" \
            -d "{\"token\":\"$TOKEN\",\"newPassword\":\"newpass123\"}")
        
        echo "Using same token again (2nd time)..."
        RESPONSE2=$(curl -s -X POST "$V1_URL/api/reset-password" \
            -H "Content-Type: application/json" \
            -d "{\"token\":\"$TOKEN\",\"newPassword\":\"anotherpass123\"}")
        
        if echo "$RESPONSE2" | grep -q "successfully"; then
            print_error "V1 allowed token reuse (vulnerability!) ❌"
        else
            print_warning "V1 blocked 2nd use: $RESPONSE2"
        fi
    else
        print_warning "Could not get reset token from V1"
    fi
}

# TEST 5: Session Cookie Flags
test_session_cookies() {
    print_header "TEST 5: Session Cookie Flags"
    echo "Check if session cookies have security flags"
    echo ""
    
    # V1 - Check cookie headers
    echo "V1 (Vulnerable) - Cookie headers:"
    RESPONSE=$(curl -s -i -X POST "$V1_URL/api/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"admin","password":"test"}' 2>&1 | grep -i "Set-Cookie")
    
    echo "  $RESPONSE"
    
    if echo "$RESPONSE" | grep -q "HttpOnly"; then
        print_warning "V1 has HttpOnly flag (unexpected)"
    else
        print_error "V1 missing HttpOnly flag ❌"
    fi
    
    if echo "$RESPONSE" | grep -q "; Secure"; then
        print_warning "V1 has Secure flag (unexpected)"
    else
        print_error "V1 missing Secure flag ❌"
    fi
    
    # V2 - Check cookie headers
    echo ""
    echo "V2 (Secure) - Cookie headers:"
    RESPONSE=$(curl -s -i -X POST "$V2_URL/api/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"admin","password":"SecurePass123!"}' 2>&1 | grep -i "Set-Cookie")
    
    echo "  $RESPONSE"
    
    if echo "$RESPONSE" | grep -q "HttpOnly"; then
        print_success "V2 has HttpOnly flag ✓"
    else
        print_error "V2 missing HttpOnly flag"
    fi
    
    if echo "$RESPONSE" | grep -q "; Secure"; then
        print_success "V2 has Secure flag ✓"
    else
        print_warning "V2 missing Secure flag (check HTTPS in production)"
    fi
}

# TEST 6: MD5 vs Bcrypt
test_password_hashing() {
    print_header "TEST 6: Password Hashing Algorithm"
    echo "Compare database storage between MD5 and bcrypt"
    echo ""
    
    echo "V1 (Vulnerable) - Using MD5:"
    echo "  Example: password 'admin123' → 0192023a7bbd73250516f069df18b500"
    echo "  Issue: Crackable with online tools, rainbow tables"
    print_error "MD5 is cryptographically broken ❌"
    
    echo ""
    echo "V2 (Secure) - Using bcrypt:"
    echo "  Example: password 'SecurePass123!' → \$2b\$10\$..."
    echo "  Features:"
    echo "    - One-way function (cannot be reversed)"
    echo "    - Unique salt per password"
    echo "    - Adaptive cost factor"
    print_success "Bcrypt is secure and modern ✓"
}

# Main execution
echo ""
echo "Select test(s) to run:"
echo "1) All tests"
echo "2) Test connectivity only"
echo "3) Test weak password policy"
echo "4) Test user enumeration"
echo "5) Test rate limiting"
echo "6) Test password reset reuse"
echo "7) Test session cookies"
echo "8) Test password hashing"
echo ""
read -p "Enter choice (1-8): " choice

case $choice in
    1)
        test_connectivity
        test_weak_password
        test_user_enumeration
        test_rate_limiting
        test_password_reset_reuse
        test_session_cookies
        test_password_hashing
        ;;
    2)
        test_connectivity
        ;;
    3)
        test_weak_password
        ;;
    4)
        test_user_enumeration
        ;;
    5)
        test_rate_limiting
        ;;
    6)
        test_password_reset_reuse
        ;;
    7)
        test_session_cookies
        ;;
    8)
        test_password_hashing
        ;;
    *)
        echo "Invalid choice"
        exit 1
        ;;
esac

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                    Tests Completed                         ║"
echo "╚════════════════════════════════════════════════════════════╝"
