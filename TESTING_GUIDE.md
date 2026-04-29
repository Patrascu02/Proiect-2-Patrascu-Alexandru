# Testing Guide - AuthX Break the Login

## Curl Command Examples

### V1 - Vulnerable Version (Port 3001)

#### 1. Register with Weak Password
```bash
curl -X POST http://localhost:3001/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "email": "admin@test.local",
    "password": "123"
  }'
```

**Expected (V1):** Accepts 3-character password  
**V2 would reject:** Minimum 12 characters required

---

#### 2. Login and Enumerate Users
```bash
# Non-existent user
curl -X POST http://localhost:3001/api/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "nonexistent_user",
    "password": "anything"
  }'
```

**Expected (V1):** `{"error": "User not found"}` (reveals user doesn't exist)  

```bash
# Existing user, wrong password
curl -X POST http://localhost:3001/api/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "wrongpass"
  }'
```

**Expected (V1):** `{"error": "Invalid password"}` (reveals user exists)

---

#### 3. Brute Force Attack (No Rate Limiting)
```bash
# Attempt multiple logins - all succeed instantly
for i in {1..10}; do
  curl -s -X POST http://localhost:3001/api/login \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"admin\",\"password\":\"wrong$i\"}"
done
```

**Expected (V1):** All 10 attempts return error (but don't block)

---

#### 4. Password Reset - Predictable Token
```bash
# Request reset - token will be revealed
curl -X POST http://localhost:3001/api/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@test.local"}'
```

**Response (V1):**
```json
{
  "message": "Password reset link sent",
  "resetLink": "http://localhost:3001/reset-password?token=1"
}
```

**Issue:** Token is just the user ID (1 = first user, 2 = second user, etc.)  
**Attack:** Can guess tokens (1, 2, 3...) or brute-force them

---

#### 5. Reuse Password Reset Token
```bash
# Save token from above (token=1)

# Use token first time
curl -X POST http://localhost:3001/api/reset-password \
  -H "Content-Type: application/json" \
  -d '{
    "token": "1",
    "newPassword": "newpass123"
  }'
# Result: 200 OK

# Use SAME token again (should fail but doesn't!)
curl -X POST http://localhost:3001/api/reset-password \
  -H "Content-Type: application/json" \
  -d '{
    "token": "1",
    "newPassword": "anotherpass123"
  }'
# Result (V1): 200 OK (token reused!) ❌
```

---

#### 6. Session is Exposed
```bash
# Login response shows session ID
curl -X POST http://localhost:3001/api/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "123"
  }'
```

**Response (V1):**
```json
{
  "message": "Login successful",
  "sessionId": "a1b2c3d4e5f6...",
  "user": {...}
}
```

**Issue:** Session ID exposed in response + accessible via JS (no HttpOnly flag)

---

### V2 - Secure Version (Port 3002)

#### 1. Register with Strong Password Required
```bash
# This FAILS
curl -X POST http://localhost:3002/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "email": "admin@test.local",
    "password": "123"
  }'
```

**Response (V2):**
```json
{
  "error": "Invalid password",
  "details": [
    "Password must be at least 12 characters",
    "Password must contain uppercase letter",
    "Password must contain number",
    "Password must contain special character (!@#$%^&*)"
  ]
}
```

---

#### 2. Register with Strong Password
```bash
curl -X POST http://localhost:3002/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "email": "admin@test.local",
    "password": "SecurePass123!"
  }'
```

**Response (V2):**
```json
{
  "message": "User registered successfully"
}
```

---

#### 3. Generic Error Messages (No User Enumeration)
```bash
# Both cases return SAME message

# Non-existent user
curl -X POST http://localhost:3002/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"nonexistent_xyz","password":"anything"}'
# Response: {"error": "Invalid credentials"}

# Existing user, wrong password  
curl -X POST http://localhost:3002/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"wrongpass"}'
# Response: {"error": "Invalid credentials"}
```

**Result:** Attacker cannot tell which failed

---

#### 4. Rate Limiting (After 5 Failed Attempts)
```bash
# Attempts 1-5: Return 401 Unauthorized
for i in {1..5}; do
  echo "Attempt $i:"
  curl -s -X POST http://localhost:3002/api/login \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"admin\",\"password\":\"wrong$i\"}" | jq .error
done

# Attempt 6: Blocked
curl -X POST http://localhost:3002/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"wrong6"}'
```

**Response (Attempt 6+):**
```json
{
  "error": "Too many login attempts. Try again later.",
  "remaining": 0
}
```

---

#### 5. One-Time Use Password Reset Token
```bash
# Request reset
curl -X POST http://localhost:3002/api/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@test.local"}'
```

**Response (V2):**
```json
{
  "message": "If email exists, a reset link will be sent",
  "resetLink": "http://localhost:3002/reset-password?token=9f4a2e7c1d3b5f8a..."
}
```

**Issue (not an issue in V2):**
- Token is 32 random bytes (not predictable)
- Token expires in 15 minutes
- Token can only be used once

---

#### 6. Token Expires After 15 Minutes
```bash
# Use token (works)
curl -X POST http://localhost:3002/api/reset-password \
  -H "Content-Type: application/json" \
  -d '{
    "token": "9f4a2e7c1d3b5f8a...",
    "newPassword": "NewSecure123!"
  }'
# Result: 200 OK

# Wait 16 minutes, try same token
curl -X POST http://localhost:3002/api/reset-password \
  -H "Content-Type: application/json" \
  -d '{
    "token": "9f4a2e7c1d3b5f8a...",
    "newPassword": "AnotherPass123!"
  }'
# Result: 400 Bad Request (expired)
```

---

#### 7. Session Cannot Be Accessed from JavaScript
```bash
# Login to V2
curl -c cookies.txt -X POST http://localhost:3002/api/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "SecurePass123!"
  }'

# In browser console (V2):
document.cookie
// Output: "" (empty - HttpOnly prevents access)

# In browser console (V1):
document.cookie
// Output: "sessionId=abc123..." (exposed - vulnerable)
```

---

## Postman Collection Import

Create a new Postman Collection and add these requests:

### V1 Collection

```json
{
  "info": {
    "name": "AuthX V1 - Vulnerable",
    "version": "1.0"
  },
  "item": [
    {
      "name": "Register (Weak Password)",
      "request": {
        "method": "POST",
        "url": "http://localhost:3001/api/register",
        "header": [{"key": "Content-Type", "value": "application/json"}],
        "body": {
          "raw": "{\"username\":\"testuser\",\"email\":\"test@test.local\",\"password\":\"123\"}"
        }
      }
    },
    {
      "name": "Login (Enumerate User)",
      "request": {
        "method": "POST",
        "url": "http://localhost:3001/api/login",
        "body": {
          "raw": "{\"username\":\"admin\",\"password\":\"wrong\"}"
        }
      }
    },
    {
      "name": "Forgot Password (Predictable Token)",
      "request": {
        "method": "POST",
        "url": "http://localhost:3001/api/forgot-password",
        "body": {
          "raw": "{\"email\":\"admin@test.local\"}"
        }
      }
    }
  ]
}
```

---

## Browser Testing

### V1 - Vulnerable (http://localhost:3001)

1. **Test Weak Password:**
   - Go to Register tab
   - Try username: `test` / password: `a` (1 character)
   - V1 accepts it

2. **Test User Enumeration:**
   - Try non-existent user: `zzzznonexistent`
   - Error says: "User not found"
   - Try existing user `admin` with wrong password
   - Error says: "Invalid password"

3. **Test Session Exposure:**
   - Login successfully
   - Open Developer Tools → Console
   - Type: `document.cookie`
   - See session ID in plain text

4. **Test Password Reset Reuse:**
   - Go to "Forgot Password" tab
   - Enter email
   - Get reset token
   - Use token to reset password
   - Use SAME token again (it works!)

---

### V2 - Secure (http://localhost:3002)

1. **Test Strong Password:**
   - Go to Register tab
   - Try password: `a`
   - See requirements not met (live validation)
   - Try: `SecurePass123!`
   - Registration succeeds

2. **Test Generic Messages:**
   - Try non-existent user
   - Error: "Invalid credentials"
   - Try existing user with wrong password
   - Error: "Invalid credentials" (same!)

3. **Test Rate Limiting:**
   - Try to login with wrong password 6 times
   - 6th attempt blocked with: "Too many login attempts"

4. **Test Session Security:**
   - Login successfully
   - Open Developer Tools → Console
   - Type: `document.cookie`
   - Empty string (HttpOnly flag blocks access)

5. **Test One-Time Token:**
   - Request password reset
   - Use token once (works)
   - Try to use same token again (fails)

---

## Database Inspection

### V1 - View Plaintext Hashes (Vulnerable!)
```bash
sqlite3 authx_v1.db "SELECT username, password FROM users;" 

# Example output:
# admin | 0192023a7bbd73250516f069df18b500
# (hash of "123" is publicly known - instant crack)
```

### V2 - View Bcrypt Hashes (Secure)
```bash
sqlite3 authx_v2.db "SELECT username, password FROM users;"

# Example output:
# admin | $2b$10$N9qo8uLOickgx2ZMRZoMyexcbJEqvI7qI5I3pJKu7FxXyIp2G5Kmq
# (cannot be reversed, each hash is unique due to salt)
```

---

## Timing Attacks Test

### V1 - Timing Variability (Can enumerate users)
```bash
# Measure response time for non-existent vs existing user
time curl -X POST http://localhost:3001/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"nonexistent","password":"x"}'

time curl -X POST http://localhost:3001/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"x"}'

# V1 might have different response times
```

### V2 - Timing Uniformity (Prevents timing attacks)
```bash
# Both take similar time (V2 adds delays to prevent timing attacks)
time curl -X POST http://localhost:3002/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"nonexistent","password":"x"}'

time curl -X POST http://localhost:3002/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"x"}'

# V2 responses are uniform
```

---

## Security Headers

### Check V1 Cookie (Vulnerable)
```bash
curl -i -X POST http://localhost:3001/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"123"}' | grep -i "Set-Cookie"

# Example output:
# Set-Cookie: sessionId=...; Path=/
# ✗ No HttpOnly
# ✗ No Secure
# ✗ No SameSite (or Lax)
```

### Check V2 Cookie (Secure)
```bash
curl -i -X POST http://localhost:3002/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"SecurePass123!"}' | grep -i "Set-Cookie"

# Example output:
# Set-Cookie: sessionId=...; Path=/; HttpOnly; Secure; SameSite=Strict
# ✓ HttpOnly
# ✓ Secure
# ✓ SameSite=Strict
```

---

## Automated Testing Script

Run the provided script:
```bash
chmod +x test-vulnerabilities.sh
./test-vulnerabilities.sh
```

This will:
- Check server connectivity
- Test weak password acceptance
- Test user enumeration
- Test rate limiting
- Test password reset token reuse
- Test session cookie flags
- Compare hashing algorithms

---

## Expected Results Summary

| Test | V1 Result | V2 Result |
|------|-----------|-----------|
| 3-char password accepted | ❌ YES | ✓ NO |
| User enumeration possible | ❌ YES | ✓ NO |
| Rate limiting | ❌ NO | ✓ YES |
| Reset token predictable | ❌ YES | ✓ NO |
| Reset token reusable | ❌ YES | ✓ NO |
| Session HttpOnly | ❌ NO | ✓ YES |
| Hash is MD5 | ❌ YES | ✓ NO (Bcrypt) |

---

**All tests documented for reproducibility and audit purposes.**
