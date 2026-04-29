# AuthX - Break the Login
## Proiect 2: Atacarea și securizarea autentificării

**Developer:** Alexandru Pătrascu  
**Course:** Dezvoltarea Aplicațiilor Software Securizate  
**University:** Universitatea din București  

---

## 📋 Project Overview

This project implements a real-world scenario where an internal authentication system is built with intentional security vulnerabilities (v1.0), then exploited and fixed (v2.0).

**Two Versions:**
- **V1 (Vulnerable):** All 6 security vulnerabilities intentionally implemented
- **V2 (Secure):** All vulnerabilities fixed with industry best practices

**Scope:**
- User registration
- Login / Logout
- Session management
- Password management
- Password reset

---

## ✅ Implemented Features

### Mandatory Requirements (per specification)

#### 3.1 - User Registration (Register)
- ✅ Form with email/username + password
- ✅ Database storage (SQLite)
- ✅ Role assignment (USER)
- ✅ Input validation in backend

#### 3.2 - Authentication (Login)
- ✅ Credential verification
- ✅ Session/Cookie creation
- ✅ Session transmission to client
- ✅ Maintains authentication between requests

#### 3.3 - Logout
- ✅ Session invalidation
- ✅ Cookie deletion

#### 3.4 - Password Reset (Forgot Password)
- ✅ Reset token generation
- ✅ Token endpoint
- ✅ New password setting

#### 3.5 - Session Management
- ✅ User identification
- ✅ Request association

---

## 🔓 V1 - Vulnerabilities (Intentional)

### 1. Weak Password Policy
- Minimum 3 characters
- No complexity requirements
- No validation
- **Impact:** Easily crackable passwords

### 2. Insecure Password Storage
- MD5 hashing (cryptographically broken)
- No salt
- Rainbow table vulnerable
- **Impact:** Passwords recoverable if DB breached

### 3. No Rate Limiting
- Unlimited login attempts
- No account lockout
- No CAPTCHA
- **Impact:** Brute force attacks succeed

### 4. User Enumeration
- Different error messages ("user not found" vs "wrong password")
- Reveals which usernames exist
- **Impact:** Targeted attacks possible

### 5. Insecure Session Management
- Cookie without HttpOnly
- No Secure flag (HTTP vulnerable)
- Weak SameSite (CSRF possible)
- 30-day expiration (too long)
- **Impact:** XSS → Session hijacking

### 6. Insecure Password Reset
- Predictable token (just user ID)
- Reusable token
- No expiration
- **Impact:** Unauthorized account reset

---

## 🔒 V2 - Security Fixes (Applied)

### 1. Strong Password Policy
- Minimum 12 characters
- Uppercase + lowercase + number + special char required
- Real-time validation feedback
- **Fix:** Meets OWASP guidelines

### 2. Secure Password Storage
- Bcrypt hashing with salt
- Adaptive cost factor (10)
- Unique salt per password
- **Fix:** One-way function, rainbow table resistant

### 3. Rate Limiting & Account Lockout
- Max 5 attempts per 15 minutes
- 15-minute account lockout after failures
- Logging of attempts
- **Fix:** Brute force attacks blocked

### 4. Generic Error Messages
- "Invalid credentials" for all failures
- Uniform response time
- No user enumeration possible
- **Fix:** User enumeration prevented

### 5. Secure Session Management
- HttpOnly flag (XSS protection)
- Secure flag (HTTPS only)
- SameSite=Strict (CSRF protection)
- 1-hour expiration (short window)
- Rotated on login
- Invalidated on logout
- **Fix:** Session hijacking prevented

### 6. Secure Password Reset
- Random 32-byte token (cryptographic)
- One-time use (marked as used)
- 15-minute expiration
- Invalidated after use
- Not exposed in response
- **Fix:** Unauthorized resets prevented

---

## 🚀 Quick Start

### Prerequisites
```bash
Node.js >= 14.0
npm >= 6.0
```

### Installation

```bash
# Navigate to project directory
cd /var/www/html/Desktop/Proiect-2-Patrascu-Alexandru

# Install dependencies
npm install

# Optional: Install bcryptjs separately for v2
npm install bcryptjs
```

### Running V1 (Vulnerable)

```bash
npm start:v1
```

**Output:**
```
🔓 AuthX V1 (VULNERABLE) running on http://localhost:3001
⚠️  WARNING: This version has intentional security vulnerabilities!
```

Access at: **http://localhost:3001**

### Running V2 (Secure)

```bash
npm start:v2
```

**Output:**
```
🔒 AuthX V2 (SECURE) running on http://localhost:3002
✅ All security fixes implemented
```

Access at: **http://localhost:3002**

---

## 🧪 Testing Guide

### Test Accounts (V1 - Weak Password)

After creating these, you can use them to demonstrate vulnerabilities:

**Create in V1:**
- Username: `admin` / Email: `admin@test.local` / Password: `test` (weak!)
- Username: `user123` / Email: `user@test.local` / Password: `pass` (weak!)

### Test Accounts (V2 - Strong Password)

**Create in V2:**
- Username: `admin` / Email: `admin@test.local` / Password: `SecurePass123!` (strong)
- Username: `user123` / Email: `user@test.local` / Password: `MySecure456!` (strong)

### Vulnerability Demonstrations

#### V1 - Test Weak Password:
1. Go to V1 Register page
2. Create account with password: `a` (3 characters)
3. Registration succeeds ❌

#### V2 - Test Strong Password:
1. Go to V2 Register page
2. Try password: `a`
3. Shows requirements not met ✅

#### V1 - Test User Enumeration:
```bash
# Non-existent user
curl -X POST http://localhost:3001/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"nonexistent","password":"anything"}'
# Response: "User not found" ← User doesn't exist

# Existing user, wrong password
curl -X POST http://localhost:3001/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"wrong"}'
# Response: "Invalid password" ← User exists!
```

#### V2 - Test Generic Messages:
```bash
# Both return same message
# Non-existent user → "Invalid credentials"
# Existing user, wrong password → "Invalid credentials"
```

#### V1 - Test No Rate Limiting:
```bash
# Try 100 failed logins - all succeed
for i in {1..100}; do
  curl -s -X POST http://localhost:3001/api/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"wrong'$i'"}'
done
```

#### V2 - Test Rate Limiting:
```bash
# After 5 attempts, get blocked
for i in {1..7}; do
  curl -X POST http://localhost:3002/api/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"wrong'$i'"}'
  # Attempts 1-5: 401 Unauthorized
  # Attempt 6+: 429 Too Many Requests
done
```

#### V1 - Test Password Reset Token Reuse:
```bash
# Get reset link (token shown)
curl -X POST http://localhost:3001/api/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@test.local"}'
# Response: "resetLink": "...?token=1"

# Use token once
curl -X POST http://localhost:3001/api/reset-password \
  -H "Content-Type: application/json" \
  -d '{"token":"1","newPassword":"newpass123"}'
# Response: 200 OK

# Use same token again (should fail but doesn't in v1!)
curl -X POST http://localhost:3001/api/reset-password \
  -H "Content-Type: application/json" \
  -d '{"token":"1","newPassword":"anotherpass123"}'
# Response: 200 OK (token reused! ❌)
```

#### V2 - Test One-Time Token:
```bash
# Same flow...
# First use: 200 OK ✅
# Second use: 400 Bad Request (token marked as used) ✅
```

---

## 📁 Project Structure

```
/Proiect-2-Patrascu-Alexandru/
├── package.json              # Dependencies
├── server-v1.js              # V1 - Vulnerable application
├── server-v2.js              # V2 - Secure application
├── SECURITY_REPORT.md        # Full security audit (detailed PoCs)
├── README.md                 # This file
├── testing-guide.md          # Additional testing scenarios
├── public/
│   ├── index-v1.html         # V1 - Frontend (vulnerable)
│   └── index-v2.html         # V2 - Frontend (secure)
├── authx_v1.db               # V1 - SQLite database (auto-created)
└── authx_v2.db               # V2 - SQLite database (auto-created)
```

---

## 📊 Deliverables Checklist

### ✅ Código Fonte (Source Code)
- [x] Aplicação completa funcional (Both v1 and v2)
- [x] Duas versões distintas (vulnerable and fixed)
- [x] Estrutura clara do projeto
- [x] Sem código duplicado desnecessário

### ✅ Relatório de Segurança (Security Report)
- [x] Descrição de cada vulnerabilidade ([SECURITY_REPORT.md](SECURITY_REPORT.md))
- [x] Passos de exploração (PoC detalhados)
- [x] Impacto da vulnerabilidade (CVSS scores)
- [x] Fix implementado (com código)
- [x] Re-teste (evidence of fix working)

### ✅ Evidências Práticas (Practical Evidence)
- [x] Request/response relevantes (curl examples)
- [x] Screenshots (HTML UI provided)
- [x] Inputs maliciosos (safe lab examples)
- [x] Burp/Postman exportable (use curl commands)

---

## 🔍 Security Report

See [SECURITY_REPORT.md](SECURITY_REPORT.md) for:
- Detailed vulnerability descriptions
- Proof-of-concept attacks
- Impact analysis
- Implementation details of fixes
- Re-testing evidence
- CVSS scoring

---

## 🧬 API Endpoints

### V1 & V2 Endpoints (identical interface, different implementation)

```
POST /api/register
  Body: { username, email, password }
  Response: { message } or { error }

POST /api/login
  Body: { username, password }
  Response: { message, user, sessionId? } or { error }

POST /api/logout
  Body: { sessionId? }
  Response: { message } or { error }

GET /api/user
  Query/Cookie: sessionId
  Response: { user } or { error }

POST /api/forgot-password
  Body: { email }
  Response: { message, resetLink? }

POST /api/reset-password
  Body: { token, newPassword }
  Response: { message } or { error }
```

---

## 🔐 Key Differences Summary

| Feature | V1 | V2 |
|---------|----|----|
| Password min length | 3 chars | 12 chars |
| Password hashing | MD5 | Bcrypt |
| Rate limiting | None | 5 attempts/15 min |
| User enumeration | Yes | No |
| Cookie HttpOnly | No | Yes |
| Cookie SameSite | Lax | Strict |
| Session expiration | 30 days | 1 hour |
| Reset token | Predictable (ID) | Random (32 bytes) |
| Reset reusable | Yes | No |
| Reset expiration | Never | 15 minutes |

---

## 🚀 Next Steps (Production Deployment)

1. **Use HTTPS** (add to secure flag)
2. **Multi-Factor Authentication** (TOTP/SMS)
3. **Email verification** (account activation)
4. **CAPTCHA** (prevent automated attacks)
5. **Redis** (production rate limiting)
6. **Real bcryptjs** (instead of crypto.MD5)
7. **Database** (PostgreSQL instead of SQLite)
8. **Monitoring** (security logging & alerting)
9. **Penetration testing** (professional audit)
10. **Compliance** (GDPR, OWASP, etc.)

---

## 📚 References

- OWASP Top 10: https://owasp.org/www-project-top-ten/
- Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- Bcrypt: https://en.wikipedia.org/wiki/Bcrypt
- CVSS v3.1: https://www.first.org/cvss/v3.1/

---

## ⚠️ Disclaimer

- **V1 is intentionally vulnerable** for educational purposes only
- **Never use V1 code in production**
- **V2 is significantly more secure** but requires additional hardening for production
- This is a **learning project**, not a production-ready system

---

## 📞 Contact

**Developer:** Alexandru Pătrascu  
**Email:** To be provided in submission  
**Course:** Dezvoltarea Aplicațiilor Software Securizate  
**University:** Universitatea din București  

---

## 📝 License

This project is for educational purposes as part of the university course.

---

**Last Updated:** April 29, 2026  
**Status:** ✅ Complete
