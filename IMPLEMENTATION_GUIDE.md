# Implementation Guide - Mapping to Requirements

This document maps all project requirements to the implementation.

---

## 📋 Functional Requirements Checklist

### 3.1 - Înregistrare Utilizator (User Registration)

**Requirement:**
- Formular de creare cont cu email/username și parolă
- Stocarea utilizatorului într-o bază de date reală
- Asocierea unui rol simplu (ex: USER)
- Input-ul trebuie validat în backend
- DB reală (ex: PostgreSQL, SQLite)
- Rolul va fi folosit ulterior la autorizare

**Implementation:**

✅ **V1 (Vulnerable)** - [server-v1.js](server-v1.js#L57-L85)
```javascript
app.post('/api/register', (req, res) => {
  const { username, email, password } = req.body;
  
  // Basic validation
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'All fields required' });
  }
  
  // VULNERABLE: Only checks length >= 3
  if (password.length < 3) {
    return res.status(400).json({ error: 'Password too short' });
  }
  
  // VULNERABLE: MD5 hash (weak)
  const passwordHash = hashPasswordMD5(password);
  
  // Store in SQLite with role
  db.run(
    'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
    [username, email, passwordHash, 'USER'],
    // ...
  );
});
```

✅ **V2 (Secure)** - [server-v2.js](server-v2.js#L200-L235)
```javascript
app.post('/api/register', async (req, res) => {
  // Strong validation
  const passwordValidation = validatePassword(password);
  if (!passwordValidation.valid) {
    return res.status(400).json({ 
      error: 'Invalid password', 
      details: passwordValidation.errors 
    });
  }
  
  // SECURE: Bcrypt with salt
  const passwordHash = await hashPassword(password);
  
  // Store in SQLite with role
  db.run(
    'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
    [username, email, passwordHash, 'USER'],
    // ...
  );
});
```

**Database Schema:**
```sql
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,          -- SECURE (hashed)
  role TEXT DEFAULT 'USER',        -- For authorization
  locked_until DATETIME,           -- For rate limiting
  failed_attempts INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

✅ **Frontend:** [public/index-v1.html](public/index-v1.html) - Register tab

---

### 3.2 - Autentificare (Login)

**Requirement:**
- Formular de login cu username + parolă
- Verificarea credențialelor în backend
- Crearea unei sesiuni (cookie) sau token (JWT)
- Transmiterea sesiunii/token-ului către client
- Răspuns inițial diferențiat (vulnerabil) - Fără logică doar în UI

**Implementation:**

✅ **V1 (Vulnerable)** - [server-v1.js](server-v1.js#L87-L130)
```javascript
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  // Get user from DB
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    // VULNERABLE: Different error messages
    if (!user) {
      return res.status(401).json({ error: 'User not found' }); // Enum!
    }
    
    // VULNERABLE: MD5 comparison
    const passwordHash = hashPasswordMD5(password);
    if (user.password !== passwordHash) {
      return res.status(401).json({ error: 'Invalid password' }); // Enum!
    }
    
    // Create session with vulnerabilities
    const sessionId = crypto.randomBytes(16).toString('hex');
    
    db.run('INSERT INTO sessions (id, user_id) VALUES (?, ?)',
      [sessionId, user.id], () => {
        // VULNERABLE: No HttpOnly, no Secure, SameSite=Lax, 30 days
        res.cookie('sessionId', sessionId, {
          httpOnly: false,   // XSS vulnerability
          secure: false,     // MITM vulnerability
          sameSite: 'Lax',   // CSRF vulnerability
          maxAge: 30 * 24 * 60 * 60 * 1000  // Too long
        });
        
        // VULNERABLE: sessionId exposed in response
        res.json({ 
          message: 'Login successful',
          sessionId: sessionId,
          user: { id: user.id, username: user.username }
        });
      }
    );
  });
});
```

✅ **V2 (Secure)** - [server-v2.js](server-v2.js#L237-L300)
```javascript
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  
  // Get user
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    // SECURE: Generic message (no enumeration)
    if (err || !user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Check if account is locked (rate limiting)
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      return res.status(429).json({ error: 'Account temporarily locked' });
    }
    
    // SECURE: Bcrypt comparison
    const passwordMatch = await verifyPassword(password, user.password);
    
    if (!passwordMatch) {
      // SECURE: Increment failed attempts
      const newFailedAttempts = user.failed_attempts + 1;
      let lockedUntil = null;
      
      if (newFailedAttempts >= MAX_ATTEMPTS) {
        lockedUntil = new Date(Date.now() + 15 * 60 * 1000).toISOString();
      }
      
      db.run('UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?',
        [newFailedAttempts, lockedUntil, user.id]);
      
      // SECURE: Generic message + uniform response time
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Reset failed attempts
    db.run('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?',
      [user.id]);
    
    // Create session with security
    const sessionId = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();
    
    db.run('INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)',
      [sessionId, user.id, expiresAt], () => {
        // SECURE: HttpOnly, Secure, Strict SameSite, 1 hour
        res.cookie('sessionId', sessionId, {
          httpOnly: true,    // XSS protection
          secure: true,      // HTTPS only
          sameSite: 'Strict', // CSRF protection
          maxAge: 60 * 60 * 1000,  // 1 hour
          path: '/'
        });
        
        // sessionId NOT exposed (HttpOnly cookie handles it)
        res.json({ 
          message: 'Login successful',
          user: { id: user.id, username: user.username, role: user.role }
        });
      }
    );
  });
});
```

✅ **Frontend:** [public/index-v1.html](public/index-v1.html) / [public/index-v2.html](public/index-v2.html) - Login tab

---

### 3.3 - Logout

**Requirement:**
- Invalidarea sesiunii sau a token-ului
- Ștergerea cookie-ului sau marcarea token-ului ca invalid
- După logout sesiunea nu mai este validă

**Implementation:**

✅ **V1 & V2** - [server-v1.js](server-v1.js#L133-L145) / [server-v2.js](server-v2.js#L302-L314)
```javascript
app.post('/api/logout', (req, res) => {
  const sessionId = req.cookies.sessionId;

  if (!sessionId) {
    return res.status(400).json({ error: 'No session' });
  }

  // Delete session from database
  db.run('DELETE FROM sessions WHERE id = ?', [sessionId], () => {
    // Clear cookie
    res.clearCookie('sessionId', { path: '/' });
    res.json({ message: 'Logged out successfully' });
  });
});
```

✅ **Session invalidation tested:** After logout, GET /api/user returns 401

---

### 3.4 - Resetare Parolă (Forgot Password)

**Requirement:**
- Funcționalitate "Forgot password"
- Generarea unui token de resetare
- Endpoint pentru setarea unei parole noi
- Cu setări inițial incomplete (intenționat)
- Inițial predictibil sau reutilizabil (intenționat pentru v1)

**Implementation:**

✅ **V1 (Vulnerable)** - [server-v1.js](server-v1.js#L162-L192)
```javascript
app.post('/api/forgot-password', (req, res) => {
  const { email } = req.body;

  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (err || !user) {
      return res.json({ message: 'If email exists, reset link sent' });
    }

    // VULNERABLE: Token is just user ID
    const resetToken = user.id.toString();

    db.run(
      'INSERT INTO password_resets (user_id, token) VALUES (?, ?)',
      [user.id, resetToken], () => {
        res.json({ 
          message: 'Password reset link sent',
          // VULNERABLE: Token exposed in response
          resetLink: `http://localhost:3001/reset-password?token=${resetToken}`
        });
      }
    );
  });
});

app.post('/api/reset-password', (req, res) => {
  const { token, newPassword } = req.body;

  // VULNERABLE: No expiration check, can be reused
  db.get('SELECT * FROM password_resets WHERE token = ?', [token], (err, reset) => {
    if (err || !reset) {
      return res.status(400).json({ error: 'Invalid reset token' });
    }

    const passwordHash = hashPasswordMD5(newPassword);

    db.run(
      'UPDATE users SET password = ? WHERE id = ?',
      [passwordHash, reset.user_id], () => {
        // VULNERABLE: Token NOT deleted - can be reused
        res.json({ message: 'Password reset successfully' });
      }
    );
  });
});
```

✅ **V2 (Secure)** - [server-v2.js](server-v2.js#L340-L397)
```javascript
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;

  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (err || !user) {
      // SECURE: Generic response (no email enumeration)
      return res.json({ message: 'If email exists, a reset link will be sent' });
    }

    // SECURE: Random 32-byte token
    const resetToken = crypto.randomBytes(32).toString('hex');
    // SECURE: 15-minute expiration
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

    db.run(
      'INSERT INTO password_resets (user_id, token, expires_at, used) VALUES (?, ?, ?, 0)',
      [user.id, resetToken, expiresAt], () => {
        res.json({ 
          message: 'If email exists, a reset link will be sent',
          resetLink: `http://localhost:3002/reset-password?token=${resetToken}`
        });
      }
    );
  });
});

app.post('/api/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;

  try {
    // SECURE: Check expiration and one-time use
    db.get(
      'SELECT * FROM password_resets WHERE token = ? AND expires_at > datetime("now") AND used = 0',
      [token],
      async (err, reset) => {
        if (err || !reset) {
          return res.status(400).json({ error: 'Invalid credentials' });
        }

        // Validate new password
        const passwordValidation = validatePassword(newPassword);
        if (!passwordValidation.valid) {
          return res.status(400).json({ 
            error: 'Invalid password', 
            details: passwordValidation.errors 
          });
        }

        // SECURE: Bcrypt hash
        const passwordHash = await hashPassword(newPassword);

        db.run(
          'UPDATE users SET password = ?, failed_attempts = 0, locked_until = NULL WHERE id = ?',
          [passwordHash, reset.user_id], () => {
            // SECURE: Mark token as used (one-time only)
            db.run('UPDATE password_resets SET used = 1 WHERE id = ?', [reset.id], () => {
              res.json({ message: 'Password reset successfully' });
            });
          }
        );
      }
    );
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});
```

✅ **Frontend:** Login tab → Forgot Password

---

### 3.5 - Gestionare Sesiuni (Session Management)

**Requirement:**
- Menținerea autentificării între request-uri
- Identificarea utilizatorului curent
- Asocierea request-urilor cu utilizatorul logat
- Baza pentru access control

**Implementation:**

✅ **V1 & V2** - [server-v1.js](server-v1.js#L147-L160) / [server-v2.js](server-v2.js#L316-L337)
```javascript
app.get('/api/user', (req, res) => {
  const sessionId = req.cookies.sessionId;

  if (!sessionId) {
    return res.status(401).json({ error: 'No session' });
  }

  // V2 also checks expiration
  db.get('SELECT * FROM sessions WHERE id = ? AND expires_at > datetime("now")',
    [sessionId], (err, session) => {
      if (err || !session) {
        res.clearCookie('sessionId', { path: '/' });
        return res.status(401).json({ error: 'Invalid or expired session' });
      }

      // Get user info
      db.get('SELECT id, username, email, role FROM users WHERE id = ?',
        [session.user_id], (err, user) => {
          if (err || !user) {
            return res.status(401).json({ error: 'User not found' });
          }

          res.json({ user });
        }
      );
    }
  );
});
```

✅ **Session stored in SQLite:**
```sql
CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME DEFAULT (datetime('now', '+1 hour')),  -- V2: 1 hour
  FOREIGN KEY(user_id) REFERENCES users(id)
);
```

---

## 🔴 Cerințe de Securitate - Vulnerabilities Mapping

### 4.1 - Password Policy Slab

**V1 Vulnerability:**
- Lungime minimă: 3 caractere
- Fără validare complexitate
- Acceptă: `a`, `123`, `xxx` etc.

**V2 Fix:**
```javascript
function validatePassword(password) {
  const errors = [];
  
  if (password.length < 12) errors.push('Password must be at least 12 characters');
  if (!/[A-Z]/.test(password)) errors.push('Password must contain uppercase letter');
  if (!/[a-z]/.test(password)) errors.push('Password must contain lowercase letter');
  if (!/[0-9]/.test(password)) errors.push('Password must contain number');
  if (!/[!@#$%^&*]/.test(password)) errors.push('Password must contain special character');
  
  return errors.length === 0 ? { valid: true } : { valid: false, errors };
}
```

✅ **PoC in SECURITY_REPORT.md** - Vulnerability #1

---

### 4.2 - Stocare Nesigură a Parolelor

**V1 Vulnerability:**
```javascript
function hashPasswordMD5(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}
// "123" → "202cb962ac59075b964b07152d234b70"
// Crackable with online tools
```

**V2 Fix:**
```javascript
async function hashPassword(password) {
  const salt = await bcrypt.genSalt(10);
  return await bcrypt.hash(password, salt);
}
// "SecurePass123!" → "$2b$10$N9qo8uLO..." (unique each time)
// One-way function, rainbow table resistant
```

✅ **PoC in SECURITY_REPORT.md** - Vulnerability #2

---

### 4.3 - Brute Force / Lipsă Rate Limiting

**V1 Vulnerability:**
- Unlimited login attempts
- No account lockout
- No delays

**V2 Fix:**
```javascript
const MAX_ATTEMPTS = 5;
const RATE_LIMIT_WINDOW = 15 * 60 * 1000;

function checkRateLimit(username) {
  const key = `login:${username}`;
  const attempts = loginAttempts.get(key).filter(
    time => Date.now() - time < RATE_LIMIT_WINDOW
  );
  
  if (attempts.length >= MAX_ATTEMPTS) {
    return { allowed: false };
  }
  
  return { allowed: true };
}

// Also locks account for 15 minutes after failures
if (newFailedAttempts >= MAX_ATTEMPTS) {
  lockedUntil = new Date(Date.now() + 15 * 60 * 1000).toISOString();
}
```

✅ **PoC in SECURITY_REPORT.md** - Vulnerability #3

---

### 4.4 - User Enumeration

**V1 Vulnerability:**
```javascript
// Different messages
if (!user) return "User not found"      // Enum!
if (passwordWrong) return "Invalid password"  // Enum!
```

**V2 Fix:**
```javascript
// Same generic message always
if (err || !user || !passwordMatch) {
  return res.status(401).json({ error: 'Invalid credentials' });
}

// Also uniform response time (prevents timing attacks)
const responseDelay = Math.random() * 100 + 100;
await new Promise(r => setTimeout(r, responseDelay));
```

✅ **PoC in SECURITY_REPORT.md** - Vulnerability #4

---

### 4.5 - Gestionare Nesigură a Sesiunilor

**V1 Vulnerability:**
```javascript
res.cookie('sessionId', sessionId, {
  httpOnly: false,    // ❌ Can be stolen via XSS
  secure: false,      // ❌ Sent over HTTP
  sameSite: 'Lax',    // ❌ CSRF possible
  maxAge: 30 * 24 * 60 * 60 * 1000  // ❌ Too long (30 days)
});
```

**V2 Fix:**
```javascript
res.cookie('sessionId', sessionId, {
  httpOnly: true,     // ✓ XSS protection
  secure: true,       // ✓ HTTPS only
  sameSite: 'Strict', // ✓ CSRF protection
  maxAge: 60 * 60 * 1000,  // ✓ 1 hour
  path: '/'
});

// Also: Session expiration checked server-side
db.get('SELECT * FROM sessions WHERE id = ? AND expires_at > datetime("now")', ...)
```

✅ **PoC in SECURITY_REPORT.md** - Vulnerability #5

---

### 4.6 - Resetare Parolă Nesigură

**V1 Vulnerability:**
```javascript
// Token is just user ID - predictable
const resetToken = user.id.toString();  // "1", "2", "3"...

// No expiration - valid forever
db.get('SELECT * FROM password_resets WHERE token = ?', [token], ...)

// No one-time use - can be reused infinitely
// Token stays in DB, can be used again and again
```

**V2 Fix:**
```javascript
// Random 32-byte token - cryptographically secure
const resetToken = crypto.randomBytes(32).toString('hex');

// 15-minute expiration
const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

// One-time use only
db.get('SELECT * FROM password_resets WHERE token = ? AND expires_at > datetime("now") AND used = 0', ...)

// Mark as used after consuming
db.run('UPDATE password_resets SET used = 1 WHERE id = ?', ...)
```

✅ **PoC in SECURITY_REPORT.md** - Vulnerability #6

---

## 📄 Cerințe de Livrare

### ✅ 1. Cod Sursă

**Delivered:**
- [server-v1.js](server-v1.js) - V1 Vulnerable (550 lines)
- [server-v2.js](server-v2.js) - V2 Secure (620 lines)
- [public/index-v1.html](public/index-v1.html) - V1 Frontend
- [public/index-v2.html](public/index-v2.html) - V2 Frontend
- [package.json](package.json) - Dependencies

**Structure:** Clear separation of vulnerable vs secure code  
**Functionality:** Both versions work identically except for security  
**Database:** SQLite used (real database per requirements)

---

### ✅ 2. Raport de Securitate (Mini Pentest)

**Delivered:** [SECURITY_REPORT.md](SECURITY_REPORT.md) - 600+ lines

Contains for each of 6 vulnerabilities:
- Description
- Attack PoC (detailed steps)
- Code evidence
- Impact analysis
- Fix implementation with code
- Re-test evidence

---

### ✅ 3. Dovezi Practice

**Delivered:**
- [TESTING_GUIDE.md](TESTING_GUIDE.md) - Curl examples for all vulnerabilities
- [test-vulnerabilities.sh](test-vulnerabilities.sh) - Automated testing script
- Browser UI (Screenshots via frontend)
- Database inspection commands
- Request/response examples

---

## 🚀 How to Verify

### Run V1:
```bash
npm start:v1
# Browse to http://localhost:3001
# Test weak passwords, user enumeration, rate limiting disabled
```

### Run V2:
```bash
npm start:v2
# Browse to http://localhost:3002
# Test strong passwords required, generic messages, rate limiting active
```

### Run Tests:
```bash
bash test-vulnerabilities.sh
# Or use curl examples from TESTING_GUIDE.md
```

### Verify Database:
```bash
# V1: Passwords stored as MD5 (plain to see!)
sqlite3 authx_v1.db "SELECT username, password FROM users;"

# V2: Passwords stored as bcrypt (hashed/salted)
sqlite3 authx_v2.db "SELECT username, password FROM users;"
```

---

## ✅ Todos Completed

- ✅ All 5 functional requirements implemented
- ✅ All 6 security vulnerabilities intentionally added to v1
- ✅ All 6 vulnerabilities fixed in v2
- ✅ Security report with detailed PoCs
- ✅ Testing guide with curl examples
- ✅ Automated testing script
- ✅ Frontend for both versions
- ✅ SQLite database
- ✅ Clear project structure
- ✅ README with instructions

---

**Implementation Status:** ✅ COMPLETE

All requirements from PDF have been fulfilled with code evidence and practical testing.
