/**
 * PROIECT 2: BREAK THE LOGIN - VERSIUNEA FIXATĂ (V2)
 * 
 * FIXES IMPLEMENTATE:
 * 1. Strong password policy - Lungime minimă 12, complexitate, mesaj generic
 * 2. Secure password storage - bcrypt cu salt
 * 3. Rate limiting - Rate limiting pe login, blocare temporară
 * 4. No user enumeration - Mesaj generic "Invalid credentials"
 * 5. Secure session management - HttpOnly, Secure, SameSite cookies, expirare scurtă
 * 6. Secure password reset - Token random, one-time, cu expirare scurtă
 */

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const cookieParser = require('cookie-parser');

// Simple bcrypt-like hashing (în producție use real bcrypt)
const bcrypt = require('bcryptjs');

const app = express();
const PORT = 3002;

// Configurare
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static('public'));

// Bază de date SQLite
const db = new sqlite3.Database('./authx_v2.db', (err) => {
  if (err) console.error('Database error:', err);
  console.log('Connected to SQLite database (V2 - Secure)');
});

// Inițializare tabele
db.serialize(() => {
  // Tabelul utilizatorilor
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'USER',
    locked_until DATETIME,
    failed_attempts INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Tabelul sesiunilor (securizate)
  db.run(`CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME DEFAULT (datetime('now', '+1 hour')),
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  // Tabelul reset token-uri (securizate)
  db.run(`CREATE TABLE IF NOT EXISTS password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT NOT NULL UNIQUE,
    expires_at DATETIME DEFAULT (datetime('now', '+15 minutes')),
    used INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  // Tabelul login attempts (monitorizare)
  db.run(`CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    success INTEGER,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT
  )`);
});

// ============ SECURITY HELPERS ============

// FIX #1: Validare parolă puternică
function validatePassword(password) {
  const errors = [];
  
  if (password.length < 12) {
    errors.push('Password must be at least 12 characters');
  }
  if (!/[A-Z]/.test(password)) {
    errors.push('Password must contain uppercase letter');
  }
  if (!/[a-z]/.test(password)) {
    errors.push('Password must contain lowercase letter');
  }
  if (!/[0-9]/.test(password)) {
    errors.push('Password must contain number');
  }
  if (!/[!@#$%^&*]/.test(password)) {
    errors.push('Password must contain special character (!@#$%^&*)');
  }
  
  return errors.length === 0 ? { valid: true } : { valid: false, errors };
}

// FIX #2: Hash sigur cu bcrypt
async function hashPassword(password) {
  const salt = await bcrypt.genSalt(10);
  return await bcrypt.hash(password, salt);
}

async function verifyPassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

// FIX #3: Rate limiting în memorie (în producție: Redis)
const loginAttempts = new Map();
const RATE_LIMIT_WINDOW = 15 * 60 * 1000; // 15 minute
const MAX_ATTEMPTS = 5;

function checkRateLimit(username) {
  const now = Date.now();
  const key = `login:${username}`;
  
  if (!loginAttempts.has(key)) {
    loginAttempts.set(key, []);
  }
  
  const attempts = loginAttempts.get(key).filter(time => now - time < RATE_LIMIT_WINDOW);
  loginAttempts.set(key, attempts);
  
  if (attempts.length >= MAX_ATTEMPTS) {
    return { allowed: false, remaining: 0 };
  }
  
  return { allowed: true, remaining: MAX_ATTEMPTS - attempts.length };
}

function recordLoginAttempt(username) {
  const key = `login:${username}`;
  const attempts = loginAttempts.get(key) || [];
  attempts.push(Date.now());
  loginAttempts.set(key, attempts);
}

// ============ REGISTER ============
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;

  // Validare input
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'All fields required' });
  }

  // FIX #1: Validare parolă puternică
  const passwordValidation = validatePassword(password);
  if (!passwordValidation.valid) {
    return res.status(400).json({ error: 'Invalid password', details: passwordValidation.errors });
  }

  try {
    // FIX #2: Hash sigur
    const passwordHash = await hashPassword(password);

    db.run(
      'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
      [username, email, passwordHash, 'USER'],
      (err) => {
        if (err) {
          // FIX #4: Mesaj generic (nu arată dacă userul există)
          return res.status(400).json({ error: 'Registration failed. Invalid credentials' });
        }
        res.json({ message: 'User registered successfully' });
      }
    );
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ LOGIN ============
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const clientIP = req.ip;

  // Validare input
  if (!username || !password) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }

  // FIX #3: Rate limiting
  const rateLimit = checkRateLimit(username);
  if (!rateLimit.allowed) {
    return res.status(429).json({ 
      error: 'Too many login attempts. Try again later.',
      remaining: 0
    });
  }

  try {
    // Uniform response time (simplificat) - FIX #4
    const startTime = Date.now();
    const responseDelay = Math.random() * 100 + 100; // 100-200ms

    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
      recordLoginAttempt(username);

      // FIX #4: Mesaj generic - NU se spune dacă userul există sau parolă greșită
      if (err || !user) {
        await new Promise(r => setTimeout(r, responseDelay));
        db.run('INSERT INTO login_attempts (username, success, ip_address) VALUES (?, ?, ?)',
          [username, 0, clientIP]);
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // FIX #3: Verificare dacă cont este blocat
      if (user.locked_until && new Date(user.locked_until) > new Date()) {
        await new Promise(r => setTimeout(r, responseDelay));
        return res.status(429).json({ error: 'Account temporarily locked' });
      }

      // FIX #2: Verificare parolă cu hash sigur
      const passwordMatch = await verifyPassword(password, user.password);
      
      if (!passwordMatch) {
        // FIX #3: Incrementare tentative eșuate
        const newFailedAttempts = user.failed_attempts + 1;
        let lockedUntil = null;

        if (newFailedAttempts >= MAX_ATTEMPTS) {
          lockedUntil = new Date(Date.now() + 15 * 60 * 1000).toISOString(); // Lock 15 minute
        }

        db.run('UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?',
          [newFailedAttempts, lockedUntil, user.id]);

        await new Promise(r => setTimeout(r, responseDelay));
        db.run('INSERT INTO login_attempts (username, success, ip_address) VALUES (?, ?, ?)',
          [username, 0, clientIP]);

        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // Login reușit - reset tentative
      db.run('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?', [user.id]);

      // FIX #5: Session sigur cu expirare scurtă
      const sessionId = crypto.randomBytes(32).toString('hex');
      const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 1 oră

      db.run(
        'INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)',
        [sessionId, user.id, expiresAt],
        () => {
          // FIX #5: Cookie cu setări de securitate
          res.cookie('sessionId', sessionId, {
            httpOnly: true,   // Nu se poate accesa din JavaScript (protecție XSS)
            secure: true,     // Se trimite doar pe HTTPS
            sameSite: 'Strict', // Protecție CSRF
            maxAge: 60 * 60 * 1000, // 1 oră
            path: '/'
          });

          db.run('INSERT INTO login_attempts (username, success, ip_address) VALUES (?, ?, ?)',
            [username, 1, clientIP]);

          res.json({ 
            message: 'Login successful',
            user: { id: user.id, username: user.username, email: user.email, role: user.role }
          });
        }
      );
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ LOGOUT ============
app.post('/api/logout', (req, res) => {
  const sessionId = req.cookies.sessionId;

  if (!sessionId) {
    return res.status(400).json({ error: 'No session' });
  }

  db.run('DELETE FROM sessions WHERE id = ?', [sessionId], () => {
    res.clearCookie('sessionId', { path: '/' });
    res.json({ message: 'Logged out successfully' });
  });
});

// ============ GET USER (verifică sesiune) ============
app.get('/api/user', (req, res) => {
  const sessionId = req.cookies.sessionId;

  if (!sessionId) {
    return res.status(401).json({ error: 'No session' });
  }

  // FIX #5: Verificare expirare sesiune
  db.get('SELECT * FROM sessions WHERE id = ? AND expires_at > datetime("now")', [sessionId], (err, session) => {
    if (err || !session) {
      res.clearCookie('sessionId', { path: '/' });
      return res.status(401).json({ error: 'Invalid or expired session' });
    }

    db.get('SELECT id, username, email, role FROM users WHERE id = ?', [session.user_id], (err, user) => {
      if (err || !user) {
        return res.status(401).json({ error: 'User not found' });
      }

      res.json({ user });
    });
  });
});

// ============ PASSWORD RESET ============
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email required' });
  }

  // Generic response (nu arată dacă email există)
  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    // FIX #4: Mesaj generic indiferent de rezultat
    if (err || !user) {
      return res.json({ message: 'If email exists, a reset link will be sent' });
    }

    // FIX #6: Token random și secure
    const resetToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString(); // 15 minute

    db.run(
      'INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, ?)',
      [user.id, resetToken, expiresAt],
      () => {
        // În producție, s-ar trimite prin email
        res.json({ 
          message: 'If email exists, a reset link will be sent',
          // În test - se dă direct (nu în producție!)
          resetLink: `http://localhost:3002/reset-password?token=${resetToken}`
        });
      }
    );
  });
});

// RESET PASSWORD
app.post('/api/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;

  if (!token || !newPassword) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }

  try {
    // FIX #6: Token trebuie valid, neexprirat și neutilizat
    db.get(
      'SELECT * FROM password_resets WHERE token = ? AND expires_at > datetime("now") AND used = 0',
      [token],
      async (err, reset) => {
        if (err || !reset) {
          return res.status(400).json({ error: 'Invalid credentials' });
        }

        // Validare parolă nouă
        const passwordValidation = validatePassword(newPassword);
        if (!passwordValidation.valid) {
          return res.status(400).json({ 
            error: 'Invalid password', 
            details: passwordValidation.errors 
          });
        }

        try {
          const passwordHash = await hashPassword(newPassword);

          db.run(
            'UPDATE users SET password = ?, failed_attempts = 0, locked_until = NULL WHERE id = ?',
            [passwordHash, reset.user_id],
            () => {
              // FIX #6: Marchează token-ul ca utilizat (nu poate fi reutilizat)
              db.run('UPDATE password_resets SET used = 1 WHERE id = ?', [reset.id], () => {
                res.json({ message: 'Password reset successfully' });
              });
            }
          );
        } catch (err) {
          res.status(500).json({ error: 'Server error' });
        }
      }
    );
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ PAGE ============
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index-v2.html'));
});

// Verificare instalare bcryptjs
const checkBcrypt = () => {
  try {
    require('bcryptjs');
    return true;
  } catch (e) {
    console.error('⚠️  bcryptjs not installed. Install with: npm install bcryptjs');
    return false;
  }
};

app.listen(PORT, () => {
  if (!checkBcrypt()) {
    console.error('❌ Missing dependency: bcryptjs');
    console.error('Please run: npm install bcryptjs');
    process.exit(1);
  }
  
  console.log(`🔒 AuthX V2 (SECURE) running on http://localhost:${PORT}`);
  console.log('✅ All security fixes implemented');
});
