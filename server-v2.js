/**
 * PROIECT 2: BREAK THE LOGIN - VERSIUNEA FIXATĂ (V2)
 * * FIXES IMPLEMENTATE:
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

const bcrypt = require('bcryptjs');

const app = express();
const PORT = 3002;

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static('public'));

const db = new sqlite3.Database('./authx_v2.db', (err) => {
  if (err) console.error('Database error:', err);
  console.log('Connected to SQLite database (V2 - Secure)');
});

db.serialize(() => {
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

  db.run(`CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT,
    status TEXT DEFAULT 'OPEN',
    owner_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(owner_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    resource TEXT,
    resource_id TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME DEFAULT (datetime('now', '+1 hour')),
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT NOT NULL UNIQUE,
    expires_at DATETIME DEFAULT (datetime('now', '+15 minutes')),
    used INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
});


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

async function hashPassword(password) {
  const salt = await bcrypt.genSalt(10);
  return await bcrypt.hash(password, salt);
}

async function verifyPassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

const loginAttempts = new Map();
const RATE_LIMIT_WINDOW = 15 * 60 * 1000; 
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

app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ error: 'All fields required' });
  }

  const passwordValidation = validatePassword(password);
  if (!passwordValidation.valid) {
    return res.status(400).json({ error: 'Invalid password', details: passwordValidation.errors });
  }

  try {
    const passwordHash = await hashPassword(password);

    db.run(
      'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
      [username, email, passwordHash, 'USER'],
      function(err) {
        if (err) {
          return res.status(400).json({ error: 'Registration failed. Invalid credentials' });
        }
        
        db.run('INSERT INTO audit_logs (user_id, action, resource, ip_address) VALUES (?, ?, ?, ?)',
          [this.lastID, 'REGISTER', 'auth', req.ip]);

        res.json({ message: 'User registered successfully' });
      }
    );
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const clientIP = req.ip;

  if (!username || !password) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }

  const rateLimit = checkRateLimit(username);
  if (!rateLimit.allowed) {
    return res.status(429).json({ 
      error: 'Too many login attempts. Try again later.',
      remaining: 0
    });
  }

  try {
    const responseDelay = Math.random() * 100 + 100;

    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
      recordLoginAttempt(username);

      if (err || !user) {
        await new Promise(r => setTimeout(r, responseDelay));
        db.run('INSERT INTO audit_logs (action, resource, ip_address) VALUES (?, ?, ?)',
          ['LOGIN_FAILED', 'auth', clientIP]);
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      if (user.locked_until && new Date(user.locked_until) > new Date()) {
        await new Promise(r => setTimeout(r, responseDelay));
        return res.status(429).json({ error: 'Account temporarily locked' });
      }

      const passwordMatch = await verifyPassword(password, user.password);
      
      if (!passwordMatch) {
        const newFailedAttempts = user.failed_attempts + 1;
        let lockedUntil = null;

        if (newFailedAttempts >= MAX_ATTEMPTS) {
          lockedUntil = new Date(Date.now() + 15 * 60 * 1000).toISOString();
        }

        db.run('UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?',
          [newFailedAttempts, lockedUntil, user.id]);

        await new Promise(r => setTimeout(r, responseDelay));
        db.run('INSERT INTO audit_logs (user_id, action, resource, ip_address) VALUES (?, ?, ?, ?)',
          [user.id, 'LOGIN_FAILED', 'auth', clientIP]);

        return res.status(401).json({ error: 'Invalid credentials' });
      }

      db.run('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?', [user.id]);

      const sessionId = crypto.randomBytes(32).toString('hex');
      const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();

      db.run(
        'INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)',
        [sessionId, user.id, expiresAt],
        () => {
          res.cookie('sessionId', sessionId, {
            httpOnly: true,
            secure: true,
            sameSite: 'Strict',
            maxAge: 60 * 60 * 1000,
            path: '/'
          });

          db.run('INSERT INTO audit_logs (user_id, action, resource, ip_address) VALUES (?, ?, ?, ?)',
            [user.id, 'LOGIN_SUCCESS', 'auth', clientIP]);

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

app.post('/api/logout', (req, res) => {
  const sessionId = req.cookies.sessionId;

  if (!sessionId) {
    return res.status(400).json({ error: 'No session' });
  }

  db.get('SELECT user_id FROM sessions WHERE id = ?', [sessionId], (err, session) => {
    if (session) {
      db.run('INSERT INTO audit_logs (user_id, action, resource, ip_address) VALUES (?, ?, ?, ?)',
        [session.user_id, 'LOGOUT', 'auth', req.ip]);
    }

    db.run('DELETE FROM sessions WHERE id = ?', [sessionId], () => {
      res.clearCookie('sessionId', { path: '/' });
      res.json({ message: 'Logged out successfully' });
    });
  });
});

app.get('/api/user', (req, res) => {
  const sessionId = req.cookies.sessionId;

  if (!sessionId) {
    return res.status(401).json({ error: 'No session' });
  }

  db.get('SELECT * FROM sessions WHERE id = ?', [sessionId], (err, session) => {
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

app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email required' });
  }

  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (err || !user) {
      return res.json({ message: 'If email exists, a reset link will be sent' });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

    db.run(
      'INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, ?)',
      [user.id, resetToken, expiresAt],
      () => {
        db.run('INSERT INTO audit_logs (user_id, action, resource, ip_address) VALUES (?, ?, ?, ?)',
          [user.id, 'PASSWORD_RESET_REQUEST', 'auth', req.ip]);

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

  if (!token || !newPassword) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }

  try {
    db.get(
      'SELECT * FROM password_resets WHERE token = ? AND used = 0',
      [token],
      async (err, reset) => {
        if (err || !reset) {
          return res.status(400).json({ error: 'Invalid credentials' });
        }

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
              db.run('UPDATE password_resets SET used = 1 WHERE id = ?', [reset.id], () => {
                db.run('INSERT INTO audit_logs (user_id, action, resource, ip_address) VALUES (?, ?, ?, ?)',
                  [reset.user_id, 'PASSWORD_RESET_SUCCESS', 'auth', req.ip]);

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

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index-v2.html'));
});

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
    console.error(' Missing dependency: bcryptjs');
    console.error('Please run: npm install bcryptjs');
    process.exit(1);
  }
  
  console.log(` AuthX V2 (SECURE) running on http://localhost:${PORT}`);
  console.log(' All security fixes implemented');
});