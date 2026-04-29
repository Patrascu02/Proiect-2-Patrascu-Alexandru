/**
 * PROIECT 2: BREAK THE LOGIN - VERSIUNEA VULNERABILĂ (V1)
 * 
 * VULNERABILITĂȚI INTENȚIONATE:
 * 1. Weak password policy - Parole foarte scurte acceptate
 * 2. Insecure password storage - MD5 hash slab
 * 3. No rate limiting - Brute force nelimitat
 * 4. User enumeration - Mesaje diferite pentru user inexistent vs parolă greșită
 * 5. Insecure session management - Cookie fără Secure/HttpOnly/SameSite, expirare lungă
 * 6. Insecure password reset - Token predictibil, reutilizabil, fără expirare
 */

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3001;

// Configurare
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

// Bază de date SQLite
const db = new sqlite3.Database('./authx_v1.db', (err) => {
  if (err) console.error('Database error:', err);
  console.log('Connected to SQLite database (V1 - Vulnerable)');
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
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Tabelul sesiunilor (cu vulnerabilități)
  db.run(`CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME DEFAULT (datetime('now', '+30 days')),
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  // Tabelul reset token-uri (vulnerabil)
  db.run(`CREATE TABLE IF NOT EXISTS password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  // Tabelul login attempts (pentru analiză)
  db.run(`CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    success INTEGER,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT
  )`);
});

// ============ VULNERABILITATE #1 & #2: WEAK PASSWORD POLICY + INSECURE STORAGE ============
// MD5 hash (slab și deprecat!)
function hashPasswordMD5(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

// REGISTER - cu vulnerabilități
app.post('/api/register', (req, res) => {
  const { username, email, password } = req.body;

  // VULNERABILITATE #1: Fără validare de lungime minimă sau complexitate
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'All fields required' });
  }

  // Se acceptă parole scurte și triviale!
  if (password.length < 3) {
    return res.status(400).json({ error: 'Password too short' });
  }

  // VULNERABILITATE #2: Parola stocată cu MD5 (hash slab!)
  const passwordHash = hashPasswordMD5(password);

  db.run(
    'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
    [username, email, passwordHash, 'USER'],
    (err) => {
      if (err) {
        // VULNERABILITATE #4: Mesaje diferite pentru utilizator existent
        if (err.message.includes('UNIQUE')) {
          return res.status(400).json({ error: 'User already exists' });
        }
        return res.status(500).json({ error: 'Registration error' });
      }
      res.json({ message: 'User registered successfully' });
    }
  );
});

// LOGIN - cu vulnerabilități
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  // Log attempt (pentru audit - neprotejat)
  db.run('INSERT INTO login_attempts (username, success) VALUES (?, ?)',
    [username, 0]);

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  // VULNERABILITATE #3: Fără rate limiting - se pot încerca parole nelimitat
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err) return res.status(500).json({ error: 'Server error' });

    // VULNERABILITATE #4: Răspunsuri diferite - enumerare de utilizatori
    if (!user) {
      return res.status(401).json({ error: 'User not found' }); // Mesaj diferit!
    }

    const passwordHash = hashPasswordMD5(password);
    if (user.password !== passwordHash) {
      return res.status(401).json({ error: 'Invalid password' }); // Alt mesaj!
    }

    // Login reușit
    db.run('UPDATE login_attempts SET success = 1 WHERE username = ? ORDER BY timestamp DESC LIMIT 1',
      [username]);

    // VULNERABILITATE #5: Session/Token cu probleme
    // Sesiunea se creează fără setări de securitate
    const sessionId = crypto.randomBytes(16).toString('hex');
    
    db.run(
      'INSERT INTO sessions (id, user_id) VALUES (?, ?)',
      [sessionId, user.id],
      () => {
        // Cookie fără HttpOnly, Secure, SameSite și expirare prea lungă (30 zile)
        res.cookie('sessionId', sessionId, {
          httpOnly: false,  // VULNERABILITATE - Accesibil din JavaScript (XSS)
          secure: false,    // VULNERABILITATE - Se trimite și pe HTTP
          sameSite: 'Lax',  // VULNERABILITATE - Expus la CSRF
          maxAge: 30 * 24 * 60 * 60 * 1000 // 30 zile - prea mult!
        });

        res.json({ 
          message: 'Login successful',
          sessionId: sessionId, // Token expus în response!
          user: { id: user.id, username: user.username, email: user.email }
        });
      }
    );
  });
});

// LOGOUT
app.post('/api/logout', (req, res) => {
  const { sessionId } = req.body;

  if (!sessionId) {
    return res.status(400).json({ error: 'Session ID required' });
  }

  db.run('DELETE FROM sessions WHERE id = ?', [sessionId], () => {
    res.clearCookie('sessionId');
    res.json({ message: 'Logged out successfully' });
  });
});

// GET USER (verifică sesiune)
app.get('/api/user', (req, res) => {
  const sessionId = req.cookies.sessionId || req.query.sessionId;

  if (!sessionId) {
    return res.status(401).json({ error: 'No session' });
  }

  db.get('SELECT * FROM sessions WHERE id = ?', [sessionId], (err, session) => {
    if (err || !session) {
      return res.status(401).json({ error: 'Invalid session' });
    }

    db.get('SELECT id, username, email, role FROM users WHERE id = ?', [session.user_id], (err, user) => {
      if (err || !user) {
        return res.status(401).json({ error: 'User not found' });
      }

      res.json({ user });
    });
  });
});

// ============ VULNERABILITATE #6: INSECURE PASSWORD RESET ============
app.post('/api/forgot-password', (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email required' });
  }

  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (err || !user) {
      // Mesaj generic pentru a nu arăta dacă email-ul există
      return res.json({ message: 'If email exists, reset link sent' });
    }

    // VULNERABILITATE #6: Token predictibil (doar ID-ul utilizatorului!)
    const resetToken = user.id.toString(); // EXTREM DE SLAB!

    db.run(
      'INSERT INTO password_resets (user_id, token) VALUES (?, ?)',
      [user.id, resetToken],
      () => {
        res.json({ 
          message: 'Password reset link sent',
          // EXPUS! Nu ar trebui să fie în răspuns în producție
          resetLink: `http://localhost:3001/reset-password?token=${resetToken}`
        });
      }
    );
  });
});

// RESET PASSWORD
app.post('/api/reset-password', (req, res) => {
  const { token, newPassword } = req.body;

  if (!token || !newPassword) {
    return res.status(400).json({ error: 'Token and password required' });
  }

  // VULNERABILITATE #6: Token nu are expirare și poate fi reutilizat
  db.get('SELECT * FROM password_resets WHERE token = ?', [token], (err, reset) => {
    if (err || !reset) {
      return res.status(400).json({ error: 'Invalid reset token' });
    }

    // Parola nu este validată!
    const passwordHash = hashPasswordMD5(newPassword);

    db.run(
      'UPDATE users SET password = ? WHERE id = ?',
      [passwordHash, reset.user_id],
      () => {
        // Token-ul NU este șters după utilizare - poate fi reutilizat!
        res.json({ message: 'Password reset successfully' });
      }
    );
  });
});

// Page - index
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index-v1.html'));
});

app.listen(PORT, () => {
  console.log(`🔓 AuthX V1 (VULNERABLE) running on http://localhost:${PORT}`);
  console.log('⚠️  WARNING: This version has intentional security vulnerabilities!');
});
