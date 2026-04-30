

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const cookieParser = require('cookie-parser'); 

const app = express();
const PORT = 3001;

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static('public'));

const db = new sqlite3.Database('./authx_v1.db', (err) => {
  if (err) console.error('Database error:', err);
  console.log('Connected to SQLite database (V1 - Vulnerable)');
});

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'USER',
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
    expires_at DATETIME DEFAULT (datetime('now', '+30 days')),
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
});


function hashPasswordMD5(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

app.post('/api/register', (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ error: 'All fields required' });
  }

  if (password.length < 3) {
    return res.status(400).json({ error: 'Password too short' });
  }

  const passwordHash = hashPasswordMD5(password);

  db.run(
    'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
    [username, email, passwordHash, 'USER'],
    function(err) {
      if (err) {
        if (err.message.includes('UNIQUE')) {
          return res.status(400).json({ error: 'User already exists' });
        }
        return res.status(500).json({ error: 'Registration error' });
      }
      
      db.run('INSERT INTO audit_logs (user_id, action, resource, ip_address) VALUES (?, ?, ?, ?)',
        [this.lastID, 'REGISTER', 'auth', req.ip]);

      res.json({ message: 'User registered successfully' });
    }
  );
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const clientIP = req.ip;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err) return res.status(500).json({ error: 'Server error' });

    if (!user) {
      db.run('INSERT INTO audit_logs (action, resource, ip_address) VALUES (?, ?, ?)',
        ['LOGIN_FAILED', 'auth', clientIP]);
      return res.status(401).json({ error: 'User not found' }); 
    }

    const passwordHash = hashPasswordMD5(password);
    if (user.password !== passwordHash) {
      db.run('INSERT INTO audit_logs (user_id, action, resource, ip_address) VALUES (?, ?, ?, ?)',
        [user.id, 'LOGIN_FAILED', 'auth', clientIP]);
      return res.status(401).json({ error: 'Invalid password' }); 
    }

    db.run('INSERT INTO audit_logs (user_id, action, resource, ip_address) VALUES (?, ?, ?, ?)',
      [user.id, 'LOGIN_SUCCESS', 'auth', clientIP]);

    const sessionId = crypto.randomBytes(16).toString('hex');
    
    db.run(
      'INSERT INTO sessions (id, user_id) VALUES (?, ?)',
      [sessionId, user.id],
      () => {
        res.cookie('sessionId', sessionId, {
          httpOnly: false,  
          secure: false,    
          sameSite: 'Lax', 
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

app.post('/api/logout', (req, res) => {
  const sessionId = req.body.sessionId || req.cookies.sessionId;

  if (!sessionId) {
    return res.status(400).json({ error: 'Session ID required' });
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

app.post('/api/forgot-password', (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email required' });
  }

  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (err || !user) {
      return res.json({ message: 'If email exists, reset link sent' });
    }

    const resetToken = user.id.toString(); 

    db.run(
      'INSERT INTO password_resets (user_id, token) VALUES (?, ?)',
      [user.id, resetToken],
      () => {
        db.run('INSERT INTO audit_logs (user_id, action, resource, ip_address) VALUES (?, ?, ?, ?)',
          [user.id, 'PASSWORD_RESET_REQUEST', 'auth', req.ip]);

        res.json({ 
          message: 'Password reset link sent',
          resetLink: `http://localhost:3001/reset-password?token=${resetToken}`
        });
      }
    );
  });
});

app.post('/api/reset-password', (req, res) => {
  const { token, newPassword } = req.body;

  if (!token || !newPassword) {
    return res.status(400).json({ error: 'Token and password required' });
  }

  db.get('SELECT * FROM password_resets WHERE token = ?', [token], (err, reset) => {
    if (err || !reset) {
      return res.status(400).json({ error: 'Invalid reset token' });
    }

    const passwordHash = hashPasswordMD5(newPassword);

    db.run(
      'UPDATE users SET password = ? WHERE id = ?',
      [passwordHash, reset.user_id],
      () => {
        db.run('INSERT INTO audit_logs (user_id, action, resource, ip_address) VALUES (?, ?, ?, ?)',
          [reset.user_id, 'PASSWORD_RESET_SUCCESS', 'auth', req.ip]);

        res.json({ message: 'Password reset successfully' });
      }
    );
  });
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index-v1.html'));
});

app.listen(PORT, () => {
  console.log(` AuthX V1 (VULNERABLE) running on http://localhost:${PORT}`);
  console.log('  WARNING: This version has intentional security vulnerabilities!');
});