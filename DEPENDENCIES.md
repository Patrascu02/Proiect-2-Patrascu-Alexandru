# Dependencies for AuthX - Break the Login

This project requires Node.js and npm to run.

## Installation

### 1. Install Node.js and npm

**Ubuntu/Debian:**
```bash
curl -fsSL https://deb.nodesource.com/setup_16.x | sudo -E bash -
sudo apt-get install -y nodejs
```

**macOS (with Homebrew):**
```bash
brew install node
```

**Windows:**
Download from https://nodejs.org/

### 2. Verify Installation

```bash
node --version   # Should show v14.0.0 or higher
npm --version    # Should show 6.0.0 or higher
```

### 3. Install Project Dependencies

```bash
cd /var/www/html/Desktop/Proiect-2-Patrascu-Alexandru
npm install
```

### 4. Optional: Install bcryptjs Separately

```bash
npm install bcryptjs
```

## Dependencies List

The `package.json` includes:

- **express** - Web server framework
- **sqlite3** - Database engine
- **body-parser** - JSON parser
- **cors** - CORS middleware
- **uuid** - ID generation
- **jsonwebtoken** - JWT support
- **bcryptjs** - Secure password hashing (for v2)

## Troubleshooting

### "npm: command not found"
Install Node.js from https://nodejs.org/

### "ERR! peer dep missing"
Run: `npm install --legacy-peer-deps`

### "Cannot find module 'express'"
Run: `npm install` in project directory

### Port 3001 or 3002 already in use
Change PORT variable in server-v1.js or server-v2.js

## Post-Installation

After `npm install`, verify with:

```bash
npm start:v1  # Should run without errors
npm start:v2  # Should run without errors
```

Both should display:
-  Connected to SQLite database
-  Server running on http://localhost:PORT
