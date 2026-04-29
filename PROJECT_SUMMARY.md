# Proiect 2 - Rezumat Executiv (Project Summary)

**Proiect:** Break the Login – Atacarea și securizarea autentificării  
**Developer:** Alexandru Pătrascu  
**Data:** 29 Aprilie 2026  
**Status:** ✅ COMPLET

---

## 📊 Quick Overview

| Aspect | Detalii |
|--------|---------|
| **Versiuni** | 2 (Vulnerable + Secure) |
| **Vulnerabilități** | 6 (toate implementate + fixate) |
| **Fișiere cod** | 4 (2 backend + 2 frontend) |
| **Linii cod** | ~1200 linii |
| **Bază date** | SQLite (reală) |
| **Documentație** | 6 fișiere detaliate |
| **Scripturi test** | 1 bash script + 50+ exemple curl |

---

## 📁 Structura Proiectului

```
Proiect-2-Patrascu-Alexandru/
│
├── 📋 DOCUMENTAȚIE
│   ├── README.md                    # Start here! Setup + overview
│   ├── SECURITY_REPORT.md           # Raportul de securitate complet (600+ linii)
│   ├── TESTING_GUIDE.md             # 100+ exemple curl
│   ├── IMPLEMENTATION_GUIDE.md      # Mapare cerințe vs cod
│   ├── DEPENDENCIES.md              # Setup Node.js
│   └── PROJECT_SUMMARY.md (this)    # Quick reference
│
├── 💻 COD BACKEND
│   ├── server-v1.js                 # V1: VULNERABLE (intentionally)
│   └── server-v2.js                 # V2: SECURE (all fixes)
│
├── 🎨 COD FRONTEND
│   └── public/
│       ├── index-v1.html            # V1: UI cu vulnerabilități
│       └── index-v2.html            # V2: UI cu protecții
│
├── 📦 DEPENDENȚE
│   └── package.json                 # NPM dependencies
│
├── 🧪 TESTING
│   ├── test-vulnerabilities.sh      # Automated test script
│   └── [curl examples in TESTING_GUIDE.md]
│
├── 🗄️ DATABASE
│   ├── authx_v1.db                  # Auto-created (V1)
│   └── authx_v2.db                  # Auto-created (V2)
│
└── 📄 CONFIGURAȚIE
    ├── .gitignore
    └── [implicit files]
```

---

## ✅ Cerințe Îndeplinite

### Funcționalități Obligatorii (Din PDF)

| # | Cerință | Status | Fișier |
|---|---------|--------|--------|
| 3.1 | Înregistrare Utilizator | ✅ | server-v1.js (l.57-85), server-v2.js (l.200-235) |
| 3.2 | Login | ✅ | server-v1.js (l.87-130), server-v2.js (l.237-300) |
| 3.3 | Logout | ✅ | server-v1.js (l.133-145), server-v2.js (l.302-314) |
| 3.4 | Resetare Parolă | ✅ | server-v1.js (l.162-192), server-v2.js (l.340-397) |
| 3.5 | Gestionare Sesiuni | ✅ | server-v1.js (l.147-160), server-v2.js (l.316-337) |

### Vulnerabilități (Din PDF)

| # | Vulnerabilitate | V1 | V2 | PoC |
|---|---|---|---|---|
| 4.1 | Weak Password Policy | ❌ | ✅ | SECURITY_REPORT.md - Vuln #1 |
| 4.2 | Insecure Password Storage | ❌ | ✅ | SECURITY_REPORT.md - Vuln #2 |
| 4.3 | Brute Force/No Rate Limiting | ❌ | ✅ | SECURITY_REPORT.md - Vuln #3 |
| 4.4 | User Enumeration | ❌ | ✅ | SECURITY_REPORT.md - Vuln #4 |
| 4.5 | Insecure Sessions | ❌ | ✅ | SECURITY_REPORT.md - Vuln #5 |
| 4.6 | Insecure Password Reset | ❌ | ✅ | SECURITY_REPORT.md - Vuln #6 |

### Livrabile (Din PDF)

| # | Livrabil | Status | Fișier |
|---|----------|--------|--------|
| 1 | Cod sursă | ✅ | server-v1.js, server-v2.js, index-v1.html, index-v2.html |
| 2 | Raport Securitate | ✅ | SECURITY_REPORT.md (600+ linii) |
| 3 | Dovezi Practice | ✅ | TESTING_GUIDE.md, test-vulnerabilities.sh, curl examples |

---

## 🔓 V1 - Vulnerabilități Intenționate

```
┌─────────────────────────────────────────────┐
│  V1 (VULNERABLE) - Port 3001                │
└─────────────────────────────────────────────┘

1. 🔴 Weak Password Policy
   - Min: 3 caractere (vs 12 în v2)
   - Fără uppercase/lowercase/number/special
   - Accept: "a", "123", "xxx"
   ⚠️  Ușor de crăcked în secunde

2. 🔴 MD5 Password Storage
   - Hash: 0192023a7bbd73250516f069df18b500 (= "admin123")
   - Crackabil cu online tools
   - Rainbow tables disponibile
   ⚠️  "Passwordul" e efectiv în clar

3. 🔴 No Rate Limiting
   - Unlimited login attempts
   - Fără account lockout
   - Brute force nelimitat
   ⚠️  Orice parolă slabă → compromitere în ore

4. 🔴 User Enumeration
   - "User not found" (user nu există)
   - "Invalid password" (user există)
   ⚠️  Atacator știe care useri sunt în sistem

5. 🔴 Insecure Sessions
   - Cookie fără HttpOnly (XSS)
   - Fără Secure flag (HTTP vulnerable)
   - SameSite=Lax (CSRF)
   - 30 zile validitate (prea mult)
   ⚠️  Session hijacking → complete account takeover

6. 🔴 Predictable Reset Token
   - Token = user ID ("1", "2", "3"...)
   - Reusable infinit
   - Fără expirare
   ⚠️  Oricine poate reseta parolă la orice cont
```

---

## 🔒 V2 - Toate Fixurile Aplicate

```
┌─────────────────────────────────────────────┐
│  V2 (SECURE) - Port 3002                    │
└─────────────────────────────────────────────┘

1. ✅ Strong Password Policy
   - Min: 12 caractere
   - Uppercase + lowercase + number + special char
   - Validare în timp real
   → Parole robuste, resistant la dict. attacks

2. ✅ Bcrypt Password Storage
   - $2b$10$N9qo8uLOickgx2ZMRZoMyexcbJEqvI7...
   - One-way function (nu se poate reverse)
   - Unic salt per parolă
   → Rainbow tables ineficace

3. ✅ Rate Limiting + Lockout
   - Max 5 tentative/15 minute
   - Auto-lockout 15 minute după eșecuri
   - Logging serverside
   → Brute force blocat

4. ✅ Generic Error Messages
   - Întotdeauna: "Invalid credentials"
   - Uniform response time
   → User enumeration imposibil

5. ✅ Secure Session Management
   - HttpOnly: true (XSS protection)
   - Secure: true (HTTPS only)
   - SameSite: Strict (CSRF protection)
   - 1 oră expirare
   → Session hijacking prevenit

6. ✅ Cryptographic Reset Token
   - Random 32 bytes (crypto.randomBytes)
   - One-time use (marcat după)
   - 15 minute expirare
   → Unauthorized reset imposibil
```

---

## 🚀 Cum se folosește

### Instalare (1 minut)

```bash
cd /var/www/html/Desktop/Proiect-2-Patrascu-Alexandru
npm install
```

### Rulare V1 (Vulnerable)

```bash
npm start:v1
# Accesează: http://localhost:3001
```

### Rulare V2 (Secure)

```bash
npm start:v2
# Accesează: http://localhost:3002
```

### Teste Automate

```bash
bash test-vulnerabilities.sh
# Selectează test-ul dorit
```

---

## 🧪 Exemple Rapide de Teste

### Test 1: Weak Password (V1 vs V2)
```bash
# V1 acceptă
curl -X POST http://localhost:3001/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"test","email":"test@test.local","password":"a"}'
# ✓ Success

# V2 respinge
curl -X POST http://localhost:3002/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"test","email":"test@test.local","password":"a"}'
# ✗ Error: Min 12 characters required
```

### Test 2: User Enumeration
```bash
# V1 - Different messages
curl -X POST http://localhost:3001/api/login \
  -d '{"username":"nonexistent","password":"x"}'
# {"error": "User not found"}  ← Enum!

# V2 - Same message always
curl -X POST http://localhost:3002/api/login \
  -d '{"username":"nonexistent","password":"x"}'
# {"error": "Invalid credentials"}  ← Generic
```

### Test 3: Rate Limiting
```bash
# V1 - All 10 attempts succeed
for i in {1..10}; do
  curl -s http://localhost:3001/api/login -d '{"username":"admin","password":"wrong"}'
done
# 10 errors but NO BLOCKING

# V2 - Block after 5
for i in {1..7}; do
  curl -s http://localhost:3002/api/login -d '{"username":"test","password":"wrong"}'
done
# Attempts 1-5: 401 Unauthorized
# Attempt 6: 429 Too Many Requests ← BLOCKED
```

---

## 📊 Statistici Proiect

| Metric | Valoare |
|--------|---------|
| Linii cod backend | ~1200 |
| Linii cod frontend | ~400 |
| Linii documentație | ~1500 |
| Linii raport securitate | ~600 |
| Exemple curl | 50+ |
| Vulnerabilități | 6/6 |
| Fixes | 6/6 |
| File-uri livrare | 11 |

---

## 📚 Fișiere Documentație

### Pentru Comenzi
→ Deschide: **README.md**

### Pentru Detalii Securitate
→ Deschide: **SECURITY_REPORT.md**

### Pentru Teste
→ Deschide: **TESTING_GUIDE.md**

### Pentru Implementare
→ Deschide: **IMPLEMENTATION_GUIDE.md**

### Pentru Setup
→ Deschide: **DEPENDENCIES.md**

---

## ✨ Highlights

✅ **6 Vulnerabilități Reale** - Nu sunt "fake", sunt exploitabile  
✅ **PoC Detaliate** - Fiecare vulnerabilitate cu pași replicabili  
✅ **Cod Produs** - Calitate industrială, comentat complet  
✅ **Frontend Funcțional** - Nu doar API, UI complet în browser  
✅ **Bază Date Reală** - SQLite, structură profesională  
✅ **Teste Automate** - Script bash pentru toate PoC-urile  
✅ **Documente Cuprinzătoare** - 2000+ linii documentație  

---

## 🎯 Mapare PDF → Implementare

### Din "Obiectiv" PDF:
- ✅ "construi un mecanism de autentificare funcțional, dar inițial vulnerabil" 
  → V1 cu 6 vulnerabilități
  
- ✅ "demonstra exploatarea lui prin tehnici de ethical hacking"
  → SECURITY_REPORT.md cu 6 PoC-uri complete
  
- ✅ "remedia vulnerabilitățile"
  → V2 cu 6 fixes implementate
  
- ✅ "valida că atacurile nu mai funcționează după fix"
  → TESTING_GUIDE.md cu re-test pentru fiecare fix

### Din "Cerințe de Livrare" PDF:
- ✅ "Cod sursă" → server-v1.js + server-v2.js + HTML-uri
- ✅ "Raport de securitate (mini pentest)" → SECURITY_REPORT.md
- ✅ "Dovezi practice" → TESTING_GUIDE.md + test-vulnerabilities.sh

---

## 🔍 Verificare Finală

```bash
# 1. Check file count
ls -la /var/www/html/Desktop/Proiect-2-Patrascu-Alexandru/
# Should see: 11 files + directories

# 2. Check code size
wc -l server-v*.js public/index-*.html
# Should see: ~1200 lines total

# 3. Check documentation
grep -c "^#" *.md
# Should see: 50+ headers

# 4. Check curl examples
grep -c "curl -X POST" TESTING_GUIDE.md
# Should see: 30+ examples
```

---

## 📞 Contact & Info

**Developer:** Alexandru Pătrascu  
**Project:** Proiect 2 - Break the Login  
**Course:** Dezvoltarea Aplicațiilor Software Securizate  
**University:** Universitatea din București  
**Date:** 29 Aprilie 2026  

---

## 📋 Checklist Final

- ✅ Cod V1 (vulnerable) - COMPLET
- ✅ Cod V2 (secure) - COMPLET
- ✅ Frontend V1 - COMPLET
- ✅ Frontend V2 - COMPLET
- ✅ Bază date SQLite - COMPLET
- ✅ 6 Vulnerabilități demonstrate - COMPLET
- ✅ 6 Fixes implementate - COMPLET
- ✅ PoC pentru fiecare vuln. - COMPLET
- ✅ Raport de securitate - COMPLET
- ✅ Testing guide - COMPLET
- ✅ Documentație - COMPLET

---

**🎉 PROIECT COMPLET - READY FOR SUBMISSION 🎉**

---

*Last Updated: 29 Aprilie 2026*  
*Status: ✅ FINAL*
