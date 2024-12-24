# OWASP Top 10 2021 Security Risks

## Table of Contents

1. [Broken Access Control](#broken-access-control)
2. [Cryptographic Failures](#cryptographic-failures)
3. [Injection](#injection)
4. [Insecure Design](#insecure-design)
5. [Security Misconfiguration](#security-misconfiguration)
6. [Vulnerable Components](#vulnerable-components)
7. [Authentication Failures](#authentication-failures)
8. [Software & Data Integrity Failures](#software--data-integrity-failures)
9. [Security Logging & Monitoring Failures](#security-logging--monitoring-failures)
10. [Server-Side Request Forgery](#server-side-request-forgery)

## Broken Access Control

### Description

Broken Access Control occurs when users can act outside of their intended permissions. This happens when access restrictions are not properly enforced, allowing attackers to:

-   View unauthorized information
-   Modify other users' data
-   Access administrative functions
-   Manipulate access controls

### Common Vulnerabilities

1. **Insecure Direct Object References (IDOR)**

    - Directly accessing resources through IDs without verification
    - Example: Changing URL from /api/users/2 to /api/users/1 to access another user's data

2. **Missing Function Level Access Control**

    - Hidden admin functions accessible to regular users
    - Example: Admin functions visible in HTML but not in UI can still be called

3. **Privilege Escalation**
    - Vertical: User gains admin privileges
    - Horizontal: User accesses other users' data

### Prevention

```javascript
// Implement Role-Based Access Control (RBAC)
const accessControl = {
    roles: {
        ADMIN: ['read', 'write', 'delete'],
        USER: ['read'],
    },
    check(user, action) {
        return this.roles[user.role]?.includes(action) ?? false
    },
}

// Implement resource-based access control
app.get('/api/documents/:id', (req, res) => {
    const doc = documents.find(d => d.id === req.params.id)
    if (!doc) return res.status(404).send()
    if (doc.userId !== req.user.id) return res.status(403).send()
    res.json(doc)
})

// Middleware for function-level access control
function requireRole(role) {
    return (req, res, next) => {
        if (req.user.role !== role) {
            return res.status(403).json({ error: 'Access denied' })
        }
        next()
    }
}

app.post('/api/admin/users', requireRole('ADMIN'), (req, res) => {
    // Only admins can access this endpoint
})
```

## Cryptographic Failures

### Description

Cryptographic failures, previously known as Sensitive Data Exposure, occur when sensitive data is not properly protected. This includes:

-   Transmitting sensitive data in clear text
-   Using weak or outdated cryptographic algorithms
-   Using default or weak keys
-   Not enforcing encryption

### Common Vulnerabilities

1. **Weak Password Storage**

    - Using plain text passwords
    - Using weak hashing algorithms (MD5, SHA1)
    - Not using salts with hashes

2. **Data in Transit**

    - Missing TLS encryption
    - Using outdated SSL/TLS versions
    - Accepting weak ciphers

3. **Insecure Key Storage**
    - Hardcoded encryption keys
    - Keys in source code or config files
    - Weak key generation

### Prevention

```javascript
// 1. Password Hashing
const bcrypt = require('bcrypt')
const saltRounds = 12

async function hashPassword(password) {
    return await bcrypt.hash(password, saltRounds)
}

async function verifyPassword(password, hash) {
    return await bcrypt.compare(password, hash)
}

// 2. Data Encryption
const crypto = require('crypto')
const algorithm = 'aes-256-gcm'

function encrypt(text, secretKey) {
    const iv = crypto.randomBytes(16)
    const salt = crypto.randomBytes(64)
    const key = crypto.pbkdf2Sync(secretKey, salt, 100000, 32, 'sha512')
    const cipher = crypto.createCipheriv(algorithm, key, iv)

    const encrypted = Buffer.concat([
        cipher.update(text, 'utf8'),
        cipher.final(),
    ])
    const tag = cipher.getAuthTag()

    return {
        encrypted: encrypted.toString('hex'),
        iv: iv.toString('hex'),
        salt: salt.toString('hex'),
        tag: tag.toString('hex'),
    }
}

// 3. HTTPS Configuration
const https = require('https')
const fs = require('fs')

const options = {
    key: fs.readFileSync('private-key.pem'),
    cert: fs.readFileSync('certificate.pem'),
    cipherSuites: ['TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384'],
    minVersion: 'TLSv1.2',
}

https.createServer(options, app).listen(443)
```

## Injection

### Description

Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. The attacker's hostile data can trick the interpreter into executing unintended commands or accessing unauthorized data.

### Types of Injection

1. **SQL Injection**

    - Inserting malicious SQL code
    - Example: `' OR '1'='1` in login forms
    - Can lead to data theft, modification, or deletion

2. **Command Injection**

    - Executing system commands through application
    - Example: `;rm -rf /` in a file name input
    - Can lead to system compromise

3. **NoSQL Injection**
    - Manipulating NoSQL queries
    - Example: Using `$gt` operator in MongoDB queries
    - Can bypass authentication or access unauthorized data

### Prevention

```javascript
// 1. SQL Injection Prevention
const mysql = require('mysql2')
const pool = mysql.createPool({
    host: 'localhost',
    user: 'user',
    database: 'test',
})

// BAD: Vulnerable to SQL injection
app.get('/api/users', (req, res) => {
    const query = `SELECT * FROM users WHERE name = '${req.query.name}'`
    pool.query(query) // NEVER DO THIS
})

// GOOD: Using prepared statements
app.get('/api/users', (req, res) => {
    pool.execute('SELECT * FROM users WHERE name = ?', [req.query.name])
})

// 2. Command Injection Prevention
const { spawn } = require('child_process')

// BAD: Vulnerable to command injection
app.get('/api/files', (req, res) => {
    exec(`ls ${req.query.dir}`, (error, stdout) => {
        res.send(stdout)
    })
})

// GOOD: Using spawn with arguments array
app.get('/api/files', (req, res) => {
    if (!/^[a-zA-Z0-9-_/]+$/.test(req.query.dir)) {
        return res.status(400).send('Invalid directory name')
    }
    const ls = spawn('ls', [req.query.dir])
    ls.stdout.pipe(res)
})

// 3. NoSQL Injection Prevention
// BAD: Vulnerable to NoSQL injection
app.post('/api/login', async (req, res) => {
    const user = await User.findOne({
        username: req.body.username,
        password: req.body.password,
    })
})

// GOOD: Proper query construction
app.post('/api/login', async (req, res) => {
    const user = await User.findOne({
        username: String(req.body.username),
    })
    if (!user || !(await bcrypt.compare(req.body.password, user.password))) {
        return res.status(401).send('Invalid credentials')
    }
})
```

## Insecure Design

### Description

Insecure Design refers to risks stemming from design and architectural flaws. Unlike implementation bugs, these are flaws baked into the application's requirements and design.

### Common Issues

1. **Missing Rate Limits**

    - Allows brute force attacks
    - Resource exhaustion
    - DoS vulnerability

2. **Insufficient Input Validation**

    - Accepting any input format
    - Missing business logic validation
    - Inadequate data sanitization

3. **Weak Authentication Design**
    - Single-factor authentication for sensitive operations
    - Weak password recovery mechanisms
    - Missing multi-step verification for critical actions

### Prevention

```javascript
// 1. Rate Limiting Implementation
const rateLimit = require('express-rate-limit')

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts
    message: 'Too many login attempts, please try again later',
    standardHeaders: true,
    legacyHeaders: false,
})

app.post('/api/login', loginLimiter, (req, res) => {
    // Login logic...
})

// 2. Input Validation Design
const Joi = require('joi')

const userSchema = Joi.object({
    username: Joi.string().alphanum().min(3).max(30).required(),
    password: Joi.string()
        .pattern(new RegExp('^[a-zA-Z0-9]{8,30}$'))
        .required(),
    email: Joi.string().email().required(),
})

app.post('/api/users', (req, res) => {
    const { error } = userSchema.validate(req.body)
    if (error) {
        return res.status(400).json({
            error: error.details[0].message,
        })
    }
    // Process valid input...
})

// 3. Multi-Step Operations
const multiStep = {
    steps: new Map(),

    start(userId, operation) {
        const token = crypto.randomBytes(32).toString('hex')
        this.steps.set(token, {
            userId,
            operation,
            step: 1,
            timestamp: Date.now(),
        })
        return token
    },

    verify(token, step) {
        const op = this.steps.get(token)
        if (!op || op.step !== step || Date.now() - op.timestamp > 300000) {
            return false
        }
        op.step++
        return true
    },
}

// Example usage for critical operation
app.post('/api/critical-operation/start', (req, res) => {
    const token = multiStep.start(req.user.id, 'delete-account')
    // Send email verification...
    res.json({ token })
})

app.post('/api/critical-operation/confirm', (req, res) => {
    if (!multiStep.verify(req.body.token, 1)) {
        return res.status(400).send('Invalid or expired token')
    }
    // Complete operation...
})
```

## Security Misconfiguration

### Description

Security misconfiguration is the most commonly seen vulnerability. It occurs when security settings are defined, implemented, or maintained improperly. This includes:

-   Default configurations left unchanged
-   Incomplete configurations
-   Open cloud storage
-   Misconfigured HTTP headers
-   Verbose error messages

### Common Vulnerabilities

1. **Default Configurations**

    - Default admin credentials unchanged
    - Default permissions too permissive
    - Sample applications left on production servers
    - Example: Default admin/admin credentials on CMS systems

2. **Information Disclosure**

    - Detailed error messages exposed to users
    - Stack traces visible in production
    - Version numbers and technology stack exposed
    - Example: Database errors showing SQL queries

3. **Missing Security Headers**
    - No HTTPS enforcement
    - Missing CORS policies
    - No protection against clickjacking
    - Example: Missing X-Frame-Options allowing clickjacking attacks

### Prevention

```javascript
// Security header implementation
const helmet = require('helmet')
app.use(helmet())

// Custom headers for specific protection
app.use((req, res, next) => {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000')
    res.setHeader('Content-Security-Policy', "default-src 'self'")
    next()
})
```

## Vulnerable Components

### Description

Applications using components with known vulnerabilities may undermine application defenses and enable various attacks. Common issues include:

-   Outdated dependencies
-   Unsupported system components
-   Vulnerable client-side libraries
-   Lack of security patch management

### Common Vulnerabilities

1. **Dependency Issues**

    - Using outdated npm packages
    - Unmaintained third-party components
    - Known CVEs in dependencies
    - Example: Log4Shell vulnerability in Log4j

2. **Version Management**
    - No version tracking
    - Inconsistent dependency versions
    - Missing security updates
    - Example: Using jQuery 1.x with known XSS vulnerabilities

### Prevention

```javascript
// Regular dependency audits
{
    "scripts": {
        "audit": "npm audit",
        "outdated": "npm outdated"
    }
}
```

## Authentication Failures

### Description

Authentication failures occur when functions related to user identity, authentication, or session management are implemented incorrectly. This allows attackers to:

-   Compromise passwords, keys, or session tokens
-   Exploit implementation flaws to assume other users' identities
-   Bypass authentication methods

### Common Vulnerabilities

1. **Weak Credentials**

    - Weak password requirements
    - No protection against brute force
    - Predictable credential recovery
    - Example: Allowing "password123" as valid password

2. **Session Management**

    - Session fixation
    - Exposed session IDs
    - Missing session timeouts
    - Example: Not invalidating session after password change

3. **Implementation Flaws**
    - Broken remember-me functionality
    - Missing multi-factor authentication
    - Weak password recovery
    - Example: Security questions with guessable answers

### Prevention

```javascript
// Session security implementation
app.use(
    session({
        secret: process.env.SESSION_SECRET,
        cookie: { secure: true, httpOnly: true },
        resave: false,
        saveUninitialized: false,
    })
)
```

## Software & Data Integrity Failures

### Description

Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations. This includes:

-   Untrusted software updates
-   Critical data tampering
-   CI/CD pipeline vulnerabilities

### Common Vulnerabilities

1. **Update Integrity**

    - Unsigned software updates
    - No checksum verification
    - Insecure update channels
    - Example: Man-in-the-middle during auto-updates

2. **Pipeline Security**
    - Unsecured CI/CD pipelines
    - No code signing
    - Compromised build processes
    - Example: Supply chain attacks through build dependencies

### Prevention

```javascript
// Subresource integrity
<script
    src='https://example.com/script.js'
    integrity='sha384-hash'
    crossorigin='anonymous'
></script>
```

## Security Logging & Monitoring Failures

### Description

This category helps detect, escalate, and respond to active breaches. Without logging and monitoring, breaches cannot be detected. Common issues include:

-   Missing log entries
-   Unclear log messages
-   Logs not monitored
-   No real-time alerting

### Common Vulnerabilities

1. **Insufficient Logging**

    - Login attempts not logged
    - Failed access attempts ignored
    - Missing audit trails
    - Example: Unable to trace unauthorized access attempts

2. **Poor Monitoring**
    - No automated alerts
    - Delayed breach detection
    - Inadequate log storage
    - Example: Data breach discovered months after occurrence

### Prevention

```javascript
// Structured logging implementation
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.json(),
    defaultMeta: { service: 'user-service' },
    transports: [
        new winston.transports.File({ filename: 'error.log', level: 'error' }),
        new winston.transports.File({ filename: 'combined.log' }),
    ],
})
```

## Server-Side Request Forgery (SSRF)

### Description

SSRF flaws occur when a web application is fetching a remote resource without validating the user-supplied URL. It enables an attacker to coerce the application to send a crafted request to an unexpected destination, even when protected by a firewall or VPN.

### Common Vulnerabilities

1. **Direct SSRF**

    - Unvalidated URL inputs
    - Access to internal services
    - Cloud metadata access
    - Example: Accessing AWS metadata through http://169.254.169.254

2. **Indirect SSRF**
    - File inclusion
    - Image processing
    - PDF generators
    - Example: Including internal network files in PDF reports

### Prevention

```javascript
// URL validation implementation
async function validateUrl(urlString) {
    const url = new URL(urlString)
    const privateRanges = [
        /^127\./,
        /^10\./,
        /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
        /^192\.168\./,
    ]

    // Check for private IP ranges
    const ipAddress = await dns.resolve4(url.hostname)
    if (privateRanges.some(range => range.test(ipAddress[0]))) {
        throw new Error('Private IP not allowed')
    }
    return url
}
```

## Additional Resources

-   [OWASP Top 10 Project](https://owasp.org/www-project-top-ten/)
-   [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
-   [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

## Demo Instructions

Check individual security topic folders for specific demonstrations:

-   SQL Injection: `./SQL-Injection/`
-   XSS: `./XSS/`
-   CSRF: `./CSRF/`
-   Authentication: `./Auth/`
-   IFrame Security: `./IFrame-Security/`

Each folder contains vulnerable and secure implementations for learning purposes.
