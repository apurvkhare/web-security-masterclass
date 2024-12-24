# SQL Injection (SQLi)

## Table of Contents

1. [Introduction](#introduction)
2. [Types of SQL Injection](#types-of-sql-injection)
3. [Prevention Techniques](#prevention-techniques)
4. [Parameterized Queries](#parameterized-queries)
5. [ORM Security](#orm-security)
6. [Best Practices](#best-practices)

## Introduction

SQL Injection is a web security vulnerability that allows attackers to interfere with database queries, potentially leading to:

-   Unauthorized data access
-   Data manipulation
-   Data deletion
-   Authentication bypass
-   Command execution

## Types of SQL Injection

### 1. In-band SQLi (Classic)

Direct retrieval of data through the same channel used to inject the SQL code.

#### Error-based

```sql
-- Vulnerable query
SELECT * FROM users WHERE username = 'admin' AND password = ''' -- Causes error

-- Attack payload
admin' OR '1'='1
```

#### Union-based

```sql
-- Vulnerable query
SELECT title, content FROM articles WHERE id = '1'

-- Attack payload
1 UNION SELECT username, password FROM users--
```

### 2. Blind SQLi

When results are not directly visible to the attacker.

#### Boolean-based

```sql
-- Vulnerable query
SELECT * FROM users WHERE username = '$username' AND password = '$password'

-- Attack payload
admin' AND (SELECT ASCII(SUBSTRING(password,1,1)) FROM users WHERE username='admin') > 50--
```

#### Time-based

```sql
-- Attack payload
admin' AND IF(ASCII(SUBSTRING(password,1,1))>50, SLEEP(5), 0)--
```

## Prevention Techniques

### 1. Prepared Statements

```javascript
// Vulnerable
const query = `SELECT * FROM users WHERE username = '${username}'`

// Safe
const query = 'SELECT * FROM users WHERE username = ?'
db.query(query, [username])
```

### 2. Input Validation

```javascript
function validateInput(input) {
    // Remove dangerous characters
    return input.replace(/[;'"\\]/g, '')
}

// Whitelist validation
function isValidUsername(username) {
    return /^[a-zA-Z0-9_]{3,20}$/.test(username)
}
```

### 3. Escaping Special Characters

```javascript
function escapeSQL(unsafe) {
    return unsafe
        .replace(/'/g, "''")
        .replace(/\\/g, '\\\\')
        .replace(/\x00/g, '\\0')
        .replace(/\n/g, '\\n')
        .replace(/\r/g, '\\r')
        .replace(/"/g, '\\"')
}
```

## Parameterized Queries

### Node.js with MySQL

```javascript
// Using prepared statements
const mysql = require('mysql2')

async function safeQuery(username, password) {
    const query = 'SELECT * FROM users WHERE username = ? AND password = ?'
    const [rows] = await pool.execute(query, [username, password])
    return rows
}
```

### Node.js with PostgreSQL

```javascript
const { Pool } = require('pg')

async function safeQuery(username) {
    const query = {
        text: 'SELECT * FROM users WHERE username = $1',
        values: [username],
    }
    const result = await pool.query(query)
    return result.rows
}
```

### Node.js with SQLite

```javascript
const sqlite3 = require('sqlite3')

function safeQuery(username, callback) {
    const query = 'SELECT * FROM users WHERE username = ?'
    db.get(query, [username], callback)
}
```

## ORM Security

### Sequelize Example

```javascript
// Safe by default
const user = await User.findOne({
    where: {
        username: username,
        password: password,
    },
})

// Unsafe raw query
const users = await sequelize.query(
    `SELECT * FROM users WHERE username = '${username}'` // Dangerous!
)

// Safe raw query
const users = await sequelize.query('SELECT * FROM users WHERE username = ?', {
    replacements: [username],
    type: sequelize.QueryTypes.SELECT,
})
```

### Prisma Example

```javascript
// Safe by default
const user = await prisma.user.findUnique({
    where: {
        username: username,
    },
})

// Even raw queries are safe
const result = await prisma.$queryRaw`
    SELECT * FROM users WHERE username = ${username}
`
```

## Best Practices

### 1. Database Configuration

```javascript
// Principle of least privilege
const dbConfig = {
    user: 'app_user',
    password: 'secret',
    database: 'myapp',
    // Limit permissions
    allowedCommands: ['SELECT', 'INSERT', 'UPDATE'],
    // Restrict database access
    host: 'localhost',
    // Use connection pooling
    connectionLimit: 10,
}
```

### 2. Query Construction

-   Use parameterized queries
-   Avoid dynamic table names
-   Validate and sanitize all inputs
-   Use ORMs when possible

### 3. Error Handling

```javascript
// Don't expose SQL errors
app.use((err, req, res, next) => {
    if (err.code === 'ER_PARSE_ERROR') {
        res.status(400).json({
            error: 'Invalid input', // Generic error
        })
    } else {
        next(err)
    }
})
```

### 4. Security Headers

```javascript
app.use((req, res, next) => {
    // Prevent clickjacking
    res.setHeader('X-Frame-Options', 'DENY')
    // Prevent MIME type sniffing
    res.setHeader('X-Content-Type-Options', 'nosniff')
    next()
})
```

## Demo Instructions

The accompanying `index.html` and `server.js` files demonstrate:

1. SQL Injection vulnerability in login form
2. SQL Injection in search functionality
3. Parameterized queries implementation
4. Input validation and sanitization
5. Error handling best practices

Check the demo files to see these security concepts in action.

## NoSQL Injection

### MongoDB Injection Examples

#### 1. Authentication Bypass

```javascript
// Vulnerable query
const user = await User.findOne({
    username: username,
    password: password
});

// Attack payload
username: admin
password[$ne]: null
```

#### 2. Query Operator Injection

```javascript
// Vulnerable query
const users = await User.find({
    role: userInput
});

// Attack payload
role[$regex]: admin.*
```

#### 3. JavaScript Evaluation

```javascript
// Vulnerable query using $where
const users = await User.find({
    $where: `this.balance > ${amount}`,
})

// Attack payload
amount: '0; sleep(5000)'
```

### Prevention Techniques for NoSQL

#### 1. Type Checking

```javascript
// Safe query construction
const query = {
    username: String(username),
    age: Number(age),
}
```

#### 2. Schema Validation

```javascript
const userSchema = new mongoose.Schema({
    username: {
        type: String,
        validate: {
            validator: function (v) {
                return /^[a-zA-Z0-9_]{3,20}$/.test(v)
            },
        },
    },
})
```

#### 3. Query Sanitization

```javascript
function sanitizeMongoQuery(obj) {
    const clean = {}
    for (let key in obj) {
        if (typeof obj[key] === 'object') {
            if (key[0] === '$') continue // Skip operator injection
            clean[key] = sanitizeMongoQuery(obj[key])
        } else {
            clean[key] = obj[key]
        }
    }
    return clean
}
```

## Advanced Attack Scenarios

### 1. Query Stacking

Multiple queries executed in one statement.

```sql
-- Vulnerable query
const query = `SELECT * FROM users WHERE id = ${id}`;

-- Attack payload
1; DROP TABLE users; --
```

Prevention:

```javascript
// Most databases don't allow multiple queries in prepared statements
const query = 'SELECT * FROM users WHERE id = ?'
db.query(query, [id])
```

### 2. Data Exfiltration

Extracting data through different channels.

```sql
-- Attack using UNION
1 UNION SELECT creditcard_num,email FROM users--

-- Attack using conditional responses
' AND (SELECT CASE WHEN (username='admin') THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users)--

-- Attack using out-of-band channels
' UNION SELECT null,load_file('/etc/passwd')--
```

Prevention:

```javascript
// 1. Column type checking
const schema = {
    id: { type: 'number', min: 1 },
    name: { type: 'string', maxLength: 50 },
}

// 2. Result set validation
function validateResults(rows) {
    return rows.every(
        row => typeof row.id === 'number' && typeof row.name === 'string'
    )
}
```
