# Cross-Site Scripting (XSS)

## Agenda

1. [Introduction](#introduction)
2. [Types of XSS](#types-of-xss)
3. [Prevention Techniques](#prevention-techniques)
4. [Security Headers](#security-headers)
5. [Best Practices](#best-practices)

## Introduction

Cross-Site Scripting (XSS) is a security vulnerability that allows attackers to inject malicious client-side scripts into web pages viewed by other users. When successful, XSS can be used to:

-   Capture keystrokes
-   Steal sensitive data
-   Deface websites
-   Hijack user sessions

## Types of XSS

### 1. Reflected XSS

-   Scripts are injected through URL parameters or form inputs
-   Payload is reflected back in server response
-   Not persistent, requires victim to click malicious link

Example of vulnerable code:

```javascript
// Vulnerable
app.get('/search', (req, res) => {
    const query = req.query.q
    res.send(`Search results for: ${query}`) // Dangerous!
})

// query: <script>alert('XSS')</script>

// Safe
app.get('/search', (req, res) => {
    const query = escapeHtml(req.query.q)
    res.send(`Search results for: ${query}`)
})

// escaped query: &lt;script&gt;alert('XSS')&lt;/script&gt;
```

### 2. Stored XSS

-   Malicious script is saved in database
-   Payload is served to all users who access affected page
-   More dangerous as it affects multiple users

Example of vulnerable code:

```javascript
// Vulnerable
app.post('/comments', (req, res) => {
    db.comments.save({
        text: req.body.comment, // Dangerous!
    })
})

// comment: <script>alert('XSS')</script>

// Safe
app.post('/comments', (req, res) => {
    db.comments.save({
        text: sanitizeHtml(req.body.comment),
    })
})

// sanitized comment: alert('XSS')
```

### 3. DOM-based XSS

-   Occurs in client-side JavaScript
-   Payload is executed through DOM manipulation
-   Never reaches the server

Example of vulnerable code:

```javascript
// Vulnerable
const hash = location.hash.substring(1)
document.getElementById('output').innerHTML = hash // Dangerous!

// Safe
const hash = location.hash.substring(1)
document.getElementById('output').textContent = hash

```

## Prevention Techniques

### 1. Output Encoding

```javascript
function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;')
}
```

### 2. Input Validation & Sanitization

```javascript
const sanitizeHtml = require('sanitize-html')

const clean = sanitizeHtml(dirty, {
    allowedTags: ['b', 'i', 'em', 'strong'],
    allowedAttributes: {},
})
```

### 3. Content Security Policy (CSP)

```javascript
// Server-side header
app.use((req, res, next) => {
    res.setHeader(
        'Content-Security-Policy',
        "default-src 'self'; script-src 'self'"
    )
    next()
})
```

### 4. Safe DOM Methods

```javascript
// Unsafe
element.innerHTML = userInput

// Safe alternatives
element.textContent = userInput // For text
element.setAttribute('value', userInput) // For attributes
```

## Security Headers

### Content-Security-Policy (CSP)

```http
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-random123'; style-src 'self' 'unsafe-inline'; img-src 'self' https:;
```

CSP provides granular control over resource loading:

- `default-src 'self'`: Only allow resources from same origin
- `script-src`: Control JavaScript source locations
    - `'self'`: Same origin only
    - `'nonce-random123'`: Allow inline scripts with matching nonce
    - `'strict-dynamic'`: Trust scripts loaded by trusted scripts
- `style-src`: Control CSS source locations
    - `https:`: Allow images from HTTPS sources
- `img-src`: Control image source locations
    - `https://images.example.com`: Allow images from specific domain

Example implementation:

```javascript
app.use((req, res, next) => {
    // Generate unique nonce for each request
    const nonce = crypto.randomBytes(16).toString('base64')

    // Construct CSP with nonce
    const csp = `
        default-src 'self';
        script-src 'self' 'nonce-${nonce}';
        style-src 'self' 'unsafe-inline';
        img-src 'self' https://images.example.com;
    `
        .replace(/\s+/g, ' ')
        .trim()

    res.setHeader('Content-Security-Policy', csp)

    // Make nonce available to templates
    res.locals.nonce = nonce
    next()
})
```

Usage in HTML:

```html
<script nonce="<%= nonce %>">
    // This script will execute if nonce matches
</script>
```

## Best Practices

### 1. Input Validation

-   Validate on both client and server side
-   Use whitelisting over blacklisting
-   Validate for length, format, and type

```javascript
function validateInput(input) {
    return /^[a-zA-Z0-9\s]+$/.test(input)
}

// userInput: <script>alert('XSS')</script>
// validateInput(userInput): false
```

### 2. Framework Security Features

-   Use built-in security features
-   Keep frameworks updated

```javascript
// React (safe by default)
const element = <div>{userInput}</div>

// userInput: <script>alert('XSS')</script>
// element: <div>&lt;script&gt;alert('XSS')&lt;/script&gt;</div>
```
