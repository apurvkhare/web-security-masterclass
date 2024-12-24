# Cross-Site Scripting (XSS)

## Table of Contents

1. [Introduction](#introduction)
2. [Types of XSS](#types-of-xss)
3. [Prevention Techniques](#prevention-techniques)
4. [Input Validation & Sanitization](#input-validation--sanitization)
5. [Security Headers](#security-headers)
6. [Best Practices](#best-practices)

## Introduction

Cross-Site Scripting (XSS) is a security vulnerability that allows attackers to inject malicious client-side scripts into web pages viewed by other users. When successful, XSS can be used to:

-   Steal session cookies
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

// Safe
app.get('/search', (req, res) => {
    const query = escapeHtml(req.query.q)
    res.send(`Search results for: ${query}`)
})
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

// Safe
app.post('/comments', (req, res) => {
    db.comments.save({
        text: sanitizeHtml(req.body.comment),
    })
})
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

### Essential Headers for XSS Prevention

1. **Content-Security-Policy (CSP)**

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
    - `img-src`: Control image source locations

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
            img-src 'self' https:;
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

2. **X-XSS-Protection**

    ```http
    X-XSS-Protection: 1; mode=block; report=/xss-report
    ```

    Controls the browser's built-in XSS filter:

    - `0`: Disable XSS filtering
    - `1`: Enable XSS filtering
    - `mode=block`: Block rendering rather than sanitize
    - `report=/xss-report`: Report violations to specified endpoint

    Example implementation:

    ```javascript
    app.use((req, res, next) => {
        res.setHeader('X-XSS-Protection', '1; mode=block')
        next()
    })

    // Optional reporting endpoint
    app.post('/xss-report', (req, res) => {
        console.log('XSS Attempt:', req.body)
        res.status(204).end()
    })
    ```

3. **X-Content-Type-Options**

    ```http
    X-Content-Type-Options: nosniff
    ```

    Prevents MIME type sniffing:

    - Stops browsers from interpreting files as a different MIME type
    - Prevents XSS attacks via MIME type confusion
    - Critical for serving user-uploaded content

    Example implementation:

    ```javascript
    app.use((req, res, next) => {
        res.setHeader('X-Content-Type-Options', 'nosniff')
        next()
    })
    ```

4. **Additional Security Headers**

    a. **Strict-Transport-Security (HSTS)**

    ```http
    Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
    ```

    - Forces HTTPS connections
    - Prevents protocol downgrade attacks
    - `includeSubDomains`: Applies to all subdomains
    - `preload`: Include in browser HSTS preload list

    b. **X-Frame-Options**

    ```http
    X-Frame-Options: SAMEORIGIN
    ```

    - Controls iframe embedding
    - Prevents clickjacking attacks
    - Options: `DENY`, `SAMEORIGIN`, `ALLOW-FROM uri`

    Complete headers implementation:

    ```javascript
    app.use((req, res, next) => {
        // Basic security headers
        const headers = {
            'Content-Security-Policy': constructCSP(req),
            'X-XSS-Protection': '1; mode=block',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'SAMEORIGIN',
            'Strict-Transport-Security':
                'max-age=31536000; includeSubDomains; preload',
        }

        // Apply all headers
        Object.entries(headers).forEach(([key, value]) => {
            res.setHeader(key, value)
        })

        next()
    })

    function constructCSP(req) {
        const nonce = crypto.randomBytes(16).toString('base64')
        return `
            default-src 'self';
            script-src 'self' 'nonce-${nonce}';
            style-src 'self' 'unsafe-inline';
            img-src 'self' https:;
            frame-ancestors 'self';
            form-action 'self';
        `
            .replace(/\s+/g, ' ')
            .trim()
    }
    ```

### Header Testing and Verification

-   Use security header scanning tools
-   Verify headers are present and correct
-   Test CSP violations are properly blocked
-   Monitor violation reports

Example testing code:

```javascript
const axios = require('axios')

async function testSecurityHeaders(url) {
    try {
        const response = await axios.get(url)
        const headers = response.headers

        // Check essential headers
        const requiredHeaders = [
            'content-security-policy',
            'x-xss-protection',
            'x-content-type-options',
            'strict-transport-security',
        ]

        requiredHeaders.forEach(header => {
            if (headers[header]) {
                console.log(`✅ ${header} is present`)
            } else {
                console.log(`❌ ${header} is missing`)
            }
        })
    } catch (error) {
        console.error('Error testing headers:', error)
    }
}
```

These security headers, when properly implemented, provide multiple layers of defense against XSS and related attacks. Regular testing and monitoring ensure they remain effective.

## Best Practices

### 1. Input Validation

-   Validate on both client and server side
-   Use whitelisting over blacklisting
-   Validate for length, format, and type

```javascript
function validateInput(input) {
    return /^[a-zA-Z0-9\s]+$/.test(input)
}
```

### 2. Context-Aware Encoding

-   HTML encoding for HTML content
-   JavaScript encoding for script contexts
-   URL encoding for URL parameters
-   CSS encoding for style values

### 3. Framework Security Features

-   Use built-in security features
-   Keep frameworks updated
-   Use secure configurations

```javascript
// React (safe by default)
const element = <div>{userInput}</div>

// Angular (safe by default)
;<div>{{ userInput }}</div>
```

### 4. Security Testing

-   Regular security audits
-   Automated scanning
-   Penetration testing
-   Code reviews

## Demo Instructions

The accompanying `index.html` and `server.js` files demonstrate:

1. Reflected XSS vulnerability and prevention
2. Stored XSS vulnerability and prevention
3. DOM-based XSS vulnerability and prevention
4. Input validation and sanitization
5. CSP implementation

Check the demo files to see these security concepts in action.
