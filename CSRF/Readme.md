# Cross-Site Request Forgery (CSRF)

## Table of Contents

1. [Introduction](#introduction)
2. [How CSRF Works](#how-csrf-works)
3. [Prevention Techniques](#prevention-techniques)
4. [Content Security Policy (CSP)](#content-security-policy)
5. [CSRF Tokens](#csrf-tokens)
6. [Best Practices](#best-practices)

## Introduction

Cross-Site Request Forgery (CSRF) is an attack that forces authenticated users to execute unwanted actions on a web application in which they're currently authenticated. CSRF attacks specifically target state-changing requests, not theft of data, since the attacker has no way to see the response to the forged request.

### Common CSRF Attack Targets

-   Change user's email/password
-   Transfer funds
-   Make purchases
-   Delete account/data
-   Submit forms with user's credentials

## How CSRF Works

### Attack Scenario

1. User logs into legitimate site (e.g., bank.com)
2. Session cookie is stored in browser
3. User visits malicious site while still logged in
4. Malicious site triggers unwanted request to bank.com
5. Browser includes session cookie automatically
6. Request is executed with user's privileges

### Example of Vulnerable Form

```html
<!-- Vulnerable form without CSRF protection -->
<form action="/transfer" method="POST">
    <input type="text" name="amount" />
    <input type="text" name="to" />
    <button type="submit">Transfer</button>
</form>
```

### Example of Malicious Page

```html
<!-- Malicious page exploiting CSRF -->
<form
    id="hack-form"
    action="https://bank.com/transfer"
    method="POST"
    style="display:none"
>
    <input type="hidden" name="amount" value="1000" />
    <input type="hidden" name="to" value="attacker" />
</form>
<script>
    document.getElementById('hack-form').submit()
</script>
```

## Prevention Techniques

### 1. CSRF Tokens
Synchronizer (CSRF) tokens are unique, unpredictable values that are:
- Generated server-side
- Tied to user's session
- Required in every state-changing request
- Validated for each protected request

#### Implementation Patterns:
a) **Per-Session Token**
```javascript
// Generate once per session
app.use((req, res, next) => {
    if (!req.session.csrfToken) {
        req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    }
    next();
});
```

b) **Per-Request Token**
```javascript
// Generate new token for each request
app.use((req, res, next) => {
    req.csrfToken = crypto.randomBytes(32).toString('hex');
    req.session.csrfTokens = req.session.csrfTokens || {};
    req.session.csrfTokens[req.csrfToken] = true;
    next();
});
```

### 2. Same-Site Cookies
SameSite attribute prevents cookies from being sent in cross-site requests:

#### Strict Mode
```javascript
// Most secure - cookies never sent in cross-site requests
app.use(session({
    cookie: {
        sameSite: 'strict',  // Cookies only sent in same-site context
        secure: true,        // Only sent over HTTPS
        httpOnly: true       // Not accessible via JavaScript
    }
}));
```

#### Lax Mode
```javascript
// Balance between security and usability
app.use(session({
    cookie: {
        sameSite: 'lax',    // Cookies sent in same-site context and top-level GET
        secure: true,
        httpOnly: true
    }
}));
```

### 3. Custom Request Headers
Custom headers provide additional CSRF protection because browsers prevent malicious sites from setting custom headers in cross-origin requests.

#### Implementation:
```javascript
// Client-side
const makeRequest = async (url, data) => {
    const response = await fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest',
            'X-Custom-Header': 'value'  // Attacker can't set this
        },
        body: JSON.stringify(data)
    });
    return response.json();
};

// Server-side
app.use((req, res, next) => {
    if (req.method === 'POST') {
        if (!req.headers['x-requested-with'] || 
            !req.headers['x-custom-header']) {
            return res.status(403).json({
                error: 'CSRF validation failed'
            });
        }
    }
    next();
});
```

## Content Security Policy (CSP)

CSP provides multiple directives to prevent CSRF and related attacks:

### 1. form-action Directive
Restricts where forms can be submitted:
```javascript
// Only allow forms to submit to same origin
res.setHeader('Content-Security-Policy', "form-action 'self';");

// Allow specific domains
res.setHeader('Content-Security-Policy', 
    "form-action 'self' https://trusted-api.com;");
```

### 2. frame-ancestors Directive
Controls which sites can embed your pages:
```javascript
// Prevent any framing (clickjacking protection)
res.setHeader('Content-Security-Policy', "frame-ancestors 'none';");

// Allow specific parent frames
res.setHeader('Content-Security-Policy', 
    "frame-ancestors 'self' https://trusted-parent.com;");
```

### 3. base-uri Directive
Restricts URLs that can be used as base URLs:
```javascript
// Only allow same-origin base URLs
res.setHeader('Content-Security-Policy', "base-uri 'self';");
```

### Complete CSP Configuration
```javascript
app.use((req, res, next) => {
    const csp = [
        "default-src 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "upgrade-insecure-requests",
        "block-all-mixed-content"
    ].join('; ');
    
    res.setHeader('Content-Security-Policy', csp);
    next();
});
```

## CSRF Tokens

### 1. Token Generation Strategies

#### Cryptographic Token
```javascript
function generateCryptoToken() {
    // Generate random bytes and hash them
    const random = crypto.randomBytes(32);
    const hash = crypto
        .createHash('sha256')
        .update(random)
        .digest('hex');
    return hash;
}
```

#### HMAC-Based Token
```javascript
function generateHmacToken(sessionId) {
    // Create token using session ID and secret
    const hmac = crypto.createHmac('sha256', process.env.SECRET_KEY);
    hmac.update(sessionId + Date.now());
    return hmac.digest('hex');
}
```

### 2. Token Storage Patterns

#### Session Storage
```javascript
// Store in session
app.use((req, res, next) => {
    if (!req.session.csrfTokens) {
        req.session.csrfTokens = new Set();
    }
    next();
});

// Add new token
function addToken(req, token) {
    req.session.csrfTokens.add(token);
    // Optional: Limit number of valid tokens
    if (req.session.csrfTokens.size > 10) {
        const [oldestToken] = req.session.csrfTokens;
        req.session.csrfTokens.delete(oldestToken);
    }
}
```

#### Double Submit Cookie
```javascript
function setupDoubleSubmit(req, res) {
    const token = generateCryptoToken();
    
    // Set in cookie
    res.cookie('csrf-token', token, {
        httpOnly: false,  // Accessible to JavaScript
        secure: true,
        sameSite: 'strict'
    });
    
    // Return for form/header
    return token;
}
```

### 3. Token Validation

#### Synchronous Validation
```javascript
function validateToken(req, res, next) {
    const token = req.body._csrf || 
                 req.headers['x-csrf-token'] || 
                 req.query._csrf;
                 
    if (!token || !req.session.csrfTokens.has(token)) {
        return res.status(403).json({
            error: 'Invalid or missing CSRF token'
        });
    }
    
    // Optional: Single-use tokens
    req.session.csrfTokens.delete(token);
    next();
}
```

#### Asynchronous Validation
```javascript
async function validateTokenAsync(req, res, next) {
    try {
        const token = req.body._csrf;
        const timestamp = parseInt(token.split('.')[1]);
        
        // Check token age
        if (Date.now() - timestamp > 3600000) { // 1 hour
            throw new Error('Token expired');
        }
        
        // Verify HMAC
        const isValid = await verifyHmac(token, req.session.id);
        if (!isValid) {
            throw new Error('Invalid token');
        }
        
        next();
    } catch (error) {
        res.status(403).json({
            error: 'CSRF validation failed: ' + error.message
        });
    }
}
```

## Best Practices

### 1. Defense in Depth

-   Implement multiple CSRF protections
-   Use both tokens and SameSite cookies
-   Apply proper CSP headers

### 2. Token Management

-   Use cryptographically secure tokens
-   Rotate tokens regularly
-   Validate token presence and value

### 3. Cookie Security

```javascript
app.use(
    session({
        secret: 'your-secret-key',
        cookie: {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
        },
    })
)
```

### 4. Form Security

-   Use POST for state-changing operations
-   Include CSRF tokens in all forms
-   Validate token on all state-changing endpoints

### 5. API Security

-   Require custom headers for API requests
-   Implement proper CORS policies
-   Use proper authentication methods

## Demo Instructions

The accompanying `index.html` and `server.js` files demonstrate:

1. CSRF vulnerability in a form submission
2. Token-based CSRF protection
3. SameSite cookie protection
4. Double Submit Cookie pattern
5. CSP implementation

Check the demo files to see these security concepts in action.
