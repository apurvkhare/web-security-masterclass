# iFrame Security & Clickjacking Protection

## Table of Contents

1. [Introduction](#introduction)
2. [Attack Scenarios](#attack-scenarios)
3. [Prevention Techniques](#prevention-techniques)
4. [Defense in Depth](#defense-in-depth)
5. [Monitoring & Logging](#monitoring--logging)
6. [Best Practices](#best-practices)

## Introduction

iFrame security involves protecting against various UI redressing attacks where malicious sites attempt to trick users into performing unintended actions on legitimate sites.

### Key Security Concerns:

-   Clickjacking/UI redressing
-   Frame hijacking
-   Cross-origin information leakage
-   Double frame attacks
-   Frame spoofing

## Attack Scenarios

### 1. Basic Clickjacking

Attacker overlays a transparent iframe over a decoy website to steal clicks.

```html
<!-- ATTACK SCENARIO -->
<!-- Malicious site (attacker.com) -->
<style>
    .overlay {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        z-index: 1000;
        opacity: 0.01; /* Nearly invisible */
    }
    .victim-frame {
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        border: none;
    }
</style>

<div class="overlay">
    <h1>Win a Free iPhone!</h1>
    <button style="position: absolute; top: 200px; left: 150px;">
        Click Here to Win!
    </button>
</div>
<iframe class="victim-frame" src="https://bank.com/transfer-money"></iframe>
```

**Prevention:**

```javascript
// Server-side protection
app.use((req, res, next) => {
    // Modern browsers
    res.setHeader(
        'Content-Security-Policy',
        "frame-ancestors 'none'"
    );

    // Legacy browsers
    res.setHeader('X-Frame-Options', 'DENY');
    next();
});

// Client-side protection
<script>
    if (window !== window.top) {
        window.top.location = window.location;
    }
</script>
```

### 2. UI Redressing Attack

Attacker creates multiple layers to trick users into interacting with hidden elements.

```html
<!-- ATTACK SCENARIO -->
<style>
    .layer1,
    .layer2 {
        position: absolute;
        width: 500px;
        height: 300px;
    }
    .layer1 {
        z-index: 1;
    }
    .layer2 {
        z-index: 2;
    }
</style>

<div class="layer1">
    <iframe src="https://bank.com/account"></iframe>
</div>
<div class="layer2">
    <div style="opacity: 0.01;">
        <!-- Malicious content positioned precisely -->
        <button>Click for discount!</button>
    </div>
</div>
```

**Prevention:**

```javascript
// 1. Strict CSP Policy
app.use((req, res, next) => {
    res.setHeader(
        'Content-Security-Policy',
        `
        frame-ancestors 'none';
        frame-src 'self' https://trusted-source.com;
        sandbox allow-scripts allow-same-origin;
    `
    )
    next()
})

// 2. Secure Frame Configuration
;<iframe
    src='content.html'
    sandbox='allow-scripts allow-same-origin'
    referrerpolicy='no-referrer'
    loading='lazy'
    importance='low'
></iframe>
```

### 3. Double Frame Attack

Attacker uses nested iframes to bypass simple frame busting code.

```html
<!-- ATTACK SCENARIO -->
<iframe src="frame1.html">
    <script>
        if (top !== self) {
            // Attempt to bypass basic frame buster
            top = self
        }
    </script>
    <iframe src="https://victim-site.com"></iframe>
</iframe>
```

**Prevention:**

```javascript
// Advanced Frame Busting
;(function () {
    if (self !== top) {
        // Multiple protection layers
        try {
            // 1. Break out of frame
            top.location = self.location
        } catch (e) {
            // 2. Clear content if breakout fails
            document.body.innerHTML = 'This site cannot be displayed in a frame'
        }

        // 3. Force redirect
        window.location = 'https://safe-site.com'
    }

    // 4. Hide content until safety verified
    document.documentElement.style.display = 'none'
    if (self === top) {
        document.documentElement.style.display = 'block'
    }
})()
```

## Prevention Techniques

### 1. Server-Side Headers

```javascript
function setupSecureHeaders(app) {
    app.use((req, res, next) => {
        // CSP Headers
        res.setHeader(
            'Content-Security-Policy',
            `
            frame-ancestors 'none';
            frame-src 'self' https://trusted-site.com;
            sandbox allow-scripts allow-same-origin;
        `
        )

        // Legacy Frame Protection
        res.setHeader('X-Frame-Options', 'DENY')

        // Additional Security Headers
        res.setHeader('X-Content-Type-Options', 'nosniff')
        res.setHeader('Referrer-Policy', 'no-referrer')

        next()
    })
}
```

### 2. Client-Side Protection

```javascript
// Comprehensive Frame Protection
class FrameProtector {
    static init() {
        // 1. Basic frame detection
        if (window !== window.top) {
            this.handleFraming()
        }

        // 2. Style-based protection
        document.documentElement.style.display = 'none'
        if (window === window.top) {
            document.documentElement.style.display = 'block'
        }

        // 3. Mutation observer for dynamic content
        this.watchDOMChanges()
    }

    static handleFraming() {
        try {
            window.top.location = window.self.location
        } catch (e) {
            window.location = 'https://safe-site.com'
        }
    }

    static watchDOMChanges() {
        new MutationObserver(mutations => {
            for (const mutation of mutations) {
                if (mutation.addedNodes.length) {
                    this.checkNewElements(mutation.addedNodes)
                }
            }
        }).observe(document, { childList: true, subtree: true })
    }

    static checkNewElements(nodes) {
        nodes.forEach(node => {
            if (node.tagName === 'IFRAME') {
                this.validateFrame(node)
            }
        })
    }

    static validateFrame(frame) {
        // Enforce secure attributes
        frame.sandbox = 'allow-scripts allow-same-origin'
        frame.referrerPolicy = 'no-referrer'
        frame.loading = 'lazy'
    }
}

// Initialize protection
FrameProtector.init()
```

## Defense in Depth

### 1. Multiple Protection Layers

```javascript
// Combine all protections
function setupComprehensiveProtection(app) {
    // 1. Server Headers
    setupSecureHeaders(app)

    // 2. Content Security Policy
    setupCSP(app)

    // 3. Frame Monitoring
    setupFrameMonitoring(app)

    // 4. Response Validation
    setupResponseValidation(app)
}

function setupCSP(app) {
    const csp = {
        'frame-ancestors': ["'none'"],
        'frame-src': ["'self'"],
        'child-src': ["'self'"],
        'worker-src': ["'none'"],
        sandbox: ['allow-scripts', 'allow-same-origin'],
    }

    app.use(helmet.contentSecurityPolicy({ directives: csp }))
}
```

### 2. Monitoring & Logging

```javascript
// Frame attempt monitoring
window.addEventListener('securitypolicyviolation', e => {
    const violation = {
        timestamp: new Date(),
        blockedURI: e.blockedURI,
        violatedDirective: e.violatedDirective,
        originalPolicy: e.originalPolicy,
        disposition: e.disposition,
        documentURI: e.documentURI,
        referrer: e.referrer,
        userAgent: navigator.userAgent,
    }

    // Log violation
    fetch('/api/security/violations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(violation),
    })
})
```

## Best Practices

1. **Default Deny**: Prevent framing by default, allow only when necessary
2. **Defense in Depth**: Implement multiple layers of protection
3. **Monitoring**: Track and alert on framing attempts
4. **Regular Updates**: Keep security headers and policies current
5. **Testing**: Regular security assessments against new attack vectors

## Demo Instructions

The accompanying files demonstrate:

1. Various clickjacking attacks
2. Frame protection implementations
3. Monitoring and logging
4. Security header configuration

Check `vulnerable.html`, `protected.html`, and `server.js` for practical examples.
