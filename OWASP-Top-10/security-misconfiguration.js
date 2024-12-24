// 1. Security Headers Implementation
const helmet = require('helmet')
const express = require('express')
const app = express()

// Apply basic security headers
app.use(helmet())

// Custom security headers configuration
app.use(
    helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: ["'self'", "'unsafe-inline'"],
                styleSrc: ["'self'", "'unsafe-inline'"],
                imgSrc: ["'self'", 'data:', 'https:'],
                connectSrc: ["'self'"],
                fontSrc: ["'self'"],
                objectSrc: ["'none'"],
                mediaSrc: ["'self'"],
                frameSrc: ["'none'"],
            },
        },
        crossOriginEmbedderPolicy: true,
        crossOriginOpenerPolicy: true,
        crossOriginResourcePolicy: { policy: 'same-origin' },
        dnsPrefetchControl: { allow: false },
        expectCt: { enforce: true, maxAge: 30 },
        frameguard: { action: 'deny' },
        hidePoweredBy: true,
        hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
        ieNoOpen: true,
        noSniff: true,
        referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
        xssFilter: true,
    })
)

// 2. Error Handling
// BAD: Exposing sensitive information in errors
app.use((err, req, res, next) => {
    console.error(err.stack)
    res.status(500).json({
        error: err.message,
        stack: err.stack, // Never expose stack traces!
    })
})

// GOOD: Secure error handling
app.use((err, req, res, next) => {
    console.error(err.stack) // Log for debugging
    res.status(500).json({
        error: 'Internal Server Error',
        id: req.errorId, // Reference ID for tracking
    })
})

// 3. Environment Configuration
// BAD: Example of insecure configuration (for demonstration only)
/* 
const insecureConfig = {
    database: 'mongodb://admin:password@localhost:27017/prod',
    apiKey: '1234567890abcdef',
    debug: true
};
*/

// GOOD: Environment-based configuration
require('dotenv').config()

const config = {
    database: process.env.DATABASE_URL,
    apiKey: process.env.API_KEY,
    debug: process.env.NODE_ENV !== 'production',
}

module.exports = { config } // Export for use in other files

// 4. Security Middleware
function securityChecks(req, res, next) {
    // Check for required security headers
    if (!req.secure && process.env.NODE_ENV === 'production') {
        return res.redirect(`https://${req.headers.host}${req.url}`)
    }

    // Validate content types
    if (req.method === 'POST' && !req.is('application/json')) {
        return res.status(415).json({ error: 'Unsupported Media Type' })
    }

    // Check for suspicious patterns
    const suspicious = /[<>]|javascript:|data:/i
    if (suspicious.test(req.url)) {
        return res.status(400).json({ error: 'Invalid request' })
    }

    next()
}

app.use(securityChecks)

// 5. File Upload Security
const multer = require('multer')
const path = require('path')

const upload = multer({
    storage: multer.diskStorage({
        destination: 'uploads/',
        filename: (req, file, cb) => {
            const safeName = path
                .basename(file.originalname)
                .replace(/[^a-z0-9.]/gi, '_')
            cb(null, `${Date.now()}-${safeName}`)
        },
    }),
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['image/jpeg', 'image/png', 'application/pdf']
        if (!allowedTypes.includes(file.mimetype)) {
            return cb(new Error('Invalid file type'), false)
        }
        cb(null, true)
    },
    limits: {
        fileSize: 5 * 1024 * 1024, // 5MB
    },
})

app.post('/upload', upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' })
    }
    res.json({ filename: req.file.filename })
})
