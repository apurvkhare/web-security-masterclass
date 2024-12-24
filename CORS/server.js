const express = require('express')
const cookieParser = require('cookie-parser')
const app = express()

// Middleware
app.use(express.json())
app.use(cookieParser())

// CORS configuration examples
const corsConfig = {
    // Example 1: Simple CORS
    simple: (req, res, next) => {
        res.header('Access-Control-Allow-Origin', '*')
        next()
    },

    // Example 2: Preflight
    preflight: (req, res, next) => {
        res.header('Access-Control-Allow-Origin', 'http://localhost:5500')
        res.header(
            'Access-Control-Allow-Methods',
            'GET, POST, PUT, DELETE, OPTIONS'
        )
        res.header(
            'Access-Control-Allow-Headers',
            'Content-Type, Custom-Header'
        )

        if (req.method === 'OPTIONS') {
            return res.sendStatus(200)
        }
        next()
    },

    // Example 3: Credentials
    credentials: (req, res, next) => {
        res.header('Access-Control-Allow-Origin', 'http://localhost:5500')
        res.header('Access-Control-Allow-Credentials', 'true')
        res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        res.header('Access-Control-Allow-Headers', 'Content-Type')

        if (req.method === 'OPTIONS') {
            return res.sendStatus(200)
        }
        next()
    },
}

// Routes
app.get('/api/simple', corsConfig.simple, (req, res) => {
    res.json({ message: 'Simple CORS request successful' })
})

app.post('/api/preflight', corsConfig.preflight, (req, res) => {
    res.json({
        message: 'Preflight CORS request successful',
        receivedData: req.body,
    })
})

app.get('/api/credentials', corsConfig.credentials, (req, res) => {
    // Set a cookie to demonstrate credentials
    res.cookie('corsDemo', 'test-value', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
    })
    res.json({ message: 'Credentials CORS request successful' })
})

app.get('/api/error', (req, res) => {
    // No CORS headers - will cause an error
    res.json({ message: 'This should fail due to CORS' })
})

// Start server
const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`)
    console.log('Open index.html in your browser to test CORS scenarios')
})
