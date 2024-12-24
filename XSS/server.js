const express = require('express')
const cors = require('cors')
const sqlite3 = require('sqlite3').verbose()
const sanitizeHtml = require('sanitize-html')

const app = express()

// Middleware
app.use(cors())
app.use(express.json())

// Initialize SQLite database
const db = new sqlite3.Database(':memory:')
db.serialize(() => {
    db.run('CREATE TABLE unsafe_comments (text TEXT)')
    db.run('CREATE TABLE safe_comments (text TEXT)')
})

// Helper functions
function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;')
}

// Security headers middleware
app.use((req, res, next) => {
    // CSP header
    res.setHeader(
        'Content-Security-Policy',
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    )
    // Other security headers
    res.setHeader('X-XSS-Protection', '1; mode=block')
    res.setHeader('X-Content-Type-Options', 'nosniff')
    next()
})

// Reflected XSS endpoints
app.get('/search-unsafe', (req, res) => {
    const query = req.query.q || ''
    // Vulnerable: Direct injection of user input
    res.send(`<p>Search results for: ${query}</p>`)
})

app.get('/search-safe', (req, res) => {
    const query = req.query.q || ''
    // Safe: Escaped user input
    res.send(`<p>Search results for: ${escapeHtml(query)}</p>`)
})

// Stored XSS endpoints
app.post('/comments-unsafe', (req, res) => {
    const { comment } = req.body
    // Vulnerable: Storing raw user input
    db.run('INSERT INTO unsafe_comments (text) VALUES (?)', [comment], err => {
        if (err) return res.status(500).json({ error: err.message })
        res.json({ success: true })
    })
})

app.post('/comments-safe', (req, res) => {
    const { comment } = req.body
    // Safe: Sanitizing user input before storage
    const sanitized = sanitizeHtml(comment, {
        allowedTags: ['b', 'i', 'em', 'strong'],
        allowedAttributes: {},
    })
    db.run('INSERT INTO safe_comments (text) VALUES (?)', [sanitized], err => {
        if (err) return res.status(500).json({ error: err.message })
        res.json({ success: true })
    })
})

app.get('/get-comments-unsafe', (req, res) => {
    db.all('SELECT text FROM unsafe_comments', (err, rows) => {
        if (err) return res.status(500).json({ error: err.message })
        res.json(rows)
    })
})

app.get('/get-comments-safe', (req, res) => {
    db.all('SELECT text FROM safe_comments', (err, rows) => {
        if (err) return res.status(500).json({ error: err.message })
        res.json(rows)
    })
})

// Start server
const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`)
    console.log(
        'Warning: Contains vulnerable endpoints for educational purposes!'
    )
})
