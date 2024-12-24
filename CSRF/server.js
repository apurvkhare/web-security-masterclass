const express = require('express')
const cors = require('cors')
const session = require('express-session')
const crypto = require('crypto')
const sqlite3 = require('sqlite3').verbose()

const app = express()

// Middleware
app.use(
    cors({
        origin: 'http://localhost:5500',
        credentials: true,
    })
)
app.use(express.json())
app.use(
    session({
        secret: 'your-secret-key',
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
        },
    })
)

// Initialize SQLite database
const db = new sqlite3.Database(':memory:')
db.serialize(() => {
    // Users table
    db.run(`CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        balance REAL DEFAULT 1000.00
    )`)

    // Transactions table
    db.run(`CREATE TABLE transactions (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        recipient TEXT,
        amount REAL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`)

    // Add demo user
    db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [
        'demo',
        'password123',
    ])
})

// CSRF token management
function generateToken() {
    return crypto.randomBytes(32).toString('hex')
}

function validateToken(req, res, next) {
    const token = req.body._csrf || req.headers['x-csrf-token']

    if (!token || token !== req.session.csrfToken) {
        return res.status(403).json({ error: 'Invalid CSRF token' })
    }
    next()
}

// Authentication middleware
function requireAuth(req, res, next) {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Authentication required' })
    }
    next()
}

// Routes
app.post('/login', (req, res) => {
    const { username, password } = req.body

    db.get(
        'SELECT id FROM users WHERE username = ? AND password = ?',
        [username, password],
        (err, user) => {
            if (err) return res.status(500).json({ error: err.message })
            if (!user)
                return res.status(401).json({ error: 'Invalid credentials' })

            // Set session and CSRF token
            req.session.userId = user.id
            req.session.csrfToken = generateToken()

            res.json({ success: true, csrfToken: req.session.csrfToken })
        }
    )
})

// Vulnerable endpoints (no CSRF protection)
app.get('/api/unsafe/balance', requireAuth, (req, res) => {
    db.get(
        'SELECT balance FROM users WHERE id = ?',
        [req.session.userId],
        (err, row) => {
            if (err) return res.status(500).json({ error: err.message })
            res.json({ balance: row.balance })
        }
    )
})

app.post('/api/unsafe/transfer', requireAuth, (req, res) => {
    const { to, amount } = req.body
    const userId = req.session.userId

    db.serialize(() => {
        // Start transaction
        db.run('BEGIN TRANSACTION')

        // Update sender's balance
        db.run(
            'UPDATE users SET balance = balance - ? WHERE id = ? AND balance >= ?',
            [amount, userId, amount],
            function (err) {
                if (err || this.changes === 0) {
                    db.run('ROLLBACK')
                    return res
                        .status(400)
                        .json({
                            error: 'Insufficient funds or invalid transfer',
                        })
                }

                // Record transaction
                db.run(
                    'INSERT INTO transactions (user_id, recipient, amount) VALUES (?, ?, ?)',
                    [userId, to, amount],
                    err => {
                        if (err) {
                            db.run('ROLLBACK')
                            return res.status(500).json({ error: err.message })
                        }

                        db.run('COMMIT')
                        res.json({ success: true })
                    }
                )
            }
        )
    })
})

app.get('/api/unsafe/transactions', requireAuth, (req, res) => {
    db.all(
        'SELECT recipient as to, amount FROM transactions WHERE user_id = ? ORDER BY timestamp DESC LIMIT 5',
        [req.session.userId],
        (err, rows) => {
            if (err) return res.status(500).json({ error: err.message })
            res.json({ transactions: rows })
        }
    )
})

// Secure endpoints (with CSRF protection)
app.get('/api/safe/balance', requireAuth, validateToken, (req, res) => {
    db.get(
        'SELECT balance FROM users WHERE id = ?',
        [req.session.userId],
        (err, row) => {
            if (err) return res.status(500).json({ error: err.message })
            res.json({ balance: row.balance })
        }
    )
})

app.post('/api/safe/transfer', requireAuth, validateToken, (req, res) => {
    const { to, amount } = req.body
    const userId = req.session.userId

    db.serialize(() => {
        db.run('BEGIN TRANSACTION')

        db.run(
            'UPDATE users SET balance = balance - ? WHERE id = ? AND balance >= ?',
            [amount, userId, amount],
            function (err) {
                if (err || this.changes === 0) {
                    db.run('ROLLBACK')
                    return res
                        .status(400)
                        .json({
                            error: 'Insufficient funds or invalid transfer',
                        })
                }

                db.run(
                    'INSERT INTO transactions (user_id, recipient, amount) VALUES (?, ?, ?)',
                    [userId, to, amount],
                    err => {
                        if (err) {
                            db.run('ROLLBACK')
                            return res.status(500).json({ error: err.message })
                        }

                        db.run('COMMIT')
                        res.json({ success: true })
                    }
                )
            }
        )
    })
})

app.get('/api/safe/transactions', requireAuth, validateToken, (req, res) => {
    db.all(
        'SELECT recipient as to, amount FROM transactions WHERE user_id = ? ORDER BY timestamp DESC LIMIT 5',
        [req.session.userId],
        (err, rows) => {
            if (err) return res.status(500).json({ error: err.message })
            res.json({ transactions: rows })
        }
    )
})

// Start server
const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`)
    console.log(
        'Warning: Contains vulnerable endpoints for educational purposes!'
    )
})
