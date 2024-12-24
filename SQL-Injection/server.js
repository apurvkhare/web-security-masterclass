const express = require('express')
const cors = require('cors')
const sqlite3 = require('sqlite3').verbose()
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')

const app = express()

// Middleware
app.use(cors())
app.use(express.json())

// Initialize SQLite database
const db = new sqlite3.Database(':memory:')

// Initialize MongoDB
mongoose.connect('mongodb://localhost:27017/sqli_demo', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})

// MongoDB Schema
const UserSchema = new mongoose.Schema({
    username: String,
    password: String,
    role: String,
})

const User = mongoose.model('User', UserSchema)

// Initialize databases
async function initializeDatabases() {
    // SQLite setup
    db.serialize(() => {
        // Users table
        db.run(`CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            role TEXT
        )`)

        // Products table
        db.run(`CREATE TABLE products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            price REAL
        )`)

        // Insert demo data
        db.run(`INSERT INTO users (username, password, role) VALUES 
            ('admin', 'admin123', 'admin'),
            ('user', 'user123', 'user')`)

        db.run(`INSERT INTO products (name, price) VALUES 
            ('Laptop', 999.99),
            ('Phone', 599.99),
            ('Tablet', 299.99)`)
    })

    // MongoDB setup
    await User.deleteMany({})
    await User.insertMany([
        {
            username: 'admin',
            password: await bcrypt.hash('admin123', 10),
            role: 'admin',
        },
        {
            username: 'user',
            password: await bcrypt.hash('user123', 10),
            role: 'user',
        },
    ])
}

// Initialize route
app.post('/api/initialize', async (req, res) => {
    await initializeDatabases()
    res.json({ message: 'Databases initialized' })
})

// SQL Injection vulnerable endpoints
app.post('/api/unsafe/login', (req, res) => {
    const { username, password } = req.body

    // Vulnerable to SQL injection
    const query = `
        SELECT * FROM users 
        WHERE username = '${username}' 
        AND password = '${password}'
    `

    db.get(query, (err, row) => {
        if (err) return res.status(500).json({ error: err.message })
        if (!row) return res.status(401).json({ error: 'Invalid credentials' })
        res.json({ success: true, user: row })
    })
})

app.get('/api/unsafe/search', (req, res) => {
    const { query } = req.query

    // Vulnerable to UNION-based attacks
    const sql = `
        SELECT name, price FROM products 
        WHERE name LIKE '%${query}%'
    `

    db.all(sql, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message })
        res.json({ results: rows })
    })
})

app.post('/api/unsafe/update', (req, res) => {
    const { id, name } = req.body

    // Vulnerable to query stacking
    const query = `
        UPDATE products 
        SET name = '${name}' 
        WHERE id = ${id}
    `

    db.exec(query, err => {
        if (err) return res.status(500).json({ error: err.message })
        res.json({ success: true })
    })
})

// SQL Injection safe endpoints
app.post('/api/safe/login', (req, res) => {
    const { username, password } = req.body

    // Safe: Using parameterized query
    const query = `
        SELECT * FROM users 
        WHERE username = ? AND password = ?
    `

    db.get(query, [username, password], (err, row) => {
        if (err) return res.status(500).json({ error: 'Invalid request' })
        if (!row) return res.status(401).json({ error: 'Invalid credentials' })
        res.json({ success: true, user: row })
    })
})

app.get('/api/safe/search', (req, res) => {
    const { query } = req.query

    // Safe: Using parameterized query and input validation
    if (!query.match(/^[a-zA-Z0-9\s]+$/)) {
        return res.status(400).json({ error: 'Invalid search query' })
    }

    db.all(
        'SELECT name, price FROM products WHERE name LIKE ?',
        [`%${query}%`],
        (err, rows) => {
            if (err) return res.status(500).json({ error: 'Search failed' })
            res.json({ results: rows })
        }
    )
})

app.post('/api/safe/update', (req, res) => {
    const { id, name } = req.body

    // Safe: Using parameterized query and type checking
    if (!Number.isInteger(Number(id)) || typeof name !== 'string') {
        return res.status(400).json({ error: 'Invalid input' })
    }

    db.run(
        'UPDATE products SET name = ? WHERE id = ?',
        [name, id],
        function (err) {
            if (err) return res.status(500).json({ error: 'Update failed' })
            res.json({ success: true, changes: this.changes })
        }
    )
})

// NoSQL Injection vulnerable endpoints
app.post('/api/unsafe/mongo/login', async (req, res) => {
    try {
        // Vulnerable to NoSQL injection
        const user = await User.findOne(req.body)

        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' })
        }

        res.json({
            success: true,
            user: { username: user.username, role: user.role },
        })
    } catch (error) {
        res.status(500).json({ error: error.message })
    }
})

app.get('/api/unsafe/mongo/search', async (req, res) => {
    try {
        // Vulnerable to operator injection
        const users = await User.find({ role: req.query.role })
        res.json({
            users: users.map(u => ({ username: u.username, role: u.role })),
        })
    } catch (error) {
        res.status(500).json({ error: error.message })
    }
})

// NoSQL Injection safe endpoints
app.post('/api/safe/mongo/login', async (req, res) => {
    try {
        const { username, password } = req.body

        // Safe: Using exact field matching and proper password comparison
        const user = await User.findOne({ username: String(username) })

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid credentials' })
        }

        res.json({
            success: true,
            user: { username: user.username, role: user.role },
        })
    } catch (error) {
        res.status(500).json({ error: 'Login failed' })
    }
})

app.get('/api/safe/mongo/search', async (req, res) => {
    try {
        const { role } = req.query

        // Safe: Using schema validation and sanitization
        if (!role.match(/^[a-zA-Z]+$/)) {
            return res.status(400).json({ error: 'Invalid role format' })
        }

        const users = await User.find({ role: String(role) })
        res.json({
            users: users.map(u => ({ username: u.username, role: u.role })),
        })
    } catch (error) {
        res.status(500).json({ error: 'Search failed' })
    }
})

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack)
    res.status(500).json({
        error: 'Something went wrong!',
        details:
            process.env.NODE_ENV === 'development' ? err.message : undefined,
    })
})

// Start server
const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`)
    console.log(
        'Warning: Contains vulnerable endpoints for educational purposes!'
    )
    initializeDatabases()
})
