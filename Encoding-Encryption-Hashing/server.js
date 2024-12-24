const express = require('express')
const cors = require('cors')
const crypto = require('crypto')
const bcrypt = require('bcrypt')

const app = express()

// Middleware
app.use(cors())
app.use(express.json())

// Store hashed password for demo (in practice, use a database)
let storedHash = null

// Encryption key and IV (in practice, use secure key management)
const encryptionKey = crypto.randomBytes(32)
const iv = crypto.randomBytes(16)

// Encryption functions
function encrypt(text) {
    const cipher = crypto.createCipheriv('aes-256-cbc', encryptionKey, iv)
    let encrypted = cipher.update(text, 'utf8', 'hex')
    encrypted += cipher.final('hex')
    return encrypted
}

function decrypt(encrypted) {
    const decipher = crypto.createDecipheriv('aes-256-cbc', encryptionKey, iv)
    let decrypted = decipher.update(encrypted, 'hex', 'utf8')
    decrypted += decipher.final('utf8')
    return decrypted
}

// Routes
app.post('/api/encrypt', (req, res) => {
    try {
        const { text } = req.body
        const encrypted = encrypt(text)
        const decrypted = decrypt(encrypted)

        res.json({
            encrypted,
            decrypted,
        })
    } catch (error) {
        res.status(500).json({ error: error.message })
    }
})

app.post('/api/hash', async (req, res) => {
    try {
        const { password } = req.body
        const saltRounds = 10
        const hash = await bcrypt.hash(password, saltRounds)

        // Store hash for later verification
        storedHash = hash

        res.json({ hash })
    } catch (error) {
        res.status(500).json({ error: error.message })
    }
})

app.post('/api/verify', async (req, res) => {
    try {
        const { password } = req.body

        if (!storedHash) {
            return res.status(400).json({
                match: false,
                message: 'No password has been hashed yet',
            })
        }

        const match = await bcrypt.compare(password, storedHash)
        res.json({ match })
    } catch (error) {
        res.status(500).json({ error: error.message })
    }
})

// Start server
const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`)
    console.log('Open index.html in your browser to test security concepts')
})
