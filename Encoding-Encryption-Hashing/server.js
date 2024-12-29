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
// IV: Initialization vector ensures same plaintext encrypts to different ciphertext
// to prevent pattern recognition in encrypted data.
// Generate a new, random IV for each encryption operation.

// Encryption functions
function encrypt(text) {
    console.log("Secret Key:\n", encryptionKey.toString('hex'));
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

function asymmetricEncryption(text) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048, // Key size in bits
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        // Subject Public Key Info (SPKI) is a standard format for public key information.
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        // Public-Key Cryptography Standards (PKCS) #8 is a standard syntax for private key information.
        // PEM: Privacy Enhanced Mail is a Base64 encoded DER format.
    });

    console.log("Public Key:\n", publicKey);
    console.log("Private Key:\n", privateKey);

    const encryptedMessage = crypto.publicEncrypt(publicKey, Buffer.from(text));
    // Buffer: Node.js class to handle binary data
    // Encryption works with binary data, so we convert the text to a Buffer

    const decryptedMessage = crypto.privateDecrypt(privateKey, encryptedMessage);

    return { publicKey, privateKey, encryptedMessage, decryptedMessage };
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

app.post('/api/asymmetric-encrypt', (req, res) => {
    try {
        const { text } = req.body
        const { publicKey, privateKey, encryptedMessage, decryptedMessage } = asymmetricEncryption(text)

        res.json({
            encrypted: encryptedMessage.toString('base64'),
            decrypted: decryptedMessage.toString(),
        })
    } catch (error) {
        res.status(500).json({ error: error.message })
    }
})

app.post('/api/hash', async (req, res) => {
    try {
        const { password } = req.body
        const saltRounds = 10
        // Salt is random data added to password before hashing
        // It makes identical passwords hash to different values
        // It is stored along with the hash
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
const PORT = 3000
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`)
    console.log('Open index.html in your browser to test security concepts')
})
