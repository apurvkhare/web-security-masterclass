# Encoding, Encryption & Hashing

## Table of Contents

1. [Basic Concepts](#basic-concepts)
2. [Encoding](#encoding)
3. [Encryption](#encryption)
4. [Hashing](#hashing)
5. [HTTPS](#https)
6. [Best Practices](#best-practices)

## Basic Concepts

### Encoding vs Encryption vs Hashing

-   **Encoding**: Transforms data to ensure proper consumption. Not for security.
-   **Encryption**: Transforms data to keep it secret, with the ability to decrypt.
-   **Hashing**: One-way transformation of data into a fixed-size string.

## Encoding

### Common Encoding Schemes

1. **Base64**

    - Used for binary data in text-based protocols
    - Not for security, easily reversible

    ```javascript
    // Encoding
    const encoded = Buffer.from('Hello').toString('base64')
    // Decoding
    const decoded = Buffer.from(encoded, 'base64').toString()
    ```

2. **URL Encoding**
    - Converts special characters for URL safety
    ```javascript
    const encoded = encodeURIComponent('Hello World!')
    const decoded = decodeURIComponent(encoded)
    ```

## Encryption

### Types of Encryption

1. **Symmetric Encryption**

    - Same key for encryption and decryption
    - Faster but key distribution is challenging

    ```javascript
    const crypto = require('crypto')
    const algorithm = 'aes-256-cbc'
    const key = crypto.randomBytes(32)
    const iv = crypto.randomBytes(16)
    ```

2. **Asymmetric Encryption**
    - Public key for encryption
    - Private key for decryption
    - Slower but better key distribution
    ```javascript
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
    })
    ```

### Common Algorithms

-   AES (Symmetric)
-   RSA (Asymmetric)
-   ChaCha20 (Symmetric)

## Hashing

### Characteristics

-   One-way function
-   Fixed-size output
-   Deterministic
-   Avalanche effect

### Common Algorithms

1. **General Purpose**

    - SHA-256, SHA-512
    - Blake2, Blake3

    ```javascript
    const hash = crypto.createHash('sha256').update('password123').digest('hex')
    ```

2. **Password Hashing**
    - Argon2
    - bcrypt
    - PBKDF2
    ```javascript
    const bcrypt = require('bcrypt')
    const hashedPassword = await bcrypt.hash('password123', 10)
    ```

## HTTPS

### TLS/SSL Protocol

1. **Handshake Process**

    - Client Hello
    - Server Hello
    - Certificate Exchange
    - Key Exchange
    - Secure Communication

2. **Certificate Components**
    - Subject
    - Issuer
    - Public Key
    - Digital Signature
    - Validity Period

### Implementation

```javascript
const https = require('https')
const fs = require('fs')

const options = {
    key: fs.readFileSync('private-key.pem'),
    cert: fs.readFileSync('certificate.pem'),
}

https
    .createServer(options, (req, res) => {
        res.writeHead(200)
        res.end('Secure Hello World!')
    })
    .listen(443)
```

## Best Practices

### Encryption

1. **Key Management**

    - Secure key storage
    - Regular key rotation
    - Proper key length

2. **Algorithm Selection**
    - Use standard algorithms
    - Avoid deprecated algorithms
    - Follow industry recommendations

### Password Storage

1. **Never store plain passwords**
2. **Use strong hashing algorithms**
3. **Implement proper salting**
4. **Use appropriate work factors**

### HTTPS Implementation

1. **Force HTTPS**

    ```javascript
    app.use((req, res, next) => {
        if (!req.secure) {
            return res.redirect(`https://${req.headers.host}${req.url}`)
        }
        next()
    })
    ```

2. **Security Headers**
    ```javascript
    app.use((req, res, next) => {
        res.setHeader('Strict-Transport-Security', 'max-age=31536000')
        next()
    })
    ```

## Demo Instructions

The accompanying `index.html` and `server.js` files demonstrate:

1. Password hashing and verification
2. Data encryption/decryption
3. HTTPS server setup
4. Security headers implementation

Check the demo files to see these security concepts in action.

## Comparison Table

| Feature          | Encoding                                                                 | Encryption                                                    | Hashing                                                        |
| ---------------- | ------------------------------------------------------------------------ | ------------------------------------------------------------- | -------------------------------------------------------------- |
| **Purpose**      | Data format conversion                                                   | Data confidentiality                                          | Data integrity & verification                                  |
| **Reversible**   | Yes (easily)                                                             | Yes (with key)                                                | No                                                             |
| **Key Required** | No                                                                       | Yes                                                           | No                                                             |
| **Output**       | Variable length                                                          | Variable length                                               | Fixed length                                                   |
| **Security Use** | None (not for security)                                                  | Protecting data confidentiality                               | Password storage, data integrity                               |
| **Common Uses**  | - Binary to text conversion<br>- URL-safe strings<br>- Data transmission | - Secure communication<br>- Data storage<br>- File protection | - Password storage<br>- File checksums<br>- Digital signatures |
| **Examples**     | - Base64<br>- URL encoding<br>- ASCII                                    | - AES<br>- RSA<br>- ChaCha20                                  | - SHA-256<br>- bcrypt<br>- Argon2                              |
| **Performance**  | Fast                                                                     | Moderate to Slow                                              | Fast to Moderate                                               |
| **Use When**     | Need to represent data in a different format                             | Need to keep data secret and retrieve it later                | Need to verify data integrity or store passwords               |

Check the demo files to see these security concepts in action.
