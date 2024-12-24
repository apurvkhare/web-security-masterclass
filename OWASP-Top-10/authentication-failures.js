/**
 * Authentication Failures Prevention Example
 * 
 * This module demonstrates five critical authentication security features:
 * 1. Password Policy - Enforces strong password requirements
 * 2. Rate Limiting - Prevents brute force attacks
 * 3. Multi-Factor Authentication - Adds second layer of security
 * 4. Session Management - Secures user sessions
 * 5. Secure Authentication Flow - Implements secure login/logout
 * 
 * To demonstrate:
 * 1. Set up Redis for rate limiting:
 *    ```bash
 *    docker run -d -p 6379:6379 redis
 *    ```
 * 
 * 2. Create a test Express app:
 *    ```javascript
 *    const express = require('express');
 *    const {
 *        AuthenticationService,
 *        loginLimiter,
 *        MFAHandler
 *    } = require('./authentication-failures');
 *    
 *    const app = express();
 *    app.use(express.json());
 *    
 *    // Apply rate limiting to login
 *    app.post('/login', loginLimiter, async (req, res) => {
 *        try {
 *            const result = await AuthenticationService.login(
 *                req.body.username,
 *                req.body.password,
 *                req.body.mfaToken
 *            );
 *            res.json(result);
 *        } catch (error) {
 *            res.status(401).json({ error: error.message });
 *        }
 *    });
 *    
 *    app.listen(3000);
 *    ```
 * 
 * 3. Test authentication features:
 *    ```bash
 *    # Test password policy
 *    curl -X POST http://localhost:3000/register \
 *      -H "Content-Type: application/json" \
 *      -d '{"password": "weak"}'
 *    
 *    # Test rate limiting
 *    for i in {1..6}; do
 *        curl -X POST http://localhost:3000/login \
 *          -H "Content-Type: application/json" \
 *          -d '{"username": "test", "password": "wrong"}'
 *    done
 *    
 *    # Test MFA setup
 *    curl -X POST http://localhost:3000/mfa/setup \
 *      -H "Authorization: Bearer your-token"
 *    ```
 */

// 1. Password Policy Implementation
const passwordValidator = require('password-validator')

const passwordSchema = new passwordValidator()
    .min(12) // Minimum length
    .max(100) // Maximum length
    .uppercase() // Must have uppercase letters
    .lowercase() // Must have lowercase letters
    .digits(2) // Must have at least 2 digits
    .symbols(1) // Must have at least 1 symbol
    .not()
    .spaces() // Should not contain spaces
    .not()
    .oneOf(['Password123!', 'Admin123!']) // Blacklist common passwords

// 2. Rate Limiting
const rateLimit = require('express-rate-limit')
const RedisStore = require('rate-limit-redis')

const loginLimiter = rateLimit({
    store: new RedisStore({
        prefix: 'login_limit:',
        // Reset after 15 minutes
        windowMs: 15 * 60 * 1000,
        // Limit each IP to 5 requests per window
        max: 5,
    }),
    handler: (req, res) => {
        res.status(429).json({
            error: 'Too many login attempts, please try again later',
            retryAfter: req.rateLimit.resetTime,
        })
    },
})

// 3. Multi-Factor Authentication
class MFAHandler {
    static async setupMFA(user) {
        const secret = speakeasy.generateSecret()
        const qrCode = await QRCode.toDataURL(secret.otpauth_url)

        // Store secret securely
        await user.updateMFASecret(secret.base32)

        return {
            secret: secret.base32,
            qrCode,
        }
    }

    static verifyToken(token, secret) {
        return speakeasy.totp.verify({
            secret,
            encoding: 'base32',
            token,
            window: 1, // Allow 30 seconds clock skew
        })
    }
}

// 4. Session Management
const session = require('express-session')

app.use(
    session({
        name: 'sessionId',
        secret: process.env.SESSION_SECRET,
        cookie: {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            maxAge: 3600000, // 1 hour
        },
        rolling: true,
        resave: false,
        saveUninitialized: false,
    })
)

// 5. Secure Authentication Implementation
class AuthenticationService {
    static async login(username, password, mfaToken) {
        // Check rate limiting
        if (await this.isRateLimited(username)) {
            throw new Error('Too many attempts')
        }

        // Validate credentials
        const user = await User.findOne({ username })
        if (!user || !(await bcrypt.compare(password, user.password))) {
            await this.recordFailedAttempt(username)
            throw new Error('Invalid credentials')
        }

        // Verify MFA if enabled
        if (user.mfaEnabled) {
            if (
                !mfaToken ||
                !MFAHandler.verifyToken(mfaToken, user.mfaSecret)
            ) {
                throw new Error('Invalid MFA token')
            }
        }

        // Generate session
        const sessionToken = crypto.randomBytes(32).toString('hex')
        await this.storeSession(user.id, sessionToken)

        return {
            token: sessionToken,
            user: {
                id: user.id,
                username: user.username,
                role: user.role,
            },
        }
    }

    static async logout(sessionToken) {
        await this.invalidateSession(sessionToken)
        // Additional cleanup...
    }

    static async passwordReset(email) {
        const user = await User.findOne({ email })
        if (!user) return // Don't reveal if email exists

        const token = crypto.randomBytes(32).toString('hex')
        const expiry = Date.now() + 3600000 // 1 hour

        await this.storeResetToken(user.id, token, expiry)
        await this.sendResetEmail(email, token)
    }
}

module.exports = {
    passwordSchema,
    loginLimiter,
    MFAHandler,
    AuthenticationService,
}
