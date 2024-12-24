/**
 * SSRF (Server-Side Request Forgery) Prevention Example
 *
 * This module demonstrates three layers of SSRF protection:
 * 1. URL Validation - Blocks dangerous protocols and internal networks
 * 2. Request Sanitization - Validates all incoming URLs in requests
 * 3. Secure HTTP Client - Implements safe outbound requests
 *
 * To demonstrate:
 * 1. Start a local server with both public and internal endpoints
 * 2. Try accessing them through the SecureHTTPClient
 * 3. Observe how internal/malicious requests are blocked
 *
 * Example usage:
 * ```
 * // Setup secure client
 * const client = new SecureHTTPClient({
 *     allowedDomains: ['api.example.com'],
 *     maxRedirects: 2
 * });
 *
 * // These should fail:
 * await client.fetch('file:///etc/passwd');
 * await client.fetch('http://localhost:8080');
 * await client.fetch('http://192.168.1.1');
 *
 * // This should succeed:
 * await client.fetch('https://api.example.com/data');
 * ```
 */

const { URL } = require('url')
const dns = require('dns')
const net = require('net')
const ipRangeCheck = require('ip-range-check')

class URLValidator {
    // Protocols that could lead to SSRF attacks
    static BLOCKED_PROTOCOLS = new Set(['file:', 'gopher:', 'data:', 'dict:'])

    // IP ranges that should not be accessible
    static PRIVATE_IP_RANGES = [
        '127.0.0.0/8', // Localhost
        '10.0.0.0/8', // Private network
        '172.16.0.0/12', // Private network
        '192.168.0.0/16', // Private network
        '169.254.0.0/16', // Link-local
        'fc00::/7', // Unique local address
    ]

    /**
     * Validates a URL against SSRF vulnerabilities
     *
     * @param {string} urlString - The URL to validate
     * @throws {Error} If URL is potentially malicious
     * @returns {URL} Validated URL object
     *
     * Example:
     * ```
     * // This should throw an error
     * await URLValidator.validateURL('http://localhost/admin');
     *
     * // This should pass
     * await URLValidator.validateURL('https://api.example.com/data');
     * ```
     */
    static async validateURL(urlString) {
        try {
            // Parse URL
            const url = new URL(urlString)

            // 1. Protocol check
            if (this.BLOCKED_PROTOCOLS.has(url.protocol.toLowerCase())) {
                throw new Error('Blocked URL protocol')
            }

            // 2. Hostname validation
            if (!url.hostname) {
                throw new Error('Invalid hostname')
            }

            // 3. DNS resolution and IP check
            const ips = await this.resolveHostname(url.hostname)
            await this.validateIPs(ips)

            return url
        } catch (error) {
            throw new Error(`URL validation failed: ${error.message}`)
        }
    }

    static async resolveHostname(hostname) {
        return new Promise((resolve, reject) => {
            dns.resolve(hostname, (err, addresses) => {
                if (err) reject(err)
                resolve(addresses)
            })
        })
    }

    static async validateIPs(ips) {
        for (const ip of ips) {
            if (this.PRIVATE_IP_RANGES.some(range => ipRangeCheck(ip, range))) {
                throw new Error('Access to internal network blocked')
            }
        }
        return true
    }
}

// 2. Request Sanitization Middleware
class RequestSanitizer {
    static async sanitizeRequest(req) {
        // 1. Validate URLs in query parameters
        if (req.query) {
            for (const [key, value] of Object.entries(req.query)) {
                if (this.looksLikeURL(value)) {
                    await URLValidator.validateURL(value)
                }
            }
        }

        // 2. Validate URLs in request body
        if (req.body) {
            await this.recursiveURLValidation(req.body)
        }

        return true
    }

    static looksLikeURL(str) {
        return typeof str === 'string' && /^https?:\/\//i.test(str)
    }

    static async recursiveURLValidation(obj) {
        for (const [key, value] of Object.entries(obj)) {
            if (typeof value === 'string' && this.looksLikeURL(value)) {
                await URLValidator.validateURL(value)
            } else if (typeof value === 'object' && value !== null) {
                await this.recursiveURLValidation(value)
            }
        }
    }
}

// 3. Secure HTTP Client
class SecureHTTPClient {
    constructor(options = {}) {
        this.allowedDomains = options.allowedDomains || []
        this.maxRedirects = options.maxRedirects || 0
        this.timeout = options.timeout || 5000
    }

    async fetch(urlString, options = {}) {
        // 1. Validate URL
        const url = await URLValidator.validateURL(urlString)

        // 2. Domain whitelist check
        if (
            this.allowedDomains.length &&
            !this.allowedDomains.includes(url.hostname)
        ) {
            throw new Error('Domain not in whitelist')
        }

        // 3. Configure secure fetch options
        const secureOptions = {
            ...options,
            redirect: 'manual',
            timeout: this.timeout,
            headers: {
                ...options.headers,
                Host: url.hostname,
            },
        }

        // 4. Make request with redirect handling
        return this.makeRequestWithRedirects(url, secureOptions)
    }

    async makeRequestWithRedirects(url, options, redirectCount = 0) {
        const response = await fetch(url, options)

        if (response.status >= 300 && response.status < 400) {
            if (redirectCount >= this.maxRedirects) {
                throw new Error('Max redirects exceeded')
            }

            const location = response.headers.get('location')
            if (location) {
                const redirectUrl = await URLValidator.validateURL(location)
                return this.makeRequestWithRedirects(
                    redirectUrl,
                    options,
                    redirectCount + 1
                )
            }
        }

        return response
    }
}

/**
 * Demonstration Setup:
 *
 * 1. Create a test server:
 * ```javascript
 * const express = require('express');
 * const app = express();
 *
 * // Public endpoint
 * app.get('/public', (req, res) => res.json({ status: 'ok' }));
 *
 * app.listen(8080);
 * ```
 *
 * 2. Run test cases:
 * ```javascript
 * async function demonstrateSSRF() {
 *     const client = new SecureHTTPClient({
 *         allowedDomains: ['localhost:8080'],
 *         maxRedirects: 1
 *     });
 *
 *     try {
 *         // Should fail (internal IP)
 *         await client.fetch('http://192.168.1.1');
 *     } catch (error) {
 *         console.log('Successfully blocked internal IP');
 *     }
 *
 *     try {
 *         // Should fail (blocked protocol)
 *         await client.fetch('file:///etc/passwd');
 *     } catch (error) {
 *         console.log('Successfully blocked file protocol');
 *     }
 *
 *     // Should succeed
 *     const response = await client.fetch('http://localhost:8080/public');
 *     console.log('Successfully accessed public endpoint');
 * }
 *
 * demonstrateSSRF();
 * ```
 */

module.exports = {
    URLValidator,
    RequestSanitizer,
    SecureHTTPClient,
}
