/**
 * Security Monitoring and Logging Implementation
 * 
 * This module provides three main security monitoring components:
 * 1. SecurityLogger - Structured logging with multiple transports
 * 2. SecurityMonitor - Event tracking and alert generation
 * 3. Monitoring Middleware - Real-time request/response monitoring
 * 
 * To demonstrate:
 * 1. Set up Elasticsearch (for searchable logs):
 *    ```bash
 *    docker run -d -p 9200:9200 -e "discovery.type=single-node" elasticsearch:8.7.0
 *    ```
 * 
 * 2. Create a test Express app:
 *    ```javascript
 *    const express = require('express');
 *    const { 
 *        SecurityLogger, 
 *        SecurityMonitor, 
 *        securityMonitoringMiddleware 
 *    } = require('./security-monitoring');
 *    
 *    const app = express();
 *    app.use(securityMonitoringMiddleware);
 *    
 *    // Example notification service
 *    const notificationService = {
 *        send: (alert) => console.log('ALERT:', alert)
 *    };
 *    
 *    const monitor = new SecurityMonitor(notificationService);
 *    
 *    // Test endpoints
 *    app.post('/login', (req, res) => {
 *        monitor.trackEvent('LOGIN_FAILURES', req.ip);
 *        res.status(401).json({ error: 'Invalid credentials' });
 *    });
 *    
 *    app.listen(3000);
 *    ```
 * 
 * 3. Test the monitoring:
 *    ```bash
 *    # Generate login failures (should trigger alert after 5 attempts)
 *    for i in {1..6}; do 
 *        curl -X POST http://localhost:3000/login
 *        sleep 1
 *    done
 *    ```
 */

const winston = require('winston')
const { ElasticsearchTransport } = require('winston-elasticsearch')

/**
 * SecurityLogger Class
 * Provides structured logging with multiple output targets
 * 
 * Features:
 * - Console logging for development
 * - File logging for production
 * - Elasticsearch integration for searchable logs
 * - Standardized security event format
 * 
 * Example:
 * ```javascript
 * const logger = new SecurityLogger();
 * logger.logSecurityEvent('user_login', {
 *     userId: 'user123',
 *     ip: '192.168.1.1',
 *     success: false
 * });
 * ```
 */
class SecurityLogger {
    constructor() {
        this.logger = winston.createLogger({
            level: 'info',
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.json()
            ),
            defaultMeta: { service: 'security-service' },
            transports: [
                new winston.transports.Console({
                    format: winston.format.simple(),
                    level: 'debug'
                }),
                new winston.transports.File({
                    filename: 'security-events.log',
                    level: 'info'
                }),
                new ElasticsearchTransport({
                    level: 'info',
                    index: 'security-logs',
                    clientOpts: { node: process.env.ELASTICSEARCH_URL }
                })
            ]
        })
    }

    /**
     * Log a security event
     * @param {string} eventType - Type of security event
     * @param {object} data - Event data
     * @param {string} [severity='info'] - Event severity level
     */
    logSecurityEvent(eventType, data, severity = 'info') {
        const event = {
            eventType,
            timestamp: new Date(),
            severity,
            ...data,
            metadata: {
                ip: data.ip || 'unknown',
                userId: data.userId || 'anonymous',
                userAgent: data.userAgent || 'unknown',
            },
        }

        this.logger.log(severity, event)
    }
}

/**
 * SecurityMonitor Class
 * Tracks security events and generates alerts based on thresholds
 * 
 * Features:
 * - Configurable alert thresholds
 * - Event tracking with time windows
 * - Automatic alert generation
 * - Severity calculation
 * 
 * Example:
 * ```javascript
 * const monitor = new SecurityMonitor({
 *     send: (alert) => sendSlackNotification(alert)
 * });
 * 
 * // Track failed login attempts
 * monitor.trackEvent('LOGIN_FAILURES', userIP);
 * ```
 */
class SecurityMonitor {
    static ALERT_THRESHOLDS = {
        LOGIN_FAILURES: 5,
        SUSPICIOUS_IPS: 3,
        CRITICAL_ERRORS: 1,
    }

    constructor(notificationService) {
        this.events = new Map()
        this.notificationService = notificationService
        this.logger = new SecurityLogger()
    }

    trackEvent(eventType, identifier) {
        const key = `${eventType}:${identifier}`
        const now = Date.now()

        if (!this.events.has(key)) {
            this.events.set(key, {
                count: 1,
                firstSeen: now,
                lastSeen: now,
            })
            return
        }

        const event = this.events.get(key)
        event.count++
        event.lastSeen = now

        this.checkThresholds(eventType, identifier, event)
    }

    checkThresholds(eventType, identifier, event) {
        const threshold = SecurityMonitor.ALERT_THRESHOLDS[eventType]
        if (!threshold) return

        if (event.count >= threshold) {
            this.triggerAlert(eventType, identifier, event)
            this.events.delete(`${eventType}:${identifier}`) // Reset counter
        }
    }

    async triggerAlert(eventType, identifier, event) {
        const alert = {
            type: eventType,
            identifier,
            count: event.count,
            timespan: event.lastSeen - event.firstSeen,
            severity: this.calculateSeverity(eventType, event.count),
        }

        // Log the alert
        this.logger.logSecurityEvent('security_alert', alert, 'warn')

        // Send notification
        await this.notificationService.send(alert)
    }

    calculateSeverity(eventType, count) {
        const threshold = SecurityMonitor.ALERT_THRESHOLDS[eventType]
        if (count >= threshold * 2) return 'critical'
        if (count >= threshold) return 'high'
        return 'medium'
    }
}

/**
 * Security Monitoring Middleware
 * Express middleware for real-time request/response monitoring
 * 
 * Features:
 * - Logs all incoming requests
 * - Tracks response times
 * - Monitors error responses
 * - Captures request metadata
 * 
 * Example:
 * ```javascript
 * const app = express();
 * app.use(securityMonitoringMiddleware);
 * ```
 */
function securityMonitoringMiddleware(req, res, next) {
    const startTime = Date.now()
    const logger = new SecurityLogger()

    // Log all requests
    logger.logSecurityEvent('request', {
        method: req.method,
        path: req.path,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
    })

    // Track response
    res.on('finish', () => {
        const duration = Date.now() - startTime

        // Log suspicious responses
        if (res.statusCode >= 400) {
            logger.logSecurityEvent(
                'error_response',
                {
                    statusCode: res.statusCode,
                    duration,
                    path: req.path,
                    ip: req.ip,
                },
                res.statusCode >= 500 ? 'error' : 'warn'
            )
        }
    })

    next()
}

/**
 * Example Dashboard Setup:
 * 
 * 1. Kibana Configuration:
 * ```yaml
 * # kibana.yml
 * server.port: 5601
 * elasticsearch.hosts: ["http://localhost:9200"]
 * ```
 * 
 * 2. Create Visualization:
 * - Index pattern: security-logs-*
 * - Time field: timestamp
 * - Suggested visualizations:
 *   - Error rate over time
 *   - Top IP addresses by error count
 *   - Security events by severity
 *   - Average response time trend
 * 
 * 3. Sample Elasticsearch Query:
 * ```
 * GET security-logs-/_search
 * {
 *   "query": {
 *     "bool": {
 *       "must": [
 *         { "match": { "severity": "error" } },
 *         { "range": { 
 *             "timestamp": { "gte": "now-1h" }
 *         }}
 *       ]
 *     }
 *   }
 * }
 * ```
 */

module.exports = {
    SecurityLogger,
    SecurityMonitor,
    securityMonitoringMiddleware
}
