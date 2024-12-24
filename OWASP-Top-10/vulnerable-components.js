/**
 * Vulnerable Components Prevention Example
 *
 * This module demonstrates five key security measures:
 * 1. Dependency Management - Secure package.json configuration
 * 2. Version Verification - Check for known vulnerable versions
 * 3. Integrity Verification - Verify file checksums
 * 4. Safe Package Installation - Whitelist-based package management
 * 5. Runtime Dependency Monitoring - Active version monitoring
 *
 * To demonstrate:
 * 1. Set up a test project:
 *    ```bash
 *    mkdir secure-project && cd secure-project
 *    npm init -y
 *    ```
 *
 * 2. Run security checks:
 *    ```bash
 *    # Check for vulnerabilities
 *    npm audit
 *
 *    # Check outdated packages
 *    npm outdated
 *
 *    # Verify package signatures
 *    npm audit signatures
 *    ```
 */

/**
 * Package.json Security Configuration
 * Demonstrates secure dependency management practices
 *
 * Features:
 * - Exact version pinning
 * - Security audit scripts
 * - Pre/post install checks
 * - Dependency verification
 */
const packageJson = {
    name: 'secure-app',
    version: '1.0.0',
    scripts: {
        // Regular security checks
        audit: 'npm audit',
        outdated: 'npm outdated',
        'audit:fix': 'npm audit fix',

        // Custom security scripts
        'security:check': 'npm run audit && npm run outdated',
        preinstall: 'node scripts/check-registry.js',
        postinstall: 'node scripts/verify-checksums.js',
    },
    dependencies: {
        // Specify exact versions
        express: '4.18.2',
        helmet: '7.1.0',
    },
}

/**
 * Version Verification System
 * Checks installed packages against known vulnerable versions
 *
 * Example:
 * ```javascript
 * // Will throw error if vulnerable versions found
 * checkDependencyVersions();
 * ```
 */
function checkDependencyVersions() {
    // Get installed versions
    const dependencies = JSON.parse(execSync('npm list --json').toString())

    // Check known vulnerable versions
    const vulnerableVersions = {
        jquery: '<3.0.0',
        lodash: '<4.17.21',
        moment: '<2.29.2',
    }

    for (const [pkg, version] of Object.entries(vulnerableVersions)) {
        if (dependencies[pkg] && semver.satisfies(dependencies[pkg], version)) {
            throw new Error(`Vulnerable version of ${pkg} detected`)
        }
    }
}

/**
 * File Integrity Verification
 * Ensures files haven't been tampered with
 *
 * Example:
 * ```javascript
 * const expectedHash = 'sha256-hash-of-original-file';
 * verifyFileIntegrity('important.js', expectedHash);
 * ```
 */
function verifyFileIntegrity(filePath, expectedHash) {
    const fileBuffer = fs.readFileSync(filePath)
    const hash = crypto.createHash('sha256').update(fileBuffer).digest('hex')

    if (hash !== expectedHash) {
        throw new Error('File integrity check failed')
    }
    return true
}

/**
 * Safe Package Installation
 * Implements whitelist-based package management
 *
 * Features:
 * - Package whitelist validation
 * - Registry source verification
 * - Exact version installation
 *
 * Example:
 * ```javascript
 * try {
 *     // This should succeed
 *     await installPackage('express', '4.18.2');
 *
 *     // This should fail (not in whitelist)
 *     await installPackage('malicious-package', '1.0.0');
 * } catch (error) {
 *     console.error('Installation failed:', error.message);
 * }
 * ```
 */
function installPackage(packageName, version) {
    // Check if package is in whitelist
    const whitelist = ['express', 'helmet', 'winston']
    if (!whitelist.includes(packageName)) {
        throw new Error('Package not in whitelist')
    }

    // Verify package source
    const trustedRegistries = ['https://registry.npmjs.org']
    const registry = execSync(`npm config get registry`).toString().trim()
    if (!trustedRegistries.includes(registry)) {
        throw new Error('Untrusted package registry')
    }

    // Install with exact version
    execSync(`npm install ${packageName}@${version} --save-exact`)
}

/**
 * Runtime Dependency Monitor
 * Actively monitors loaded dependencies for version mismatches
 *
 * Features:
 * - Real-time version checking
 * - Module load tracking
 * - Version compatibility validation
 *
 * Example:
 * ```javascript
 * // Monitor critical dependencies
 * DependencyMonitor.monitor('express', '4.18.x');
 * DependencyMonitor.monitor('helmet', '7.x');
 *
 * // Check monitored modules
 * console.log(DependencyMonitor.monitoredModules);
 * ```
 */
class DependencyMonitor {
    static monitoredModules = new Map()

    static monitor(moduleName, expectedVersion) {
        try {
            const loadedModule = require(moduleName)
            const actualVersion =
                loadedModule.version || process.modules[moduleName]

            if (!semver.satisfies(actualVersion, expectedVersion)) {
                throw new Error(
                    `Version mismatch for ${moduleName}: ` +
                        `expected ${expectedVersion}, got ${actualVersion}`
                )
            }

            this.monitoredModules.set(moduleName, {
                version: actualVersion,
                loadTime: Date.now(),
            })
        } catch (error) {
            console.error(`Failed to monitor ${moduleName}:`, error)
            process.exit(1)
        }
    }
}

// Usage
DependencyMonitor.monitor('express', '4.18.x')
DependencyMonitor.monitor('helmet', '7.x')

module.exports = {
    CodeIntegrityVerifier,
    SecureUpdater,
    PipelineSecurity,
    RuntimeIntegrityMonitor,
}
