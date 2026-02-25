<?php
/**
 * SRM-Audit - OWASP Top 10 Vulnerability Library
 * Pre-populated reference data for vulnerability assessment.
 * 
 * Each vulnerability includes:
 * - Auto-assigned likelihood & impact (1-5)
 * - Threat/impact description
 * - NIST CSF function mapping
 * - Audit checklist item (connects to Module 6)
 * - Recommendation for remediation
 */

function getOwaspLibrary() {
    return [
        // ============================================
        // CATEGORY: Injection
        // ============================================
        [
            'id' => 1,
            'category' => 'Injection',
            'name' => 'SQL Injection',
            'description' => 'Untrusted data is sent to an interpreter as part of a command or query, allowing attackers to execute unintended commands or access data.',
            'default_likelihood' => 4,
            'default_impact' => 5,
            'threat' => 'Database theft, data manipulation, unauthorized access to sensitive records',
            'nist_function' => 'Protect',
            'audit_checklist' => 'Verify parameterized queries/prepared statements are used for all database interactions. Check for input validation on all user inputs.',
            'recommendation' => 'Use prepared statements/parameterized queries. Implement server-side input validation. Apply least privilege to database accounts.',
            'cwe_id' => 'CWE-89'
        ],
        [
            'id' => 2,
            'category' => 'Injection',
            'name' => 'Command Injection',
            'description' => 'Application passes unsafe user data to a system shell, allowing execution of arbitrary OS commands.',
            'default_likelihood' => 3,
            'default_impact' => 5,
            'threat' => 'Full server compromise, data exfiltration, lateral movement within network',
            'nist_function' => 'Protect',
            'audit_checklist' => 'Verify no user input is passed directly to system commands (exec, shell_exec, system). Check for command whitelist approach.',
            'recommendation' => 'Avoid calling OS commands directly. Use language-specific APIs instead. If necessary, whitelist allowed commands and sanitize all inputs.',
            'cwe_id' => 'CWE-78'
        ],
        [
            'id' => 3,
            'category' => 'Injection',
            'name' => 'LDAP Injection',
            'description' => 'Manipulation of LDAP statements via user input to access or modify directory information.',
            'default_likelihood' => 2,
            'default_impact' => 4,
            'threat' => 'Unauthorized directory access, privilege escalation, information disclosure',
            'nist_function' => 'Protect',
            'audit_checklist' => 'Verify LDAP queries use parameterized filters. Check that special LDAP characters are properly escaped.',
            'recommendation' => 'Escape special LDAP characters in user input. Use parameterized LDAP queries. Validate and sanitize all inputs before use.',
            'cwe_id' => 'CWE-90'
        ],

        // ============================================
        // CATEGORY: Broken Authentication
        // ============================================
        [
            'id' => 4,
            'category' => 'Broken Authentication',
            'name' => 'Weak Password Policy',
            'description' => 'System allows weak, default, or commonly-used passwords without enforcing complexity requirements.',
            'default_likelihood' => 4,
            'default_impact' => 4,
            'threat' => 'Account takeover, credential stuffing attacks, brute force success',
            'nist_function' => 'Protect',
            'audit_checklist' => 'Verify password policy enforces minimum 8 characters with complexity (uppercase, lowercase, number, special character). Check password history requirements.',
            'recommendation' => 'Enforce minimum 8-character passwords with complexity requirements. Implement password history. Check against known breached password lists.',
            'cwe_id' => 'CWE-521'
        ],
        [
            'id' => 5,
            'category' => 'Broken Authentication',
            'name' => 'No Account Lockout',
            'description' => 'System does not lock accounts after multiple failed login attempts, enabling brute force attacks.',
            'default_likelihood' => 4,
            'default_impact' => 4,
            'threat' => 'Brute force password cracking, automated credential attacks',
            'nist_function' => 'Protect',
            'audit_checklist' => 'Verify account lockout is enabled after 5 consecutive failed login attempts. Check lockout duration and reset mechanism.',
            'recommendation' => 'Implement account lockout after 3-5 failed attempts. Add progressive delay between attempts. Enable multi-factor authentication (MFA).',
            'cwe_id' => 'CWE-307'
        ],
        [
            'id' => 6,
            'category' => 'Broken Authentication',
            'name' => 'Session Hijacking',
            'description' => 'Session tokens can be stolen or predicted, allowing attackers to impersonate legitimate users.',
            'default_likelihood' => 3,
            'default_impact' => 5,
            'threat' => 'Account hijacking, unauthorized access to user sessions, identity theft',
            'nist_function' => 'Protect',
            'audit_checklist' => 'Verify session tokens are cryptographically random. Check that session IDs rotate after login. Confirm HttpOnly and Secure cookie flags are set.',
            'recommendation' => 'Use secure, random session tokens. Set HttpOnly and Secure flags on session cookies. Regenerate session ID after authentication. Implement session timeout.',
            'cwe_id' => 'CWE-384'
        ],

        // ============================================
        // CATEGORY: Sensitive Data Exposure
        // ============================================
        [
            'id' => 7,
            'category' => 'Sensitive Data Exposure',
            'name' => 'No HTTPS / TLS',
            'description' => 'Data transmitted in cleartext without encryption, exposing it to eavesdropping and man-in-the-middle attacks.',
            'default_likelihood' => 4,
            'default_impact' => 5,
            'threat' => 'Credential interception, data eavesdropping, man-in-the-middle attacks',
            'nist_function' => 'Protect',
            'audit_checklist' => 'Verify TLS certificate is installed and HTTPS is enforced on all pages. Check that HTTP redirects to HTTPS. Verify TLS 1.2+ is used.',
            'recommendation' => 'Install valid TLS certificate. Force HTTPS on all pages. Disable TLS 1.0/1.1. Enable HSTS header.',
            'cwe_id' => 'CWE-319'
        ],
        [
            'id' => 8,
            'category' => 'Sensitive Data Exposure',
            'name' => 'Weak Encryption',
            'description' => 'Use of outdated or weak cryptographic algorithms (MD5, SHA1, DES) to protect sensitive data.',
            'default_likelihood' => 3,
            'default_impact' => 4,
            'threat' => 'Data decryption by attackers, credential exposure, compliance violation',
            'nist_function' => 'Protect',
            'audit_checklist' => 'Verify strong encryption algorithms are used (AES-256, bcrypt/argon2 for passwords). Check that no MD5/SHA1 is used for security purposes.',
            'recommendation' => 'Use AES-256 for data encryption. Use bcrypt or Argon2 for password hashing. Replace any MD5/SHA1 usage. Implement proper key management.',
            'cwe_id' => 'CWE-327'
        ],
        [
            'id' => 9,
            'category' => 'Sensitive Data Exposure',
            'name' => 'Exposed Database Backup',
            'description' => 'Database backups are accessible via web or stored without encryption, exposing all organizational data.',
            'default_likelihood' => 3,
            'default_impact' => 5,
            'threat' => 'Complete data breach, regulatory fines, reputational damage',
            'nist_function' => 'Identify',
            'audit_checklist' => 'Verify database backups are stored outside web root. Check that backups are encrypted at rest. Confirm access controls on backup files.',
            'recommendation' => 'Store backups outside web-accessible directories. Encrypt backups at rest. Implement strict access controls. Regularly test backup restoration.',
            'cwe_id' => 'CWE-530'
        ],

        // ============================================
        // CATEGORY: Access Control Failures
        // ============================================
        [
            'id' => 10,
            'category' => 'Access Control Failures',
            'name' => 'IDOR (Insecure Direct Object Reference)',
            'description' => 'Application exposes internal object references (e.g., database IDs) allowing users to access other users\' data.',
            'default_likelihood' => 4,
            'default_impact' => 4,
            'threat' => 'Unauthorized data access, data manipulation of other users\' records',
            'nist_function' => 'Protect',
            'audit_checklist' => 'Verify all data access endpoints validate user ownership/authorization. Check that direct object references include authorization checks.',
            'recommendation' => 'Implement access control checks for every data request. Use indirect references. Validate that the current user owns or has permission to access the requested resource.',
            'cwe_id' => 'CWE-639'
        ],
        [
            'id' => 11,
            'category' => 'Access Control Failures',
            'name' => 'Privilege Escalation',
            'description' => 'Users can escalate their privileges to access admin or other restricted functions.',
            'default_likelihood' => 3,
            'default_impact' => 5,
            'threat' => 'Unauthorized admin access, system compromise, data breach',
            'nist_function' => 'Protect',
            'audit_checklist' => 'Verify role-based access control (RBAC) is enforced server-side. Check that privilege changes require re-authentication.',
            'recommendation' => 'Implement server-side role-based access control. Deny by default. Re-authenticate for privilege changes. Log all access control failures.',
            'cwe_id' => 'CWE-269'
        ],

        // ============================================
        // CATEGORY: Security Misconfiguration
        // ============================================
        [
            'id' => 12,
            'category' => 'Security Misconfiguration',
            'name' => 'Default Credentials',
            'description' => 'System or application uses default usernames/passwords that are publicly known.',
            'default_likelihood' => 4,
            'default_impact' => 5,
            'threat' => 'Immediate unauthorized access, complete system compromise',
            'nist_function' => 'Protect',
            'audit_checklist' => 'Verify all default credentials have been changed. Check admin accounts, database accounts, and service accounts for default passwords.',
            'recommendation' => 'Change all default credentials immediately after installation. Enforce password change on first login. Audit all service accounts regularly.',
            'cwe_id' => 'CWE-798'
        ],
        [
            'id' => 13,
            'category' => 'Security Misconfiguration',
            'name' => 'Directory Listing Enabled',
            'description' => 'Web server exposes directory contents, revealing file structure and potentially sensitive files.',
            'default_likelihood' => 3,
            'default_impact' => 3,
            'threat' => 'Information disclosure, discovery of sensitive files, attack surface mapping',
            'nist_function' => 'Identify',
            'audit_checklist' => 'Verify directory listing is disabled on the web server. Check Apache/Nginx configuration for Options -Indexes or autoindex off.',
            'recommendation' => 'Disable directory listing in web server configuration. Add index files to all directories. Review exposed file structure.',
            'cwe_id' => 'CWE-548'
        ],
        [
            'id' => 14,
            'category' => 'Security Misconfiguration',
            'name' => 'Exposed Admin Panel',
            'description' => 'Administrative interface is publicly accessible without IP restriction or additional authentication.',
            'default_likelihood' => 4,
            'default_impact' => 5,
            'threat' => 'Brute force on admin login, unauthorized system administration',
            'nist_function' => 'Protect',
            'audit_checklist' => 'Verify admin panel is restricted by IP or VPN. Check for additional authentication (MFA) on admin access. Confirm admin URL is not easily guessable.',
            'recommendation' => 'Restrict admin panel access by IP whitelist or VPN. Implement MFA for admin accounts. Use non-standard admin URLs. Enable logging on admin access.',
            'cwe_id' => 'CWE-749'
        ],
        [
            'id' => 15,
            'category' => 'Security Misconfiguration',
            'name' => 'Open Unnecessary Ports',
            'description' => 'Server has unnecessary services and ports open, increasing the attack surface.',
            'default_likelihood' => 3,
            'default_impact' => 4,
            'threat' => 'Service exploitation, lateral movement, unauthorized access to services',
            'nist_function' => 'Identify',
            'audit_checklist' => 'Verify only necessary ports are open (run port scan). Check firewall rules. Confirm unused services are disabled.',
            'recommendation' => 'Close all unnecessary ports. Disable unused services. Implement firewall rules following least-privilege principle. Conduct regular port scans.',
            'cwe_id' => 'CWE-16'
        ],

        // ============================================
        // CATEGORY: Cross-Site Attacks
        // ============================================
        [
            'id' => 16,
            'category' => 'Cross-Site Attacks',
            'name' => 'Cross-Site Scripting (XSS)',
            'description' => 'Application includes unvalidated user input in output, allowing attackers to execute scripts in victims\' browsers.',
            'default_likelihood' => 4,
            'default_impact' => 4,
            'threat' => 'Account hijacking, cookie theft, defacement, phishing via trusted domain',
            'nist_function' => 'Protect',
            'audit_checklist' => 'Verify all user output is properly encoded/escaped. Check for Content-Security-Policy header. Test input fields for XSS payloads.',
            'recommendation' => 'Encode all output (HTML entity encoding). Implement Content-Security-Policy header. Use frameworks with auto-escaping. Validate and sanitize all inputs.',
            'cwe_id' => 'CWE-79'
        ],
        [
            'id' => 17,
            'category' => 'Cross-Site Attacks',
            'name' => 'Cross-Site Request Forgery (CSRF)',
            'description' => 'Application does not verify that requests come from legitimate user actions, allowing forged cross-site requests.',
            'default_likelihood' => 3,
            'default_impact' => 4,
            'threat' => 'Unauthorized transactions, password changes, data modification on behalf of victim',
            'nist_function' => 'Protect',
            'audit_checklist' => 'Verify anti-CSRF tokens are present on all state-changing forms. Check that tokens are validated server-side. Confirm SameSite cookie attribute is set.',
            'recommendation' => 'Implement anti-CSRF tokens on all state-changing requests. Set SameSite cookie attribute. Verify Origin/Referer headers on critical actions.',
            'cwe_id' => 'CWE-352'
        ],

        // ============================================
        // CATEGORY: Logging & Monitoring Failure
        // ============================================
        [
            'id' => 18,
            'category' => 'Logging & Monitoring Failure',
            'name' => 'No Audit Logs',
            'description' => 'System does not log security events, making it impossible to detect or investigate incidents.',
            'default_likelihood' => 3,
            'default_impact' => 4,
            'threat' => 'Incidents go undetected, no forensic evidence, compliance violations',
            'nist_function' => 'Detect',
            'audit_checklist' => 'Verify security events are logged (login attempts, access failures, privilege changes). Check log retention policy. Confirm logs are tamper-proof.',
            'recommendation' => 'Implement comprehensive audit logging for all security events. Store logs securely with tamper protection. Set up log monitoring and alerting. Maintain logs for minimum 90 days.',
            'cwe_id' => 'CWE-778'
        ],

        // ============================================
        // CATEGORY: Dependency & Software Issues
        // ============================================
        [
            'id' => 19,
            'category' => 'Dependency & Software Issues',
            'name' => 'Outdated Server Software',
            'description' => 'Server runs outdated software versions with known vulnerabilities that have published exploits.',
            'default_likelihood' => 4,
            'default_impact' => 5,
            'threat' => 'Remote code execution, known exploit attacks, complete server compromise',
            'nist_function' => 'Identify',
            'audit_checklist' => 'Verify all server software is up-to-date (OS, web server, database, runtime). Check for known CVEs against installed versions. Confirm patch management process exists.',
            'recommendation' => 'Establish a regular patch management schedule. Subscribe to vendor security advisories. Use automated vulnerability scanning. Prioritize critical patches within 48 hours.',
            'cwe_id' => 'CWE-1104'
        ]
    ];
}

/**
 * Get OWASP library grouped by category
 */
function getOwaspLibraryGrouped() {
    $library = getOwaspLibrary();
    $grouped = [];
    foreach ($library as $vuln) {
        $grouped[$vuln['category']][] = $vuln;
    }
    return $grouped;
}

/**
 * Get a single vulnerability by ID
 */
function getOwaspVulnById($id) {
    $library = getOwaspLibrary();
    foreach ($library as $vuln) {
        if ($vuln['id'] == $id) {
            return $vuln;
        }
    }
    return null;
}

/**
 * Get vulnerabilities by array of IDs
 */
function getOwaspVulnsByIds($ids) {
    $library = getOwaspLibrary();
    $result = [];
    foreach ($library as $vuln) {
        if (in_array($vuln['id'], $ids)) {
            $result[] = $vuln;
        }
    }
    return $result;
}
