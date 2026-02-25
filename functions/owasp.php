<?php
/**
 * SRM-Audit - OWASP Vulnerability Library
 * Top vulnerabilities from OWASP Top 10 (2021) mapped to NIST CSF
 */

function getOwaspLibrary() {
    return [
        [
            'id' => 'A01:2021',
            'title' => 'Broken Access Control',
            'description' => 'Restrictions on authenticated users are not properly enforced',
            'cwe' => 'CWE-200, CWE-639',
            'nist_function' => 'Protect',
            'severity' => 'Critical',
        ],
        [
            'id' => 'A02:2021',
            'title' => 'Cryptographic Failures',
            'description' => 'Sensitive data exposed due to lack of encryption or weak cryptography',
            'cwe' => 'CWE-327, CWE-331',
            'nist_function' => 'Protect',
            'severity' => 'Critical',
        ],
        [
            'id' => 'A03:2021',
            'title' => 'Injection',
            'description' => 'SQL, NoSQL, OS, LDAP injections occur when hostile data is sent as query',
            'cwe' => 'CWE-89, CWE-94',
            'nist_function' => 'Protect',
            'severity' => 'Critical',
        ],
        [
            'id' => 'A04:2021',
            'title' => 'Insecure Design',
            'description' => 'Missing or ineffective control design and security architecture flaws',
            'cwe' => 'CWE-434, CWE-776',
            'nist_function' => 'Identify',
            'severity' => 'High',
        ],
        [
            'id' => 'A05:2021',
            'title' => 'Security Misconfiguration',
            'description' => 'Insecure default configurations, incomplete setups, open cloud storage, etc.',
            'cwe' => 'CWE-16, CWE-693',
            'nist_function' => 'Protect',
            'severity' => 'High',
        ],
        [
            'id' => 'A06:2021',
            'title' => 'Vulnerable and Outdated Components',
            'description' => 'Libraries, frameworks with known vulnerabilities are used in production',
            'cwe' => 'CWE-1035, CWE-937',
            'nist_function' => 'Identify',
            'severity' => 'High',
        ],
        [
            'id' => 'A07:2021',
            'title' => 'Authentication Flaws',
            'description' => 'Permits automated attacks like credential stuffing, brute force, default creds',
            'cwe' => 'CWE-297, CWE-613',
            'nist_function' => 'Protect',
            'severity' => 'High',
        ],
        [
            'id' => 'A08:2021',
            'title' => 'Software and Data Integrity Failures',
            'description' => 'CI/CD pipeline, unsafe deserialization, unsigned updates',
            'cwe' => 'CWE-345, CWE-502',
            'nist_function' => 'Protect',
            'severity' => 'High',
        ],
        [
            'id' => 'A09:2021',
            'title' => 'Logging and Monitoring Failures',
            'description' => 'Insufficient logging, monitoring, alerting for security events',
            'cwe' => 'CWE-778, CWE-223',
            'nist_function' => 'Detect',
            'severity' => 'High',
        ],
        [
            'id' => 'A10:2021',
            'title' => 'Server-Side Request Forgery (SSRF)',
            'description' => 'Application fetches remote resources without validating user-supplied URLs',
            'cwe' => 'CWE-918',
            'nist_function' => 'Protect',
            'severity' => 'High',
        ],
    ];
}

function getOwaspById($id) {
    $library = getOwaspLibrary();
    foreach ($library as $item) {
        if ($item['id'] === $id) {
            return $item;
        }
    }
    return null;
}

function getOwaspByNistFunction($nistFunction) {
    $library = getOwaspLibrary();
    return array_filter($library, function($item) use ($nistFunction) {
        return $item['nist_function'] === $nistFunction;
    });
}
?>
