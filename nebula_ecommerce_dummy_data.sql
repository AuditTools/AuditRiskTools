-- ====================================================
-- NEBULA E-COMMERCE — COMPLETE DUMMY DATA
-- SRM-Audit GRC & Risk Management System
-- ====================================================
--
-- Organization : Nebula E-Commerce (PT Nebula Digital Commerce)
-- Industry     : Retail
-- Digital Scale: High
-- Condition    : Growing mid-sized e-commerce company
--                Good basic IT practices, but significant gaps in
--                security monitoring, incident response, and disaster recovery.
--
-- INSTRUCTIONS:
--   1. Change @auditor_id and @auditee_id below to YOUR actual user IDs
--      (check your `users` table for the correct IDs)
--   2. Run this script against the `audit` database
--   3. All data is linked via LAST_INSERT_ID() — run sequentially!
--
-- ====================================================

USE audit;

-- ============================================
-- STEP 0: SET YOUR USER IDS HERE
-- ============================================
-- ⚠️ CHANGE THESE to match your actual auditor & auditee user IDs!
SET @auditor_id = 2;      -- <-- Replace with your auditor's user ID
SET @auditee_id = 5;      -- <-- Replace with your auditee's user ID

-- ============================================
-- STEP 1: CREATE ORGANIZATION
-- ============================================
INSERT INTO organizations (
    user_id, organization_name, industry,
    contact_person, contact_email, contact_phone,
    address, number_of_employees, system_type, is_active
) VALUES (
    @auditor_id,
    'PT Nebula Digital Commerce',
    'Retail',
    'Budi Hartono',
    'budi.hartono@nebulacommerce.co.id',
    '+62-21-5550-8899',
    'Jl. Sudirman Kav. 52-53, Senayan, Jakarta Selatan 12190',
    185,
    'E-Commerce Platform',
    1
);
SET @org_id = LAST_INSERT_ID();

-- ============================================
-- STEP 2: CREATE AUDIT SESSION
-- ============================================
-- Exposure Score: Retail(2) × High(3) = 6 → Medium
-- These metrics will be recalculated by the app, but we pre-populate them
INSERT INTO audit_sessions (
    organization_id, session_name, digital_scale, audit_date,
    exposure_score, exposure_level,
    avg_asset_criticality, avg_risk_score,
    final_risk_score, final_risk_level,
    compliance_percentage, nist_maturity_level,
    status, notes
) VALUES (
    @org_id,
    'Nebula E-Commerce Q1 2026 Cybersecurity Audit',
    'High',
    '2026-02-15',
    6.00,       -- Exposure Score: Retail(2) × High(3) = 6
    'Medium',   -- Score 4-6 = Medium
    4.00,       -- Avg Asset Criticality (calculated from 6 assets below)
    13.38,      -- Avg Risk Score (calculated from 8 findings below)
    32.10,      -- Final: (6 × 4.00 × 13.38) / 10 = 32.10
    'Medium',   -- Score 21-40 = Medium
    43.33,      -- Blended compliance (pre-calculated)
    'Developing', -- 41-70% = Developing
    'In Progress',
    'Q1 2026 annual cybersecurity audit for Nebula E-Commerce platform. Focus areas: payment security, access control, and incident response readiness.'
);
SET @audit_id = LAST_INSERT_ID();

-- ============================================
-- STEP 3: ASSIGN AUDITEE TO AUDIT
-- ============================================
INSERT INTO audit_auditees (audit_id, auditee_user_id, assigned_by)
VALUES (@audit_id, @auditee_id, @auditor_id);

-- ============================================
-- STEP 4: REGISTER ASSETS (6 assets)
-- ============================================

-- Asset 1: E-Commerce Web Platform (Critical)
INSERT INTO assets (
    audit_id, asset_name, ip_address, asset_type, description,
    confidentiality, integrity, availability,
    criticality_score, criticality_level,
    owner, department, registered_by
) VALUES (
    @audit_id,
    'Nebula E-Commerce Web Platform',
    '103.28.12.10',
    'Web Application',
    'Main customer-facing e-commerce platform built on Laravel. Handles product catalog, shopping cart, checkout, user accounts, and order tracking. Processes ~15,000 transactions/day.',
    5, 5, 5,
    5.00, 'Critical',
    'Andi Wijaya', 'Engineering', @auditee_id
);
SET @asset1 = LAST_INSERT_ID();

-- Asset 2: Payment Processing Server (Critical)
INSERT INTO assets (
    audit_id, asset_name, ip_address, asset_type, description,
    confidentiality, integrity, availability,
    criticality_score, criticality_level,
    owner, department, registered_by
) VALUES (
    @audit_id,
    'Payment Processing Server',
    '103.28.12.20',
    'Server',
    'Handles credit card processing, e-wallet integration (GoPay, OVO, Dana), and bank transfer verification. Integrates with Midtrans payment gateway. PCI-DSS scope.',
    5, 5, 4,
    4.67, 'Critical',
    'Andi Wijaya', 'Engineering', @auditee_id
);
SET @asset2 = LAST_INSERT_ID();

-- Asset 3: Customer & Order Database (High)
INSERT INTO assets (
    audit_id, asset_name, ip_address, asset_type, description,
    confidentiality, integrity, availability,
    criticality_score, criticality_level,
    owner, department, registered_by
) VALUES (
    @audit_id,
    'Customer & Order Database (MySQL)',
    '103.28.12.30',
    'Database',
    'Primary MySQL 8.0 database storing customer PII (names, emails, addresses, phone numbers), order history, payment references, and product inventory. Contains ~520,000 customer records.',
    5, 4, 4,
    4.33, 'High',
    'Rina Sari', 'Data Engineering', @auditee_id
);
SET @asset3 = LAST_INSERT_ID();

-- Asset 4: Warehouse Management System (High)
INSERT INTO assets (
    audit_id, asset_name, ip_address, asset_type, description,
    confidentiality, integrity, availability,
    criticality_score, criticality_level,
    owner, department, registered_by
) VALUES (
    @audit_id,
    'Warehouse Management System (WMS)',
    '192.168.10.50',
    'Application',
    'Internal web application managing inventory tracking, order fulfillment, shipping label generation, and warehouse staff task assignments. Connected to main database and courier APIs.',
    3, 4, 4,
    3.67, 'High',
    'Dedi Prasetyo', 'Operations', @auditee_id
);
SET @asset4 = LAST_INSERT_ID();

-- Asset 5: Employee Workstations (Medium)
INSERT INTO assets (
    audit_id, asset_name, ip_address, asset_type, description,
    confidentiality, integrity, availability,
    criticality_score, criticality_level,
    owner, department, registered_by
) VALUES (
    @audit_id,
    'Employee Workstations (45 units)',
    '192.168.1.0/24',
    'Endpoint',
    '45 Windows 11 workstations used by office staff across Engineering, Marketing, Finance, and Operations departments. Connected to internal network and cloud services.',
    3, 3, 3,
    3.00, 'Medium',
    'Hendra Gunawan', 'IT Support', @auditee_id
);
SET @asset5 = LAST_INSERT_ID();

-- Asset 6: CDN & Load Balancer (Medium)
INSERT INTO assets (
    audit_id, asset_name, ip_address, asset_type, description,
    confidentiality, integrity, availability,
    criticality_score, criticality_level,
    owner, department, registered_by
) VALUES (
    @audit_id,
    'CDN & Load Balancer (Cloudflare)',
    '104.16.0.0',
    'Network Device',
    'Cloudflare CDN and load balancer distributing traffic across 2 web server instances. Provides DDoS protection, SSL termination, and caching for static assets.',
    2, 3, 5,
    3.33, 'Medium',
    'Andi Wijaya', 'Engineering', @auditee_id
);
SET @asset6 = LAST_INSERT_ID();

-- ============================================
-- STEP 5: CREATE FINDINGS (8 findings)
-- ============================================

-- Finding 1: SQL Injection (CRITICAL) — Open
INSERT INTO findings (
    audit_id, asset_id, title, description,
    owasp_category, cwe_id, likelihood, impact, risk_score, risk_level,
    nist_function, audit_status,
    auditor_notes, recommendation,
    remediation_status, remediation_deadline
) VALUES (
    @audit_id, @asset1,
    'SQL Injection on Product Search',
    'The product search functionality is vulnerable to SQL injection via the "q" parameter. Unsanitized user input is directly concatenated into SQL queries, allowing attackers to extract customer data, modify prices, or delete records. Verified using sqlmap with --dbs flag successfully enumerating all database schemas.',
    'A03:2021 Injection', 'CWE-89',
    4, 5, 20, 'Critical',
    'Protect', 'Non-Compliant',
    'Tested with sqlmap and manual payloads. The search endpoint at /api/products?q= does not use parameterized queries. Time-based blind injection confirmed. Full database schema extractable.',
    'Immediately migrate all database queries to parameterized prepared statements (PDO). Implement input validation and WAF rules to block common injection patterns. Conduct code review of all database interaction points.',
    'Open', '2026-03-01'
);

-- Finding 2: Broken Access Control (HIGH) — Open
INSERT INTO findings (
    audit_id, asset_id, title, description,
    owasp_category, cwe_id, likelihood, impact, risk_score, risk_level,
    nist_function, audit_status,
    auditor_notes, recommendation,
    remediation_status, remediation_deadline
) VALUES (
    @audit_id, @asset1,
    'Broken Access Control on Admin Panel',
    'The admin panel at /admin is accessible by manipulating user role cookies. Regular customer accounts can escalate to admin by modifying the "role" parameter in the JWT payload. No server-side role verification exists for admin API endpoints.',
    'A01:2021 Broken Access Control', 'CWE-284',
    4, 4, 16, 'High',
    'Protect', 'Non-Compliant',
    'Created a regular customer account, intercepted JWT token using Burp Suite, modified role claim to "admin", and successfully accessed /admin/orders, /admin/users, and /admin/settings endpoints.',
    'Implement server-side role verification on all admin endpoints. Use signed JWTs with server-validated claims. Add RBAC middleware that checks user role from the database, not from the token payload alone.',
    'Open', '2026-03-10'
);

-- Finding 3: Weak Payment Encryption (HIGH) — In Progress (management response submitted)
INSERT INTO findings (
    audit_id, asset_id, title, description,
    owasp_category, cwe_id, likelihood, impact, risk_score, risk_level,
    nist_function, audit_status,
    auditor_notes, recommendation,
    remediation_status, remediation_deadline,
    management_response, response_date, responded_by
) VALUES (
    @audit_id, @asset2,
    'Weak Encryption on Payment Data Flow',
    'The payment processing server still accepts TLS 1.0 and TLS 1.1 connections. SSL Labs scan shows Grade B rating. Some internal API calls between the web app and payment server use HTTP (non-encrypted). Credit card tokenization is handled by Midtrans, but session tokens transmitted over weak TLS could be intercepted.',
    'A02:2021 Cryptographic Failures', 'CWE-326',
    3, 5, 15, 'High',
    'Protect', 'Non-Compliant',
    'SSL Labs scan result: Grade B. TLS 1.0 and 1.1 enabled. Internal API endpoint at http://103.28.12.20:8080/api/process uses plain HTTP. While card data itself goes through Midtrans tokenization, session cookies and order data are exposed.',
    'Disable TLS 1.0 and 1.1. Enforce TLS 1.3 minimum for all payment endpoints. Migrate all internal API communication to HTTPS. Enable HSTS headers with minimum 1-year max-age.',
    'In Progress', '2026-03-15',
    'We have initiated the migration to TLS 1.3 across all payment processing endpoints. Our hosting provider has been contacted and the SSL certificate upgrade is scheduled for March 10, 2026. As an interim measure, TLS 1.0 has been disabled and TLS 1.2 minimum is now enforced. Internal API migration to HTTPS is 60% complete.',
    '2026-02-22', @auditee_id
);

-- Finding 4: Server Misconfiguration (MEDIUM) — Resolved
INSERT INTO findings (
    audit_id, asset_id, title, description,
    owasp_category, cwe_id, likelihood, impact, risk_score, risk_level,
    nist_function, audit_status,
    auditor_notes, recommendation,
    remediation_status, remediation_deadline,
    management_response, response_date, responded_by
) VALUES (
    @audit_id, @asset2,
    'Server Security Misconfiguration',
    'Payment server running with default configurations. Server version headers exposed (nginx/1.18.0), directory listing enabled on /assets/, and debug mode left enabled in production showing stack traces with database credentials on error pages.',
    'A05:2021 Security Misconfiguration', 'CWE-16',
    3, 4, 12, 'Medium',
    'Protect', 'Compliant',
    'Initially found: server version header exposed, directory listing on, debug mode enabled in production. After remediation: all issues verified as fixed on Feb 20, 2026. Server version hidden, directory listing disabled, debug mode off. Re-tested and confirmed.',
    'Remove server version headers. Disable directory listing. Turn off debug mode in production. Implement security hardening baseline per CIS benchmarks.',
    'Resolved', '2026-02-28',
    'All server configurations have been updated according to CIS Nginx benchmark. Server version headers removed via server_tokens off directive. Directory listing disabled. Debug mode turned off in .env (APP_DEBUG=false). Configuration verified by IT operations team on Feb 20.',
    '2026-02-20', @auditee_id
);

-- Finding 5: Outdated Third-Party Libraries (MEDIUM) — Open
INSERT INTO findings (
    audit_id, asset_id, title, description,
    owasp_category, cwe_id, likelihood, impact, risk_score, risk_level,
    nist_function, audit_status,
    auditor_notes, recommendation,
    remediation_status, remediation_deadline
) VALUES (
    @audit_id, @asset3,
    'Outdated Third-Party Libraries with Known CVEs',
    'The application uses several outdated dependencies with known vulnerabilities: jQuery 3.3.1 (CVE-2020-23064), Bootstrap 4.1.3 (XSS vulnerability), and the MySQL connector has a known authentication bypass (CVE-2023-21971). Composer audit shows 4 packages with known security advisories.',
    'A06:2021 Vulnerable & Outdated Components', 'CWE-1104',
    3, 4, 12, 'Medium',
    'Identify', 'Non-Compliant',
    'Ran composer audit and npm audit. Found 4 critical and 7 moderate vulnerabilities in backend dependencies. Frontend jQuery version 3.3.1 has known prototype pollution vulnerability. No dependency update schedule exists.',
    'Establish a monthly dependency update schedule. Run composer audit and npm audit as part of CI/CD pipeline. Upgrade jQuery to latest 3.x, Bootstrap to 5.x, and update all packages with security advisories.',
    'Open', '2026-03-20'
);

-- Finding 6: Insufficient Logging & Monitoring (MEDIUM) — Open
INSERT INTO findings (
    audit_id, asset_id, title, description,
    owasp_category, cwe_id, likelihood, impact, risk_score, risk_level,
    nist_function, audit_status,
    auditor_notes, recommendation,
    remediation_status, remediation_deadline
) VALUES (
    @audit_id, @asset4,
    'Insufficient Logging and Security Monitoring',
    'No centralized log management (SIEM) exists. Application logs are stored locally on each server with no aggregation. Security events (failed logins, privilege escalations, API abuse) are not monitored or alerted. Log retention is only 7 days due to disk space constraints. No intrusion detection system (IDS) is deployed.',
    'A09:2021 Security Logging & Monitoring Failures', 'CWE-778',
    4, 3, 12, 'Medium',
    'Detect', 'Non-Compliant',
    'No SIEM or centralized logging. Checked server logs — only nginx access logs retained for 7 days. No application-level security event logging. No alerting configured for suspicious patterns (brute force, unusual API calls). A breach could go undetected for weeks.',
    'Deploy a SIEM solution (e.g., Wazuh open-source or Elastic Security). Centralize all logs with minimum 90-day retention. Configure alerts for: failed login attempts >5, privilege escalation, unusual data export volumes, and after-hours admin access.',
    'Open', '2026-04-01'
);

-- Finding 7: No Incident Response Plan (MEDIUM) — Open
INSERT INTO findings (
    audit_id, asset_id, title, description,
    owasp_category, cwe_id, likelihood, impact, risk_score, risk_level,
    nist_function, audit_status,
    auditor_notes, recommendation,
    remediation_status, remediation_deadline
) VALUES (
    @audit_id, @asset1,
    'No Formal Incident Response Plan',
    'The organization has no documented incident response plan (IRP). When asked about incident handling procedures, staff described ad-hoc responses with no defined roles, escalation paths, or communication templates. No incident response exercises or tabletop drills have been conducted. The last security incident (DDoS attack in November 2025) was handled reactively with no post-incident review.',
    NULL, 'CWE-778',
    3, 4, 12, 'Medium',
    'Respond', 'Non-Compliant',
    'Interviewed the CTO and IT team lead. No written IRP exists. The November 2025 DDoS incident took 6 hours to mitigate because there was no predefined playbook. No post-incident lessons learned document was created. Staff are unsure who to contact during a security incident.',
    'Develop a formal Incident Response Plan based on NIST SP 800-61. Define incident classification levels, assign response team roles (Incident Commander, Technical Lead, Communications Lead), create playbooks for common incident types (DDoS, data breach, ransomware), and conduct quarterly tabletop exercises.',
    'Open', '2026-03-30'
);

-- Finding 8: Database Backup Not Tested (LOW) — Resolved
INSERT INTO findings (
    audit_id, asset_id, title, description,
    owasp_category, cwe_id, likelihood, impact, risk_score, risk_level,
    nist_function, audit_status,
    auditor_notes, recommendation,
    remediation_status, remediation_deadline,
    management_response, response_date, responded_by
) VALUES (
    @audit_id, @asset3,
    'Database Backup Restoration Never Tested',
    'Daily automated backups of the customer database exist via mysqldump cron job, but backup restoration has never been tested. Backup files are stored on the same physical server. No offsite or cloud backup copy exists. Recovery Time Objective (RTO) and Recovery Point Objective (RPO) are undefined.',
    NULL, 'CWE-693',
    2, 4, 8, 'Low',
    'Protect', 'Compliant',
    'Initially found: backups existed but never tested, stored on same server, no offsite copy. After remediation: verified successful restoration test on Feb 20. Offsite backup to Google Cloud Storage now configured. RTO and RPO documented. Re-verified and marked compliant.',
    'Implement 3-2-1 backup strategy (3 copies, 2 different media, 1 offsite). Define RTO and RPO for each critical system. Schedule quarterly backup restoration tests and document results.',
    'Resolved', '2026-02-28',
    'We have established a quarterly backup restoration test schedule. The first successful full restoration test was completed on February 20, 2026 — full database (120GB) recovered within 1.5 hours. Offsite backup now replicates daily to Google Cloud Storage bucket. RTO defined as 2 hours, RPO as 24 hours. Documentation updated in IT runbook.',
    '2026-02-21', @auditee_id
);

-- ============================================
-- STEP 6: NIST CSF CONTROL CHECKLIST (36 controls)
-- ============================================

INSERT INTO control_checklist (audit_id, control_id, status, notes) VALUES
-- ── IDENTIFY (7 controls): 4 Compliant, 2 Partial, 1 Non-Compliant ──
(@audit_id, 'ID.AM-1', 'Compliant',
 'Complete hardware inventory maintained in IT asset register spreadsheet. All 2 web servers, 1 DB server, 1 payment server, network switches, and 45 workstations are documented with serial numbers, location, and assigned users.'),

(@audit_id, 'ID.AM-2', 'Compliant',
 'Software inventory maintained via Snipe-IT. All applications tracked with version numbers and license status. Production stack: Laravel 10, MySQL 8.0, Nginx 1.24, Redis 7.0 documented.'),

(@audit_id, 'ID.AM-5', 'Partially Compliant',
 'Basic data classification exists (Public, Internal, Confidential) but not consistently applied. Customer PII is classified as Confidential, but some internal documents containing sensitive data are not properly labeled. Asset criticality ratings not defined before this audit.'),

(@audit_id, 'ID.GV-1', 'Partially Compliant',
 'An information security policy document exists (created 2023) but has not been updated in 2 years. The policy does not cover cloud services, remote work, or mobile devices which are now part of the business. Not all new employees have acknowledged the policy.'),

(@audit_id, 'ID.GV-4', 'Non-Compliant',
 'No formal cybersecurity risk management framework adopted. Risk decisions are made ad-hoc by the CTO. No risk register exists. No periodic risk assessment schedule. This is the first formal cybersecurity audit the organization has undergone.'),

(@audit_id, 'ID.RA-1', 'Compliant',
 'Vulnerability scans conducted using Nessus quarterly. Most recent scan (January 2026) identified 12 vulnerabilities across infrastructure. OWASP ZAP used for web application scanning. Results are documented and tracked.'),

(@audit_id, 'ID.RA-5', 'Compliant',
 'Risk assessment methodology now established through this audit process. Likelihood × Impact matrix used. Risk scores calculated for all identified vulnerabilities. Risk register created as part of this audit engagement.'),

-- ── PROTECT (14 controls): 6 Compliant, 5 Partial, 3 Non-Compliant ──
(@audit_id, 'PR.AC-1', 'Compliant',
 'User accounts managed through centralized Active Directory. Account creation requires manager approval. Terminated employee accounts are disabled within 24 hours of HR notification. Unique user IDs enforced.'),

(@audit_id, 'PR.AC-3', 'Partially Compliant',
 'VPN (WireGuard) deployed for remote access. However, MFA is not required for VPN connections. 12 employees have remote access, but access logs are not regularly reviewed. Split-tunneling is enabled, which poses risk.'),

(@audit_id, 'PR.AC-4', 'Partially Compliant',
 'RBAC implemented in the e-commerce application with roles: Customer, Staff, Manager, Admin. However, 3 developer accounts still have production database root access. Service accounts use shared credentials. Quarterly access review not conducted.'),

(@audit_id, 'PR.AC-7', 'Compliant',
 'Strong password policy enforced: minimum 10 characters, complexity requirements, 90-day rotation. MFA enabled for admin panel access via Google Authenticator. Account lockout after 5 failed attempts.'),

(@audit_id, 'PR.AT-1', 'Non-Compliant',
 'No formal security awareness training program exists. Employees have not received any cybersecurity training. No phishing simulation exercises conducted. New employee onboarding does not include security orientation. This is a significant gap given the 185-person workforce.'),

(@audit_id, 'PR.DS-1', 'Partially Compliant',
 'MySQL database uses AES-256 encryption for Transparent Data Encryption (TDE) on the main customer database. However, backup files (mysqldump exports) are stored unencrypted. Employee workstation hard drives do not have BitLocker enabled. Some CSV exports of customer data found unencrypted on shared drive.'),

(@audit_id, 'PR.DS-2', 'Compliant',
 'TLS 1.2 enforced on all public-facing endpoints via Cloudflare. HSTS headers present (max-age=31536000). Internal API calls between web app and payment server use HTTPS. Certificate management automated via Let\'s Encrypt.'),

(@audit_id, 'PR.DS-6', 'Non-Compliant',
 'No file integrity monitoring (FIM) in place. No checksums verified on application deployments. Database integrity checks not scheduled. No mechanism to detect unauthorized modification of critical system files or application code.'),

(@audit_id, 'PR.IP-1', 'Partially Compliant',
 'OS-level hardening partially done using CIS benchmarks for Ubuntu 22.04 on servers. However, no documented baseline configuration standard. Database and web server hardening not formally documented. Configuration drift detection not implemented.'),

(@audit_id, 'PR.IP-4', 'Partially Compliant',
 'Daily mysqldump backups configured via cron. However, backup restoration was never tested before this audit (now remediated — see finding). Backup stored on same server initially (now moved to GCS). No backup for application code — relies solely on Git repository.'),

(@audit_id, 'PR.IP-12', 'Compliant',
 'Patch management schedule exists: OS patches monthly, critical patches within 72 hours. Nessus vulnerability scans quarterly trigger patching cycles. Most servers are within 30 days of latest patches.'),

(@audit_id, 'PR.MA-1', 'Compliant',
 'Server maintenance performed monthly during scheduled maintenance windows (Sunday 2-6 AM). Maintenance activities logged in IT ticketing system (Jira). Hardware maintenance contracts active with Dell for servers.'),

(@audit_id, 'PR.PT-1', 'Compliant',
 'Logging enabled on all servers: nginx access/error logs, MySQL slow query logs, Laravel application logs. Log retention policy: 30 days on server, 7 days for debug logs. However, logs are not centralized (see DE.AE-3).'),

(@audit_id, 'PR.PT-3', 'Non-Compliant',
 'Several unnecessary services running on production servers: FTP (port 21), Telnet (port 23), and unused PostgreSQL (port 5432). Default sample pages accessible on web server (/info.php exposing phpinfo). Multiple unused npm packages in production build increasing attack surface.'),

-- ── DETECT (6 controls): 2 Compliant, 3 Partial, 1 Non-Compliant ──
(@audit_id, 'DE.AE-1', 'Partially Compliant',
 'Basic network topology documented. Normal traffic baselines partially established through Cloudflare analytics (HTTP traffic patterns). However, internal network traffic baseline not established. No tool monitoring east-west traffic between servers.'),

(@audit_id, 'DE.AE-3', 'Non-Compliant',
 'No SIEM or centralized log collection system. Logs from web servers, database server, payment server, and application are all stored locally on each machine. No log correlation across sources. Security events cannot be investigated holistically. This is a critical gap.'),

(@audit_id, 'DE.CM-1', 'Partially Compliant',
 'Cloudflare WAF provides basic external monitoring and DDoS protection. However, no IDS/IPS deployed for internal network. No monitoring of internal-to-internal traffic. Firewall (iptables) logs not actively monitored.'),

(@audit_id, 'DE.CM-4', 'Compliant',
 'Sophos Endpoint Protection deployed on all 45 workstations and servers. Real-time scanning enabled. Definitions auto-updated hourly. Weekly full system scans scheduled. Central management console used for monitoring.'),

(@audit_id, 'DE.CM-7', 'Partially Compliant',
 'Basic alerting configured: Cloudflare alerts for DDoS spikes, Sophos alerts for malware detection, and Uptime Robot for availability monitoring. However, no alerting for unauthorized access attempts, privilege escalation, or unusual data transfer patterns.'),

(@audit_id, 'DE.DP-4', 'Compliant',
 'Escalation procedures defined: IT team receives security alerts via Slack and email. CTO is secondary escalation. Contact information documented in IT wiki. Cloudflare and Sophos alerts routed to ops-security Slack channel.'),

-- ── RESPOND (5 controls): 1 Compliant, 1 Partial, 3 Non-Compliant ──
(@audit_id, 'RS.RP-1', 'Non-Compliant',
 'No written incident response plan exists. The November 2025 DDoS attack was handled ad-hoc — CTO manually contacted Cloudflare support after 3 hours of downtime. No predefined roles, playbooks, or escalation procedures for security incidents. Significant gap.'),

(@audit_id, 'RS.CO-2', 'Partially Compliant',
 'Informal incident reporting via Slack exists. Employees can report suspicious activity in #security-alerts channel. However, no formal incident report template. No documented criteria for what constitutes a reportable incident. Customer notification procedures for data breaches not defined.'),

(@audit_id, 'RS.AN-1', 'Non-Compliant',
 'No formal incident investigation procedures. After the November 2025 DDoS attack, no root cause analysis was performed. No forensic investigation capability. No preserved evidence from previous security events. Investigation would rely entirely on limited local logs (7-day retention).'),

(@audit_id, 'RS.MI-1', 'Non-Compliant',
 'No predefined containment procedures. During the November DDoS, the response was to "wait and hope Cloudflare handles it." No procedure for isolating compromised systems, blocking malicious IPs at firewall level, or revoking compromised credentials. No network segmentation to limit lateral movement.'),

(@audit_id, 'RS.MI-2', 'Compliant',
 'While response is ad-hoc, the IT team does perform basic mitigation when incidents are identified: rebooting affected services, blocking IPs, and restoring from backups. The DDoS was eventually mitigated by upgrading Cloudflare plan. Basic capability exists but needs formalization.'),

-- ── RECOVER (4 controls): 1 Compliant, 1 Partial, 2 Non-Compliant ──
(@audit_id, 'RC.RP-1', 'Non-Compliant',
 'No formal disaster recovery plan (DRP) exists. No defined Recovery Time Objective (RTO) or Recovery Point Objective (RPO) for critical systems prior to this audit. If the primary server fails, there is no documented procedure for restoring operations. Single point of failure on database server.'),

(@audit_id, 'RC.IM-1', 'Non-Compliant',
 'No post-incident review process. The November 2025 DDoS attack did not result in any documented lessons learned. No changes were made to security posture after the incident. Recovery plans have never been updated based on actual incident experience.'),

(@audit_id, 'RC.IM-2', 'Partially Compliant',
 'Some informal improvements have been made over time (e.g., Cloudflare plan upgrade after DDoS, stronger passwords after a phishing attempt). However, no formal review cycle for recovery strategies. No annual DRP testing conducted. Changes are reactive, not proactive.'),

(@audit_id, 'RC.CO-3', 'Compliant',
 'Communication channels established for operational issues: Slack for internal team, status page (status.nebulacommerce.co.id) for external customers, and email template for customer notifications. Used effectively during the DDoS incident to communicate with customers about service disruption.');

-- ============================================
-- STEP 7: NOTIFICATIONS (sample)
-- ============================================

INSERT INTO notifications (user_id, audit_id, type, message, is_read) VALUES
(@auditee_id, @audit_id, 'assign_auditee',
 'You have been assigned as auditee for "Nebula E-Commerce Q1 2026 Cybersecurity Audit".', 1),

(@auditee_id, @audit_id, 'new_finding',
 'New Critical finding: "SQL Injection on Product Search" requires your attention.', 0),

(@auditee_id, @audit_id, 'new_finding',
 'New High finding: "Broken Access Control on Admin Panel" requires your attention.', 0),

(@auditee_id, @audit_id, 'new_finding',
 'New High finding: "Weak Encryption on Payment Data Flow" requires your attention.', 1),

(@auditor_id, @audit_id, 'evidence_review',
 'Auditee submitted management response for "Server Security Misconfiguration".', 1),

(@auditor_id, @audit_id, 'evidence_review',
 'Auditee submitted management response for "Weak Encryption on Payment Data Flow".', 0),

(@auditee_id, @audit_id, 'finding_closed',
 'Finding "Server Security Misconfiguration" has been resolved and closed by auditor.', 1),

(@auditee_id, @audit_id, 'finding_closed',
 'Finding "Database Backup Restoration Never Tested" has been resolved and closed by auditor.', 1);

-- ============================================
-- DONE!
-- ============================================
-- Summary:
--   Organization : PT Nebula Digital Commerce (Retail, High digital scale)
--   Exposure     : 6 (Medium)
--   Assets       : 6 (2 Critical, 2 High, 2 Medium)
--   Findings     : 8 (1 Critical, 2 High, 4 Medium, 1 Low)
--                  Status: 4 Open, 1 In Progress, 2 Resolved
--   Checklist    : 36 controls (14 Compliant, 12 Partial, 10 Non-Compliant)
--   Compliance   : ~43% (Developing maturity)
--   Final Risk   : 32.10 (Medium)
--   Opinion      : 🔴 Needs Immediate Action (compliance <60% + open Critical finding)
--
-- The metrics will be recalculated automatically by the app when you
-- visit the report page (updateAuditMetrics runs on page load).
-- ============================================
