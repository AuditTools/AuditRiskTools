<?php
/**
 * SRM-Audit - NIST Cybersecurity Framework (CSF) Control Library
 * Predefined security controls organized by the 5 NIST CSF Functions:
 *   Identify → Protect → Detect → Respond → Recover
 *
 * Each control has:
 *   - control_id: unique reference code
 *   - title: short control name
 *   - description: what the control requires
 *   - guidance: how to verify compliance
 */

function getNistCsfControls() {
    return [

        // ============================================================
        // IDENTIFY (ID) — Understand the organization's cybersecurity risk
        // ============================================================
        [
            'control_id' => 'ID.AM-1',
            'function' => 'Identify',
            'category' => 'Asset Management',
            'title' => 'Physical Device Inventory',
            'description' => 'Physical devices and systems within the organization are inventoried.',
            'guidance' => 'Verify a complete hardware inventory exists (servers, workstations, network devices). Check for automated discovery tools or manual register.',
        ],
        [
            'control_id' => 'ID.AM-2',
            'function' => 'Identify',
            'category' => 'Asset Management',
            'title' => 'Software Platform Inventory',
            'description' => 'Software platforms and applications within the organization are inventoried.',
            'guidance' => 'Verify a software inventory list exists with version numbers. Check for license management and approved software list.',
        ],
        [
            'control_id' => 'ID.AM-5',
            'function' => 'Identify',
            'category' => 'Asset Management',
            'title' => 'Resource Classification & Prioritization',
            'description' => 'Resources (hardware, devices, data, software) are prioritized based on classification, criticality, and business value.',
            'guidance' => 'Verify data classification policy exists (Public, Internal, Confidential, Restricted). Check that assets have assigned criticality ratings.',
        ],
        [
            'control_id' => 'ID.GV-1',
            'function' => 'Identify',
            'category' => 'Governance',
            'title' => 'Information Security Policy',
            'description' => 'Organizational cybersecurity policy is established and communicated.',
            'guidance' => 'Verify a written information security policy document exists. Check that it is approved by management and communicated to all staff.',
        ],
        [
            'control_id' => 'ID.GV-4',
            'function' => 'Identify',
            'category' => 'Governance',
            'title' => 'Governance & Risk Management Process',
            'description' => 'Governance and risk management processes address cybersecurity risks.',
            'guidance' => 'Verify risk management framework is documented. Check that risk assessments are performed periodically and risks are tracked in a register.',
        ],
        [
            'control_id' => 'ID.RA-1',
            'function' => 'Identify',
            'category' => 'Risk Assessment',
            'title' => 'Vulnerability Identification',
            'description' => 'Asset vulnerabilities are identified and documented.',
            'guidance' => 'Verify vulnerability scanning is performed regularly. Check for documented vulnerability assessment reports and remediation tracking.',
        ],
        [
            'control_id' => 'ID.RA-5',
            'function' => 'Identify',
            'category' => 'Risk Assessment',
            'title' => 'Risk Assessment Process',
            'description' => 'Threats, vulnerabilities, likelihoods, and impacts are used to determine risk.',
            'guidance' => 'Verify a formal risk assessment methodology is used. Check that risk = likelihood × impact is calculated and documented.',
        ],

        // ============================================================
        // PROTECT (PR) — Implement safeguards
        // ============================================================
        [
            'control_id' => 'PR.AC-1',
            'function' => 'Protect',
            'category' => 'Access Control',
            'title' => 'Identity & Credential Management',
            'description' => 'Identities and credentials are issued, managed, verified, revoked, and audited.',
            'guidance' => 'Verify user account lifecycle process exists (creation, modification, revocation). Check for unique user IDs and periodic access reviews.',
        ],
        [
            'control_id' => 'PR.AC-3',
            'function' => 'Protect',
            'category' => 'Access Control',
            'title' => 'Remote Access Management',
            'description' => 'Remote access is managed.',
            'guidance' => 'Verify VPN or secure remote access solution is used. Check that remote access requires MFA and is logged.',
        ],
        [
            'control_id' => 'PR.AC-4',
            'function' => 'Protect',
            'category' => 'Access Control',
            'title' => 'Access Permissions & Least Privilege',
            'description' => 'Access permissions and authorizations are managed using the principle of least privilege and separation of duties.',
            'guidance' => 'Verify role-based access control (RBAC) is implemented. Check that users have minimum necessary permissions.',
        ],
        [
            'control_id' => 'PR.AC-7',
            'function' => 'Protect',
            'category' => 'Access Control',
            'title' => 'Authentication Mechanisms',
            'description' => 'Users, devices, and other assets are authenticated commensurate with risk.',
            'guidance' => 'Verify strong password policy (min 8 chars, complexity). Check for multi-factor authentication on critical systems and admin accounts.',
        ],
        [
            'control_id' => 'PR.AT-1',
            'function' => 'Protect',
            'category' => 'Awareness & Training',
            'title' => 'Security Awareness Training',
            'description' => 'All users are informed and trained.',
            'guidance' => 'Verify security awareness training program exists. Check training records and that training is conducted at least annually.',
        ],
        [
            'control_id' => 'PR.DS-1',
            'function' => 'Protect',
            'category' => 'Data Security',
            'title' => 'Data-at-Rest Protection',
            'description' => 'Data-at-rest is protected.',
            'guidance' => 'Verify encryption is used for sensitive data stored in databases and file systems. Check encryption algorithms (AES-256 minimum).',
        ],
        [
            'control_id' => 'PR.DS-2',
            'function' => 'Protect',
            'category' => 'Data Security',
            'title' => 'Data-in-Transit Protection',
            'description' => 'Data-in-transit is protected.',
            'guidance' => 'Verify TLS/HTTPS is enforced on all web traffic. Check that TLS 1.2+ is used and older protocols are disabled.',
        ],
        [
            'control_id' => 'PR.DS-6',
            'function' => 'Protect',
            'category' => 'Data Security',
            'title' => 'Integrity Checking',
            'description' => 'Integrity checking mechanisms are used to verify software, firmware, and information integrity.',
            'guidance' => 'Verify file integrity monitoring is in place. Check for checksums on critical system files and database integrity checks.',
        ],
        [
            'control_id' => 'PR.IP-1',
            'function' => 'Protect',
            'category' => 'Protective Processes',
            'title' => 'Baseline Configuration',
            'description' => 'A baseline configuration of systems is created and maintained incorporating security principles.',
            'guidance' => 'Verify baseline/hardening standards exist for OS, database, and web servers. Check that configurations are documented and versioned.',
        ],
        [
            'control_id' => 'PR.IP-4',
            'function' => 'Protect',
            'category' => 'Protective Processes',
            'title' => 'Backup Policy & Procedures',
            'description' => 'Backups of information are conducted, maintained, and tested.',
            'guidance' => 'Verify backup policy exists with defined frequency (daily/weekly). Check that backups are tested for restoration periodically.',
        ],
        [
            'control_id' => 'PR.IP-12',
            'function' => 'Protect',
            'category' => 'Protective Processes',
            'title' => 'Vulnerability Management Plan',
            'description' => 'A vulnerability management plan is developed and implemented.',
            'guidance' => 'Verify patch management schedule exists. Check that critical vulnerabilities are patched within defined SLA (e.g., 48 hours for critical).',
        ],
        [
            'control_id' => 'PR.MA-1',
            'function' => 'Protect',
            'category' => 'Maintenance',
            'title' => 'System Maintenance & Patching',
            'description' => 'Maintenance and repair of organizational assets is performed and logged.',
            'guidance' => 'Verify a patch management process exists. Check that servers and software are kept up-to-date with security patches.',
        ],
        [
            'control_id' => 'PR.PT-1',
            'function' => 'Protect',
            'category' => 'Protective Technology',
            'title' => 'Audit/Log Records Policy',
            'description' => 'Audit/log records are determined, documented, implemented, and reviewed.',
            'guidance' => 'Verify logging policy defines what events to log and retention period. Check that logs are reviewed regularly.',
        ],
        [
            'control_id' => 'PR.PT-3',
            'function' => 'Protect',
            'category' => 'Protective Technology',
            'title' => 'Least Functionality Principle',
            'description' => 'The principle of least functionality is incorporated by configuring systems to provide only essential capabilities.',
            'guidance' => 'Verify unnecessary services and ports are disabled. Check that only required software is installed on servers.',
        ],

        // ============================================================
        // DETECT (DE) — Identify cybersecurity events
        // ============================================================
        [
            'control_id' => 'DE.AE-1',
            'function' => 'Detect',
            'category' => 'Anomalies & Events',
            'title' => 'Network Operations Baseline',
            'description' => 'A baseline of network operations and expected data flows is established and managed.',
            'guidance' => 'Verify network baseline documentation exists. Check for network monitoring tools that can detect anomalies from normal patterns.',
        ],
        [
            'control_id' => 'DE.AE-3',
            'function' => 'Detect',
            'category' => 'Anomalies & Events',
            'title' => 'Event Data Collection & Correlation',
            'description' => 'Event data are collected and correlated from multiple sources and sensors.',
            'guidance' => 'Verify centralized log collection (SIEM or syslog). Check that logs from multiple sources are correlated for incident detection.',
        ],
        [
            'control_id' => 'DE.CM-1',
            'function' => 'Detect',
            'category' => 'Continuous Monitoring',
            'title' => 'Network Monitoring',
            'description' => 'The network is monitored to detect potential cybersecurity events.',
            'guidance' => 'Verify network monitoring tools are in place (IDS/IPS, firewall logs). Check for real-time alerting on suspicious activity.',
        ],
        [
            'control_id' => 'DE.CM-4',
            'function' => 'Detect',
            'category' => 'Continuous Monitoring',
            'title' => 'Malicious Code Detection',
            'description' => 'Malicious code is detected.',
            'guidance' => 'Verify antivirus/anti-malware is installed on all endpoints. Check that definitions are updated automatically and scans run regularly.',
        ],
        [
            'control_id' => 'DE.CM-7',
            'function' => 'Detect',
            'category' => 'Continuous Monitoring',
            'title' => 'Unauthorized Activity Monitoring',
            'description' => 'Monitoring for unauthorized personnel, connections, devices, and software is performed.',
            'guidance' => 'Verify intrusion detection capability exists. Check for alerts on unauthorized access attempts, rogue devices, or unapproved software.',
        ],
        [
            'control_id' => 'DE.DP-4',
            'function' => 'Detect',
            'category' => 'Detection Processes',
            'title' => 'Event Detection Communication',
            'description' => 'Event detection information is communicated to appropriate parties.',
            'guidance' => 'Verify security event notification procedures exist. Check that escalation paths are defined and stakeholders are notified promptly.',
        ],

        // ============================================================
        // RESPOND (RS) — Take action on detected events
        // ============================================================
        [
            'control_id' => 'RS.RP-1',
            'function' => 'Respond',
            'category' => 'Response Planning',
            'title' => 'Incident Response Plan',
            'description' => 'Response plan is executed during or after an incident.',
            'guidance' => 'Verify a written incident response plan exists. Check that it defines roles, responsibilities, and procedures for different incident types.',
        ],
        [
            'control_id' => 'RS.CO-2',
            'function' => 'Respond',
            'category' => 'Communications',
            'title' => 'Incident Reporting',
            'description' => 'Incidents are reported consistent with established criteria.',
            'guidance' => 'Verify incident reporting procedures exist. Check for incident report templates and that reporting channels are known to all staff.',
        ],
        [
            'control_id' => 'RS.AN-1',
            'function' => 'Respond',
            'category' => 'Analysis',
            'title' => 'Incident Investigation & Analysis',
            'description' => 'Notifications from detection systems are investigated.',
            'guidance' => 'Verify incident investigation procedures exist. Check that security alerts are triaged, investigated, and documented.',
        ],
        [
            'control_id' => 'RS.MI-1',
            'function' => 'Respond',
            'category' => 'Mitigation',
            'title' => 'Incident Containment',
            'description' => 'Incidents are contained.',
            'guidance' => 'Verify incident containment procedures exist. Check for defined containment strategies (isolation, blocking, shutdown procedures).',
        ],
        [
            'control_id' => 'RS.MI-2',
            'function' => 'Respond',
            'category' => 'Mitigation',
            'title' => 'Incident Mitigation',
            'description' => 'Incidents are mitigated.',
            'guidance' => 'Verify mitigation procedures exist for common incident types. Check that lessons learned are documented and applied.',
        ],

        // ============================================================
        // RECOVER (RC) — Restore capabilities impaired by incidents
        // ============================================================
        [
            'control_id' => 'RC.RP-1',
            'function' => 'Recover',
            'category' => 'Recovery Planning',
            'title' => 'Disaster Recovery Plan',
            'description' => 'Recovery plan is executed during or after a cybersecurity incident.',
            'guidance' => 'Verify a disaster recovery plan (DRP) exists. Check that it includes recovery time objectives (RTO) and recovery point objectives (RPO).',
        ],
        [
            'control_id' => 'RC.IM-1',
            'function' => 'Recover',
            'category' => 'Improvements',
            'title' => 'Post-Incident Lessons Learned',
            'description' => 'Recovery plans incorporate lessons learned.',
            'guidance' => 'Verify post-incident reviews are conducted. Check that findings are documented and recovery plans are updated accordingly.',
        ],
        [
            'control_id' => 'RC.IM-2',
            'function' => 'Recover',
            'category' => 'Improvements',
            'title' => 'Recovery Strategy Updates',
            'description' => 'Recovery strategies are updated.',
            'guidance' => 'Verify recovery plans are reviewed and tested at least annually. Check for documented test results and plan updates.',
        ],
        [
            'control_id' => 'RC.CO-3',
            'function' => 'Recover',
            'category' => 'Communications',
            'title' => 'Recovery Communication',
            'description' => 'Recovery activities are communicated to internal and external stakeholders.',
            'guidance' => 'Verify communication plan for recovery exists. Check that stakeholders are informed of recovery status and timelines.',
        ],
    ];
}

/**
 * Get controls grouped by NIST CSF Function
 */
function getNistControlsByFunction() {
    $controls = getNistCsfControls();
    $grouped = [];
    foreach ($controls as $ctrl) {
        $grouped[$ctrl['function']][] = $ctrl;
    }
    return $grouped;
}

/**
 * Get the count of controls per function
 */
function getNistControlCounts() {
    $grouped = getNistControlsByFunction();
    $counts = [];
    foreach ($grouped as $func => $ctrls) {
        $counts[$func] = count($ctrls);
    }
    return $counts;
}

/**
 * Get total number of controls
 */
function getNistControlTotal() {
    return count(getNistCsfControls());
}
