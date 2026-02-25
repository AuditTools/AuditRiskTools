<?php
/**
 * SRM-Audit - NIST Cybersecurity Framework Control Checklist
 * Predefined controls for each NIST CSF function mapped to finding audit
 */

function getNistControlsChecklist() {
    return [
        'Identify' => [
            ['id' => 'ID-AM-1', 'title' => 'Asset Inventory', 'description' => 'Hardware, software and data assets are inventoried', 'category' => 'Asset Management'],
            ['id' => 'ID-AM-2', 'title' => 'Inventory Software', 'description' => 'Software licenses and registered vendors are managed and reviewed', 'category' => 'Asset Management'],
            ['id' => 'ID-RA-1', 'title' => 'Risk Assessment', 'description' => 'Organization-wide risk assessment conducted', 'category' => 'Risk Assessment'],
            ['id' => 'ID-RA-2', 'title' => 'Threat Modeling', 'description' => 'Threat modeling process established and documented', 'category' => 'Risk Assessment'],
            ['id' => 'ID-GV-1', 'title' => 'Governance', 'description' => 'Legal, regulatory, operational and industry-specific requirements are documented', 'category' => 'Governance'],
            ['id' => 'ID-GV-2', 'title' => 'Policies', 'description' => 'Privacy, information security policies are documented, communicated and reviewed', 'category' => 'Governance'],
        ],
        'Protect' => [
            ['id' => 'PR-AC-1', 'title' => 'Physical Access', 'description' => 'Physical access is controlled and monitored', 'category' => 'Access Control'],
            ['id' => 'PR-AC-2', 'title' => 'Logical Access', 'description' => 'Logical and physical access controls are deployed and maintained', 'category' => 'Access Control'],
            ['id' => 'PR-AT-1', 'title' => 'Security Training', 'description' => 'Organization conducts security awareness and technical training', 'category' => 'Training'],
            ['id' => 'PR-DS-1', 'title' => 'Data Classification', 'description' => 'Sensitive information is identified and managed per retention policy', 'category' => 'Data Security'],
            ['id' => 'PR-DS-2', 'title' => 'Encryption', 'description' => 'Data in transit and at rest are encrypted appropriately', 'category' => 'Data Security'],
            ['id' => 'PR-PT-1', 'title' => 'Maintenance', 'description' => 'Maintenance and repairs of systems are performed and logged', 'category' => 'Protective Processes'],
            ['id' => 'PR-DE-1', 'title' => 'Secure SDLC', 'description' => 'Software development practices incorporate security requirements', 'category' => 'Secure Software Development'],
        ],
        'Detect' => [
            ['id' => 'DE-AE-1', 'title' => 'Anomaly Detection', 'description' => 'Network traffic and behavior patterns are monitored for anomalies', 'category' => 'Anomaly Detection'],
            ['id' => 'DE-CM-1', 'title' => 'Monitoring', 'description' => 'System and network monitoring is implemented and logs are retained', 'category' => 'Continuous Monitoring'],
            ['id' => 'DE-DP-1', 'title' => 'Detection Process', 'description' => 'Roles and responsibilities for detection and analysis are defined', 'category' => 'Detection Process'],
            ['id' => 'DE-AE-2', 'title' => 'Intrusion Detection', 'description' => 'Intrusion detection and prevention tools are deployed and maintained', 'category' => 'Anomaly Detection'],
        ],
        'Respond' => [
            ['id' => 'RS-RP-1', 'title' => 'Response Planning', 'description' => 'Incident response plan and procedures are documented and tested', 'category' => 'Response Planning'],
            ['id' => 'RS-CO-1', 'title' => 'Communications', 'description' => 'Incident communications and notifications are coordinated', 'category' => 'Communications'],
            ['id' => 'RS-AN-1', 'title' => 'Analysis', 'description' => 'Incidents are analyzed to understand scope and cause', 'category' => 'Analysis'],
            ['id' => 'RS-MI-1', 'title' => 'Mitigation', 'description' => 'Incident activities are mitigated to achieve objectives', 'category' => 'Mitigation'],
        ],
        'Recover' => [
            ['id' => 'RC-RP-1', 'title' => 'Recovery Planning', 'description' => 'Recovery plan and procedures are documented and tested', 'category' => 'Recovery Planning'],
            ['id' => 'RC-IM-1', 'title' => 'Improvement', 'description' => 'Recovery gains knowledge to improve processes', 'category' => 'Improvement'],
            ['id' => 'RC-CO-1', 'title' => 'Communications', 'description' => 'Recovery stakeholders and communications plans are defined', 'category' => 'Communications'],
        ],
    ];
}

function getNistControlsByFunction($function) {
    $controls = getNistControlsChecklist();
    return $controls[$function] ?? [];
}

function getAllNistControls() {
    $checklist = getNistControlsChecklist();
    $all = [];
    foreach ($checklist as $function => $items) {
        foreach ($items as $item) {
            $item['nist_function'] = $function;
            $all[] = $item;
        }
    }
    return $all;
}
?>
