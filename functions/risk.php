<?php
/**
 * SRM-Audit - Risk Calculation Logic (Hybrid Version)
 * Combines pure mathematical formulas (defendable for academic presentation) 
 * with efficient auto-update database execution.
 */

// 1. EXPOSURE LOGIC (Based on Ordinal Concept 1-3)
[cite_start]// Called ONLY when creating a new Audit Session [cite: 32-50].
function calculateExposureScore($industry, $digital_scale) {
    [cite_start]// Follows the simple design (High=3, Med=2, Low=1) [cite: 39-48, 260-291]
    $base = [
        'Finance' => 3, 'Healthcare' => 3, 'Education' => 2,
        'Retail' => 2, 'Technology' => 2, 'Other' => 1
    ];
    $scale = ['Low' => 1, 'Medium' => 2, 'High' => 3];

    $baseline = $base[$industry] ?? 1; // Default to 'Other' (1)
    $weight = $scale[$digital_scale] ?? 2; // Default to 'Medium' (2)
    
    // Exposure Score = Industry Baseline * Digital Scale Weight
    $score = $baseline * $weight;

    [cite_start]// Classification [cite: 287-289]
    if ($score <= 3) $level = "Low";
    elseif ($score <= 6) $level = "Medium";
    else $level = "High";

    return ['score' => $score, 'level' => $level];
}

// 2. AUTO-UPDATE METRICS FUNCTION (Core System Calculation)
// Call this function EVERY TIME a user adds/updates/deletes an Asset or Finding.
function updateAuditMetrics($pdo, $auditId) {
    [cite_start]// A. Retrieve Exposure Score (Stored during audit creation) [cite: 198-208]
    $stmt = $pdo->prepare("SELECT exposure_score FROM audit_sessions WHERE id = ?");
    $stmt->execute([$auditId]);
    $audit = $stmt->fetch(PDO::FETCH_ASSOC);
    $exposure_score = (float)($audit['exposure_score'] ?? 0);

    [cite_start]// B. Calculate Average Asset Criticality (Directly from database) [cite: 323-325]
    $stmt = $pdo->prepare("SELECT AVG(criticality_score) AS avg_crit FROM assets WHERE audit_id = ?");
    $stmt->execute([$auditId]);
    $avg_asset_criticality = (float)($stmt->fetch(PDO::FETCH_ASSOC)['avg_crit'] ?? 0);

    [cite_start]// C. Calculate Average Risk Score [cite: 326-328]
    $stmt = $pdo->prepare("SELECT AVG(risk_score) AS avg_risk FROM findings WHERE audit_id = ?");
    $stmt->execute([$auditId]);
    $avg_risk_score = (float)($stmt->fetch(PDO::FETCH_ASSOC)['avg_risk'] ?? 0);

    [cite_start]// D. Calculate Final Risk Score (Formula: Exposure * AvgCrit * AvgRisk / 10) [cite: 97-99, 298-304]
    $final_risk_score = 0;
    if ($exposure_score > 0 && $avg_asset_criticality > 0 && $avg_risk_score > 0) {
        $final_risk_score = ($exposure_score * $avg_asset_criticality * $avg_risk_score) / 10;
    }
    $final_risk_score = round($final_risk_score, 2);

    [cite_start]// E. Classify Final Risk Level [cite: 100-104, 305-310]
    if ($final_risk_score > 70) $final_risk_level = 'Critical';
    elseif ($final_risk_score >= 41) $final_risk_level = 'High';
    elseif ($final_risk_score >= 21) $final_risk_level = 'Medium';
    else $final_risk_level = 'Low';

    [cite_start]// F. Save to database (Per PDF Schema, only stores Final Score & Level) [cite: 203-204]
    $updateStmt = $pdo->prepare("
        UPDATE audit_sessions 
        SET final_risk_score = ?, final_risk_level = ? 
        WHERE id = ?
    ");
    $updateStmt->execute([$final_risk_score, $final_risk_level, $auditId]);

    // G. Return data for Dashboard rendering
    return [
        'avg_asset_criticality' => round($avg_asset_criticality, 2),
        'avg_risk_score' => round($avg_risk_score, 2),
        'final_risk_score' => $final_risk_score,
        'final_risk_level' => $final_risk_level
    ];
}

[cite_start]// 3. HELPER: Calculate Asset Criticality [cite: 56-57, 292-293]
function calculateAssetCriticality($c, $i, $a) {
    return round(($c + $i + $a) / 3, 2);
}

[cite_start]// 4. HELPER: Calculate Compliance & Maturity Indicator [cite: 89-91, 117-126, 339-343]
function getComplianceAndMaturity($pdo, $auditId) {
    // Per PDF formula: Total Compliant / Total Findings * 100
    $stmt = $pdo->prepare("
        SELECT 
            SUM(CASE WHEN audit_status='Compliant' THEN 1 ELSE 0 END) as compliant_count,
            COUNT(*) as total
        FROM findings WHERE audit_id = ?
    ");
    $stmt->execute([$auditId]);
    $res = $stmt->fetch(PDO::FETCH_ASSOC);

    $total = (int)$res['total'];
    $compliant = (int)$res['compliant_count'];
    
    // If there are no findings yet, assume 100% compliant
    $percentage = ($total > 0) ? round(($compliant / $total) * 100, 2) : 100.0;

    [cite_start]// Maturity Classification per PDF [cite: 119-126]
    if ($percentage <= 40) $maturity = 'Initial';
    elseif ($percentage <= 70) $maturity = 'Developing';
    elseif ($percentage <= 90) $maturity = 'Managed';
    else $maturity = 'Optimized';

    return ['percentage' => $percentage, 'maturity' => $maturity];
}
?>