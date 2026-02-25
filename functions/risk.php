<?php
/**
 * SRM-Audit - Risk Calculation Logic (Hybrid Version)
 * Combines pure mathematical formulas (defendable for academic presentation) 
 * with efficient auto-update database execution.
 */

// 1. EXPOSURE LOGIC (Based on Ordinal Concept 1-3)
// Called ONLY when creating a new Audit Session .
function calculateExposureScore($industry, $digital_scale) {
    // Follows the simple design (High=3, Med=2, Low=1) 
    $base = [
        'Finance' => 3, 'Healthcare' => 3, 'Education' => 2,
        'Retail' => 2, 'Technology' => 2, 'Other' => 1
    ];
    $scale = ['Low' => 1, 'Medium' => 2, 'High' => 3];

    $baseline = $base[$industry] ?? 1; // Default to 'Other' (1)
    $weight = $scale[$digital_scale] ?? 2; // Default to 'Medium' (2)
    
    // Exposure Score = Industry Baseline * Digital Scale Weight
    $score = $baseline * $weight;

    // Classification 
    if ($score <= 3) $level = "Low";
    elseif ($score <= 6) $level = "Medium";
    else $level = "High";

    return ['score' => $score, 'level' => $level];
}

// 2. AUTO-UPDATE METRICS FUNCTION (Core System Calculation)
// Call this function EVERY TIME a user adds/updates/deletes an Asset or Finding.
function updateAuditMetrics($pdo, $auditId) {
    // A. Retrieve Exposure Score (Stored during audit creation) 
    $stmt = $pdo->prepare("SELECT exposure_score FROM audit_sessions WHERE id = ?");
    $stmt->execute([$auditId]);
    $audit = $stmt->fetch(PDO::FETCH_ASSOC);
    $exposure_score = (float)($audit['exposure_score'] ?? 0);

    // B. Calculate Average Asset Criticality (Directly from database) 
    $stmt = $pdo->prepare("SELECT AVG(criticality_score) AS avg_crit FROM assets WHERE audit_id = ?");
    $stmt->execute([$auditId]);
    $avg_asset_criticality = (float)($stmt->fetch(PDO::FETCH_ASSOC)['avg_crit'] ?? 0);

    // C. Calculate Average Risk Score 
    $stmt = $pdo->prepare("SELECT AVG(risk_score) AS avg_risk FROM findings WHERE audit_id = ?");
    $stmt->execute([$auditId]);
    $avg_risk_score = (float)($stmt->fetch(PDO::FETCH_ASSOC)['avg_risk'] ?? 0);

    // D. Calculate Final Risk Score (Formula: Exposure * AvgCrit * AvgRisk / 10) 
    $final_risk_score = 0;
    if ($exposure_score > 0 && $avg_asset_criticality > 0 && $avg_risk_score > 0) {
        $final_risk_score = ($exposure_score * $avg_asset_criticality * $avg_risk_score) / 10;
    }
    $final_risk_score = round($final_risk_score, 2);

    // E. Classify Final Risk Level 
    if ($final_risk_score > 70) $final_risk_level = 'Critical';
    elseif ($final_risk_score >= 41) $final_risk_level = 'High';
    elseif ($final_risk_score >= 21) $final_risk_level = 'Medium';
    else $final_risk_level = 'Low';

    // F. Calculate Compliance & Maturity (auto-update) 
    $compliance = getComplianceAndMaturity($pdo, $auditId);

    // G. Save to database (Final Score, Level, Compliance, Maturity) 
    $updateStmt = $pdo->prepare("
        UPDATE audit_sessions 
        SET final_risk_score = ?, final_risk_level = ?,
            compliance_percentage = ?, nist_maturity_level = ?
        WHERE id = ?
    ");
    $updateStmt->execute([
        $final_risk_score, $final_risk_level,
        $compliance['percentage'], $compliance['maturity'],
        $auditId
    ]);
    
    // H. Return data for Dashboard rendering
    return [
        'avg_asset_criticality' => round($avg_asset_criticality, 2),
        'avg_risk_score' => round($avg_risk_score, 2),
        'final_risk_score' => $final_risk_score,
        'final_risk_level' => $final_risk_level,
        'compliance_percentage' => $compliance['percentage'],
        'nist_maturity_level' => $compliance['maturity']
    ];
}

// 3. HELPER: Calculate Asset Criticality 
function calculateAssetCriticality($c, $i, $a) {
    return round(($c + $i + $a) / 3, 2);
}

// 3b. HELPER: Calculate Criticality Level from score
function calculateCriticalityLevel($score) {
    if ($score >= 4.5) return 'Critical';
    if ($score >= 3.5) return 'High';
    if ($score >= 2.5) return 'Medium';
    return 'Low';
}

// 4. HELPER: Calculate Compliance & Maturity Indicator 
function getComplianceAndMaturity($pdo, $auditId) {
    // --- Source 1: Findings-based compliance ---
    $stmt = $pdo->prepare("
        SELECT 
            SUM(CASE WHEN audit_status='Compliant' THEN 1 ELSE 0 END) as compliant_count,
            COUNT(*) as total
        FROM findings WHERE audit_id = ?
    ");
    $stmt->execute([$auditId]);
    $res = $stmt->fetch(PDO::FETCH_ASSOC);

    $findingsTotal     = (int)$res['total'];
    $findingsCompliant = (int)$res['compliant_count'];

    // --- Source 2: NIST CSF Control Checklist compliance ---
    $checklistPct = null; // null = no checklist data yet
    $stmtCL = $pdo->prepare("
        SELECT status, COUNT(*) as cnt 
        FROM control_checklist 
        WHERE audit_id = ? 
        GROUP BY status
    ");
    $stmtCL->execute([$auditId]);
    $clRows = $stmtCL->fetchAll(PDO::FETCH_KEY_PAIR);

    $clTotal = array_sum($clRows);
    if ($clTotal > 0) {
        $clCompliant = (int)($clRows['Compliant'] ?? 0);
        $clPartial   = (int)($clRows['Partially Compliant'] ?? 0);
        $clNA        = (int)($clRows['Not Applicable'] ?? 0);
        $clApplicable = $clTotal - $clNA;
        if ($clApplicable > 0) {
            $checklistPct = round((($clCompliant + $clPartial * 0.5) / $clApplicable) * 100, 2);
        }
    }

    // --- Blend: weighted average if both exist, otherwise use what's available ---
    if ($findingsTotal > 0 && $checklistPct !== null) {
        $findingsPct = round(($findingsCompliant / $findingsTotal) * 100, 2);
        // 40% findings + 60% checklist (checklist carries more weight as it covers full NIST)
        $percentage = round($findingsPct * 0.4 + $checklistPct * 0.6, 2);
    } elseif ($checklistPct !== null) {
        $percentage = $checklistPct;
    } elseif ($findingsTotal > 0) {
        $percentage = round(($findingsCompliant / $findingsTotal) * 100, 2);
    } else {
        $percentage = 100.0;
    }

    // Maturity Classification per PDF 
    if ($percentage <= 40) $maturity = 'Initial';
    elseif ($percentage <= 70) $maturity = 'Developing';
    elseif ($percentage <= 90) $maturity = 'Managed';
    else $maturity = 'Optimized';

    return ['percentage' => $percentage, 'maturity' => $maturity];
}

// 5. HELPER: Calculate Audit Opinion (P0)
// Formula (finalized):
//   Secure      → compliance ≥85% AND no open High/Critical findings
//   Acceptable  → compliance 60–84% OR ≤2 open High findings (no Critical)
//   Immediate   → compliance <60% OR any open Critical finding
function calculateAuditOpinion($pdo, $auditId) {
    $stmt = $pdo->prepare("SELECT compliance_percentage FROM audit_sessions WHERE id = ?");
    $stmt->execute([$auditId]);
    $audit = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$audit) {
        return ['opinion' => 'Unknown', 'compliance' => 0, 'open_critical' => 0, 'open_high' => 0];
    }
    
    $compliance = (float)$audit['compliance_percentage'];
    
    // Count open (non-resolved) High and Critical findings
    $stmt = $pdo->prepare("SELECT 
        SUM(CASE WHEN risk_level = 'Critical' AND remediation_status NOT IN ('Resolved','Accepted Risk') THEN 1 ELSE 0 END) AS open_critical,
        SUM(CASE WHEN risk_level = 'High' AND remediation_status NOT IN ('Resolved','Accepted Risk') THEN 1 ELSE 0 END) AS open_high
        FROM findings WHERE audit_id = ?");
    $stmt->execute([$auditId]);
    $counts = $stmt->fetch(PDO::FETCH_ASSOC);
    $openCritical = (int)($counts['open_critical'] ?? 0);
    $openHigh = (int)($counts['open_high'] ?? 0);
    
    // Determine opinion
    if ($openCritical > 0 || $compliance < 60) {
        $opinion = 'Immediate Action Required';
    } elseif ($compliance >= 85 && $openHigh === 0) {
        $opinion = 'Secure';
    } else {
        // 60-84% range OR ≤2 High open
        $opinion = 'Acceptable Risk';
    }
    
    return [
        'opinion' => $opinion,
        'compliance' => $compliance,
        'open_critical' => $openCritical,
        'open_high' => $openHigh
    ];
}

// 6. HELPER: Build Risk Matrix data for visualization
function getRiskMatrixData($pdo, $auditId) {
    // Query findings by risk level and likelihood x impact grid
    $stmt = $pdo->prepare("SELECT 
        likelihood,
        impact,
        COUNT(*) as count
        FROM findings
        WHERE audit_id = ?
        GROUP BY likelihood, impact
        ORDER BY likelihood, impact");
    $stmt->execute([$auditId]);
    $findings = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Build 5x5 matrix (rows=likelihood, cols=impact)
    $matrix = [];
    for ($l = 1; $l <= 5; $l++) {
        $matrix[$l] = [];
        for ($i = 1; $i <= 5; $i++) {
            $matrix[$l][$i] = ['count' => 0, 'level' => 'Low'];
        }
    }
    
    foreach ($findings as $row) {
        $l = (int)$row['likelihood'];
        $i = (int)$row['impact'];
        $score = $l * $i;
        if ($score >= 20) {
            $level = 'Critical';
        } elseif ($score >= 15) {
            $level = 'High';
        } elseif ($score >= 10) {
            $level = 'Medium';
        } else {
            $level = 'Low';
        }
        $matrix[$l][$i] = [
            'count' => (int)$row['count'],
            'level' => $level
        ];
    }
    
    return $matrix;
}
?>
