<?php
/**
 * SRM-Audit - Risk Calculation Functions
 * Calculate exposure scores, risk levels, and compliance metrics
 */

/**
 * Calculate Exposure Score based on Industry and Digital Scale
 * Formula: Exposure Score = Industry Baseline × Digital Scale Weight
 * 
 * @param string $industry Industry type
 * @param string $digitalScale Digital maturity (High/Medium/Low)
 * @return array ['score' => int, 'level' => string]
 */
function calculateExposureScore($industry, $digitalScale) {
    // Industry baseline scores
    $base = [
        'Finance' => 3,
        'Healthcare' => 3,
        'Education' => 2,
        'Retail' => 2,
        'Technology' => 2,
        'Other' => 1
    ];
    
    // Digital scale weights
    $scale = [
        'Low' => 1,
        'Medium' => 2,
        'High' => 3
    ];
    
    // Get baseline (default to 1 if industry not found)
    $baseline = $base[$industry] ?? $base['Other'];
    
    // Get scale weight (default to 2 if scale not found)
    $weight = $scale[$digitalScale] ?? $scale['Medium'];
    
    // Calculate exposure score
    $score = $baseline * $weight;
    
    // Determine exposure level
    if ($score <= 3) {
        $level = 'Low';
    } elseif ($score <= 6) {
        $level = 'Medium';
    } else {
        $level = 'High';
    }
    
    return [
        'score' => $score,
        'level' => $level
    ];
}

/**
 * Calculate Risk Score for a Finding
 * Risk = Likelihood × Impact
 * 
 * @param int $likelihood Likelihood rating (1-5)
 * @param int $impact Impact rating (1-5)
 * @return array ['score' => int, 'level' => string]
 */
function calculateRiskScore($likelihood, $impact) {
    // Risk Score = Likelihood × Impact (max 25)
    $riskScore = $likelihood * $impact;
    
    // Determine risk level
    if ($riskScore >= 20) {
        $level = 'Critical';
    } elseif ($riskScore >= 15) {
        $level = 'High';
    } elseif ($riskScore >= 10) {
        $level = 'Medium';
    } elseif ($riskScore >= 5) {
        $level = 'Low';
    } else {
        $level = 'Minimal';
    }
    
    return [
        'score' => $riskScore,
        'level' => $level
    ];
}

/**
 * Calculate Asset Criticality Score
 * Based on CIA triad (Confidentiality, Integrity, Availability)
 * 
 * @param int $confidentiality C rating (1-5)
 * @param int $integrity I rating (1-5)
 * @param int $availability A rating (1-5)
 * @return array ['score' => float, 'level' => string]
 */
function calculateAssetCriticality($confidentiality, $integrity, $availability) {
    // Average of CIA ratings
    $criticalityScore = ($confidentiality + $integrity + $availability) / 3;
    $criticalityScore = round($criticalityScore, 2);
    
    // Determine criticality level
    if ($criticalityScore >= 4.5) {
        $level = 'Critical';
    } elseif ($criticalityScore >= 3.5) {
        $level = 'High';
    } elseif ($criticalityScore >= 2.5) {
        $level = 'Medium';
    } else {
        $level = 'Low';
    }
    
    return [
        'score' => $criticalityScore,
        'level' => $level
    ];
}

/**
 * Calculate Final Risk Level for Audit Session
 * Formula: (Exposure Score × Avg Asset Criticality × Avg Risk Score) / 10
 * 
 * @param float $exposureScore Exposure score (1-9)
 * @param float $avgAssetCriticality Average asset criticality (1-5)
 * @param float $avgRiskScore Average finding risk score (1-25)
 * @return array ['score' => float, 'level' => string]
 */
function calculateFinalRiskLevel($exposureScore, $avgAssetCriticality, $avgRiskScore) {
    // Calculate final risk score
    // Normalization by 10 to maintain manageable classification range
    $finalScore = ($exposureScore * $avgAssetCriticality * $avgRiskScore) / 10;
    $finalScore = round($finalScore, 2);
    
    // Determine final risk level
    if ($finalScore > 70) {
        $level = 'Critical';
    } elseif ($finalScore >= 41) {
        $level = 'High';
    } elseif ($finalScore >= 21) {
        $level = 'Medium';
    } else {
        $level = 'Low';
    }
    
    return [
        'score' => $finalScore,
        'level' => $level
    ];
}

/**
 * Calculate Compliance Percentage
 * Based on number of compliant vs non-compliant findings
 * 
 * @param int $compliantCount Number of compliant findings
 * @param int $totalFindings Total number of findings
 * @return float Compliance percentage
 */
function calculateCompliancePercentage($compliantCount, $totalFindings) {
    if ($totalFindings === 0) {
        return 100.0; // No findings = 100% compliant
    }
    
    $percentage = ($compliantCount / $totalFindings) * 100;
    return round($percentage, 2);
}

/**
 * Map Finding to NIST CSF Function
 * 
 * @param string $findingCategory Category of the finding
 * @return string NIST function (Identify, Protect, Detect, Respond, Recover)
 */
function mapToNISTFunction($findingCategory) {
    $nistMapping = [
        'Access Control' => 'Protect',
        'Authentication' => 'Protect',
        'Encryption' => 'Protect',
        'Network Security' => 'Protect',
        'Patch Management' => 'Protect',
        'Vulnerability' => 'Identify',
        'Asset Management' => 'Identify',
        'Risk Assessment' => 'Identify',
        'Monitoring' => 'Detect',
        'Logging' => 'Detect',
        'Intrusion Detection' => 'Detect',
        'Incident Response' => 'Respond',
        'Business Continuity' => 'Recover',
        'Disaster Recovery' => 'Recover',
        'Backup' => 'Recover',
        'Default' => 'Identify'
    ];
    
    return $nistMapping[$findingCategory] ?? $nistMapping['Default'];
}

/**
 * Get Risk Score Color for UI
 * 
 * @param string $level Risk level
 * @return string Color code
 */
function getRiskColor($level) {
    $colors = [
        'Critical' => '#dc3545', // Red
        'High' => '#fd7e14',     // Orange
        'Medium' => '#ffc107',   // Yellow
        'Low' => '#28a745',      // Green
        'Minimal' => '#17a2b8'   // Blue
    ];
    
    return $colors[$level] ?? '#6c757d'; // Gray default
}

/**
 * Get Average Asset Criticality for Audit
 * 
 * @param PDO $pdo Database connection
 * @param int $auditId Audit session ID
 * @return float Average criticality score
 */
function getAvgAssetCriticality($pdo, $auditId) {
    $stmt = $pdo->prepare("
        SELECT AVG(criticality_score) as avg_criticality
        FROM assets
        WHERE audit_id = ?
    ");
    $stmt->execute([$auditId]);
    $result = $stmt->fetch(PDO::FETCH_ASSOC);
    
    return round($result['avg_criticality'] ?? 0, 2);
}

/**
 * Get Average Risk Score for Audit
 * 
 * @param PDO $pdo Database connection
 * @param int $auditId Audit session ID
 * @return float Average risk score
 */
function getAvgRiskScore($pdo, $auditId) {
    $stmt = $pdo->prepare("
        SELECT AVG(risk_score) as avg_risk
        FROM findings
        WHERE audit_id = ?
    ");
    $stmt->execute([$auditId]);
    $result = $stmt->fetch(PDO::FETCH_ASSOC);
    
    return round($result['avg_risk'] ?? 0, 2);
}

/**
 * Get Top 5 Highest Risks for Audit
 * 
 * @param PDO $pdo Database connection
 * @param int $auditId Audit session ID
 * @return array Top 5 findings
 */
function getTop5Risks($pdo, $auditId) {
    $stmt = $pdo->prepare("
        SELECT id, title, risk_score, risk_level, nist_function
        FROM findings
        WHERE audit_id = ?
        ORDER BY risk_score DESC
        LIMIT 5
    ");
    $stmt->execute([$auditId]);
    
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

/**
 * Get NIST CSF Distribution for Audit
 * 
 * @param PDO $pdo Database connection
 * @param int $auditId Audit session ID
 * @return array NIST function counts ['Identify' => 5, 'Protect' => 8, ...]
 */
function getNISTDistribution($pdo, $auditId) {
    $stmt = $pdo->prepare("
        SELECT nist_function, COUNT(*) as count
        FROM findings
        WHERE audit_id = ?
        GROUP BY nist_function
    ");
    $stmt->execute([$auditId]);
    $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Convert to associative array
    $distribution = [];
    foreach ($results as $row) {
        $distribution[$row['nist_function']] = (int)$row['count'];
    }
    
    return $distribution;
}

/**
 * Calculate Compliance Percentage for Audit
 * 
 * @param PDO $pdo Database connection
 * @param int $auditId Audit session ID
 * @return float Compliance percentage
 */
function getCompliancePercentage($pdo, $auditId) {
    $stmt = $pdo->prepare("
        SELECT 
            SUM(CASE WHEN audit_status = 'Compliant' THEN 1 ELSE 0 END) as compliant_count,
            COUNT(*) as total_count
        FROM findings
        WHERE audit_id = ?
    ");
    $stmt->execute([$auditId]);
    $result = $stmt->fetch(PDO::FETCH_ASSOC);
    
    $total = (int)$result['total_count'];
    
    if ($total === 0) {
        return 100.0; // No findings = 100% compliant
    }
    
    $compliant = (int)$result['compliant_count'];
    $percentage = ($compliant / $total) * 100;
    
    return round($percentage, 2);
}

/**
 * Get Dashboard Summary for Audit
 * Combines all key metrics in one call
 * 
 * @param PDO $pdo Database connection
 * @param int $auditId Audit session ID
 * @return array Complete dashboard data
 */
function getDashboardSummary($pdo, $auditId) {
    // Get audit session details
    $stmt = $pdo->prepare("
        SELECT exposure_score, exposure_level, final_risk_score, final_risk_level
        FROM audit_sessions
        WHERE id = ?
    ");
    $stmt->execute([$auditId]);
    $audit = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$audit) {
        return null;
    }
    
    return [
        'exposure_score' => (int)$audit['exposure_score'],
        'exposure_level' => $audit['exposure_level'],
        'avg_asset_criticality' => getAvgAssetCriticality($pdo, $auditId),
        'avg_risk_score' => getAvgRiskScore($pdo, $auditId),
        'final_risk_score' => (float)$audit['final_risk_score'],
        'final_risk_level' => $audit['final_risk_level'],
        'top_5_risks' => getTop5Risks($pdo, $auditId),
        'nist_distribution' => getNISTDistribution($pdo, $auditId),
        'compliance_percentage' => getCompliancePercentage($pdo, $auditId)
    ];
}
?>
