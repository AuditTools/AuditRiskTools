<?php
/**
 * SRM-Audit - Risk and exposure calculation helpers
 */

function calculateExposureScore($industry, $digitalScale) {
	$industryBase = [
		'Finance' => 4.6,
		'Healthcare' => 4.2,
		'Government' => 4.1,
		'Technology' => 3.7,
		'Manufacturing' => 3.2,
		'Retail' => 3.1,
		'Education' => 2.6,
		'Other' => 2.6,
	];

	$scaleFactor = [
		'Low' => 0.9,
		'Medium' => 1.0,
		'High' => 1.15,
	];

	$base = $industryBase[$industry] ?? 2.8;
	$factor = $scaleFactor[$digitalScale] ?? 1.0;

	$score = min(5.0, round($base * $factor, 2));

	return [
		'score' => $score,
		'level' => exposureLevelFromScore($score),
	];
}

function exposureLevelFromScore($score) {
	if ($score <= 2.5) {
		return 'Low';
	}
	if ($score <= 3.5) {
		return 'Medium';
	}
	return 'High';
}

function calculateCriticalityLevel($score) {
	if ($score >= 4.5) {
		return 'Critical';
	}
	if ($score >= 3.5) {
		return 'High';
	}
	if ($score >= 2.5) {
		return 'Medium';
	}
	return 'Low';
}

function calculateRiskLevel($riskScore) {
	if ($riskScore >= 20) {
		return 'Critical';
	}
	if ($riskScore >= 13) {
		return 'High';
	}
	if ($riskScore >= 6) {
		return 'Medium';
	}
	return 'Low';
}

function calculateAuditRisk($pdo, $auditId) {
	return updateAuditMetrics($pdo, $auditId, false);
}

function updateAuditMetrics($pdo, $auditId, $persist = true) {
	$stmt = $pdo->prepare("SELECT AVG(criticality_score) AS avg_crit FROM assets WHERE audit_id = ?");
	$stmt->execute([$auditId]);
	$avgCrit = (float)($stmt->fetch(PDO::FETCH_ASSOC)['avg_crit'] ?? 0);

	$stmt = $pdo->prepare("SELECT AVG(risk_score) AS avg_risk FROM findings WHERE audit_id = ?");
	$stmt->execute([$auditId]);
	$avgRisk = (float)($stmt->fetch(PDO::FETCH_ASSOC)['avg_risk'] ?? 0);

	$stmt = $pdo->prepare("SELECT audit_status, COUNT(*) AS total FROM findings WHERE audit_id = ? GROUP BY audit_status");
	$stmt->execute([$auditId]);
	$rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

	$totalFindings = 0;
	$compliantCount = 0;
	$partialCount = 0;

	foreach ($rows as $row) {
		$count = (int)$row['total'];
		$totalFindings += $count;

		if ($row['audit_status'] === 'Compliant') {
			$compliantCount += $count;
		} elseif ($row['audit_status'] === 'Partially Compliant') {
			$partialCount += $count;
		}
	}

	if ($totalFindings > 0) {
		$compliancePercentage = (($compliantCount + ($partialCount * 0.5)) / $totalFindings) * 100;
	} else {
		$compliancePercentage = 0.0;
	}

	$finalRiskScore = 0.0;
	if ($avgCrit > 0 && $avgRisk > 0) {
		$finalRiskScore = ($avgCrit * $avgRisk) / 5;
	}

	$riskLevel = calculateRiskLevel($finalRiskScore);
	$compliancePercentage = round($compliancePercentage, 2);

	if ($compliancePercentage < 40) {
		$nistLevel = 'Initial';
	} elseif ($compliancePercentage < 60) {
		$nistLevel = 'Developing';
	} elseif ($compliancePercentage < 80) {
		$nistLevel = 'Managed';
	} else {
		$nistLevel = 'Optimized';
	}

	$data = [
		'avg_asset_criticality' => round($avgCrit, 2),
		'avg_risk_score' => round($avgRisk, 2),
		'final_risk_score' => round($finalRiskScore, 2),
		'final_risk_level' => $riskLevel,
		'compliance_percentage' => $compliancePercentage,
		'nist_maturity_level' => $nistLevel,
	];

	if ($persist) {
		$stmt = $pdo->prepare("UPDATE audit_sessions
			SET avg_asset_criticality = ?,
				avg_risk_score = ?,
				final_risk_score = ?,
				final_risk_level = ?,
				compliance_percentage = ?,
				nist_maturity_level = ?,
				updated_at = NOW()
			WHERE id = ?");
		$stmt->execute([
			$data['avg_asset_criticality'],
			$data['avg_risk_score'],
			$data['final_risk_score'],
			$data['final_risk_level'],
			$data['compliance_percentage'],
			$data['nist_maturity_level'],
			$auditId,
		]);
	}

	return $data;
}
?>
