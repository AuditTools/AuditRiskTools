<?php
/**
 * SRM-Audit - AI Summary Actions
 */
session_start();
require_once '../functions/db.php';
require_once '../functions/auth.php';
require_once '../functions/risk.php';
require_once '../functions/report.php';

header('Content-Type: application/json');

if (!isLoggedIn()) {
	echo json_encode(['success' => false, 'message' => 'Unauthorized']);
	exit();
}

$userId = $_SESSION['user_id'];
$action = $_GET['action'] ?? 'summary';

try {
	if ($action !== 'summary') {
		throw new Exception('Invalid action');
	}

	$auditId = intval($_GET['audit_id'] ?? $_POST['audit_id'] ?? 0);
	if ($auditId <= 0) {
		throw new Exception('Invalid audit_id');
	}

	updateAuditMetrics($pdo, $auditId, true);
	$data = getReportData($pdo, $auditId, $userId);

	if (!$data) {
		throw new Exception('Audit not found or access denied');
	}

	$summary = buildLocalSummary($data);

	$apiKey = getenv('OPENAI_API_KEY');
	if ($apiKey) {
		$summary = callOpenAiSummary($data, $apiKey) ?: $summary;
	}

	echo json_encode(['success' => true, 'summary' => $summary]);
} catch (Exception $e) {
	echo json_encode(['success' => false, 'message' => $e->getMessage()]);
}

function buildLocalSummary($data) {
	$audit = $data['audit'];
	$parts = [];
	$parts[] = 'Audit ' . $audit['session_name'] . ' for ' . $audit['organization_name'] . ' (industry: ' . $audit['industry'] . ').';
	$parts[] = 'Exposure is ' . ($audit['exposure_level'] ?? 'Low') . ' with score ' . number_format((float)($audit['exposure_score'] ?? 0), 2) . '.';
	$parts[] = 'Final risk is ' . ($audit['final_risk_level'] ?? 'Low') . ' (score ' . number_format((float)($audit['final_risk_score'] ?? 0), 2) . ').';
	$parts[] = 'Compliance is ' . number_format((float)($audit['compliance_percentage'] ?? 0), 2) . '% with NIST maturity ' . ($audit['nist_maturity_level'] ?? 'Initial') . '.';
	$parts[] = 'Total assets: ' . (int)$data['assets_count'] . ', findings: ' . (int)$data['findings_count'] . '.';
	return implode(' ', $parts);
}

function callOpenAiSummary($data, $apiKey) {
	$audit = $data['audit'];
	$prompt = "Create a concise executive summary for a cybersecurity audit.\n";
	$prompt .= "Organization: {$audit['organization_name']} ({$audit['industry']})\n";
	$prompt .= "Audit: {$audit['session_name']} on {$audit['audit_date']}\n";
	$prompt .= "Exposure: {$audit['exposure_level']} ({$audit['exposure_score']})\n";
	$prompt .= "Avg asset criticality: {$audit['avg_asset_criticality']}\n";
	$prompt .= "Final risk: {$audit['final_risk_level']} ({$audit['final_risk_score']})\n";
	$prompt .= "Compliance: {$audit['compliance_percentage']}% (NIST {$audit['nist_maturity_level']})\n";
	$prompt .= "Assets: {$data['assets_count']}, Findings: {$data['findings_count']}\n";
	$prompt .= "Top findings count: " . count($data['top_findings']) . "\n";
	$prompt .= "Write 5-7 sentences with priorities and remediation focus.";

	$model = getenv('OPENAI_MODEL') ?: 'gpt-4o-mini';

	$payload = json_encode([
		'model' => $model,
		'temperature' => 0.2,
		'messages' => [
			['role' => 'system', 'content' => 'You are an executive cybersecurity audit summarizer. Keep it concise and actionable.'],
			['role' => 'user', 'content' => $prompt],
		],
	]);

	$ch = curl_init('https://api.openai.com/v1/chat/completions');
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
	curl_setopt($ch, CURLOPT_POST, true);
	curl_setopt($ch, CURLOPT_HTTPHEADER, [
		'Content-Type: application/json',
		'Authorization: Bearer ' . $apiKey,
	]);
	curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);

	$response = curl_exec($ch);
	$status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
	curl_close($ch);

	if ($status !== 200 || !$response) {
		return null;
	}

	$data = json_decode($response, true);
	$content = $data['choices'][0]['message']['content'] ?? null;

	return $content ? trim($content) : null;
}
?>
