<?php
/**
 * SRM-Audit - Report Actions API
 */
session_start();
require_once '../functions/db.php';
require_once '../functions/auth.php';
require_once '../functions/risk.php';
require_once '../functions/report.php';

if (!isLoggedIn()) {
	http_response_code(401);
	echo 'Unauthorized';
	exit();
}

$userId = $_SESSION['user_id'];
$action = $_GET['action'] ?? 'preview';
$auditId = intval($_GET['audit_id'] ?? 0);

if ($auditId <= 0) {
	http_response_code(400);
	echo 'Invalid audit_id';
	exit();
}

updateAuditMetrics($pdo, $auditId, true);
$data = getReportData($pdo, $auditId, $userId);

if (!$data) {
	http_response_code(404);
	echo 'Audit not found or access denied';
	exit();
}

$html = "<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Audit Report</title>";
$html .= "<style>
	body { font-family: Arial, sans-serif; color: #222; margin: 24px; }
	.report-card { border: 1px solid #e5e7eb; border-radius: 10px; padding: 16px; margin-bottom: 16px; }
	.report-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; }
	.report-table { width: 100%; border-collapse: collapse; }
	.report-table th, .report-table td { border: 1px solid #e5e7eb; padding: 8px; text-align: left; }
	.report-table th { background: #f3f4f6; }
	.report-stats { display: flex; gap: 14px; flex-wrap: wrap; }
</style></head><body>";
$html .= renderReportHtml($data);
$html .= "</body></html>";

if ($action === 'download_pdf') {
	$autoload = __DIR__ . '/../vendor/autoload.php';

	if (!file_exists($autoload)) {
		http_response_code(501);
		echo 'PDF engine not installed. Please install dompdf via composer.';
		exit();
	}

	require_once $autoload;

	if (!class_exists('Dompdf\\Dompdf')) {
		http_response_code(501);
		echo 'Dompdf not available.';
		exit();
	}

	$dompdf = new Dompdf\Dompdf();
	$dompdf->loadHtml($html);
	$dompdf->setPaper('A4', 'portrait');
	$dompdf->render();

	$fileName = 'audit-report-' . $auditId . '.pdf';
	header('Content-Type: application/pdf');
	header('Content-Disposition: attachment; filename="' . $fileName . '"');
	echo $dompdf->output();
	exit();
}

header('Content-Type: text/html; charset=UTF-8');
echo $html;
?>
