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

updateAuditMetrics($pdo, $auditId);
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

	// Generate PDF with audit opinion and risk matrix
	$pdfHtml = "<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Audit Report</title>";
	$pdfHtml .= "<style>
		body { font-family: Arial, sans-serif; color: #222; margin: 24px; line-height: 1.6; }
		.report-card { border: 1px solid #e5e7eb; border-radius: 10px; padding: 16px; margin-bottom: 16px; page-break-inside: avoid; }
		.report-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; }
		.report-table { width: 100%; border-collapse: collapse; margin-bottom: 16px; }
		.report-table th, .report-table td { border: 1px solid #e5e7eb; padding: 8px; text-align: left; }
		.report-table th { background: #f3f4f6; font-weight: bold; }
		.report-stats { display: flex; gap: 14px; flex-wrap: wrap; }
		.badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 1.1em; font-weight: bold; }
		.badge-success { background-color: #28a745; color: white; }
		.badge-warning { background-color: #ffc107; color: #333; }
		.badge-danger { background-color: #dc3545; color: white; }
		.matrix-table { font-size: 12px; }
		.matrix-table td { text-align: center; font-weight: bold; height: 30px; }
		h1, h2 { color: #1f2937; }
		h3, h4 { color: #374151; margin-top: 16px; margin-bottom: 12px; }
		.text-center { text-align: center; }
		.text-muted { color: #6b7280; }
		small { color: #6b7280; }
	</style></head><body>";
    
	$pdfHtml .= renderReportHtml($data);
    
	// Add Audit Opinion
	$opinionData = calculateAuditOpinion($pdo, $auditId);
	$opinion = $opinionData['opinion'];
	$opinionBgColor = $opinion === 'Secure' ? '#28a745' : ($opinion === 'Acceptable Risk' ? '#ffc107' : '#dc3545');
	$opinionTextColor = $opinion === 'Acceptable Risk' ? '#333' : '#fff';
    
	$pdfHtml .= "<div class='report-card'>";
	$pdfHtml .= "<h3>🔐 Audit Opinion</h3>";
	$pdfHtml .= "<div class='text-center'>";
	$pdfHtml .= "<div class='badge' style='background-color: " . $opinionBgColor . "; color: " . $opinionTextColor . "; font-size: 1.3em; padding: 8px 16px;'>" . htmlspecialchars($opinion) . "</div>";
	$pdfHtml .= "</div>";
	$pdfHtml .= "<p class='text-center text-muted'>";
	$pdfHtml .= "<strong>Based on:</strong><br>";
	$pdfHtml .= "Compliance: " . number_format($opinionData['compliance'], 2) . "% | ";
	$pdfHtml .= "Open Critical: " . $opinionData['open_critical'] . " | ";
	$pdfHtml .= "Open High: " . $opinionData['open_high'];
	$pdfHtml .= "</p>";
	$pdfHtml .= "</div>";
    
	// Add Risk Matrix
	$matrix = getRiskMatrixData($pdo, $auditId);
	$pdfHtml .= "<div class='report-card'>";
	$pdfHtml .= "<h3>Risk Matrix (Likelihood × Impact)</h3>";
	$pdfHtml .= "<table class='report-table matrix-table'>";
	$pdfHtml .= "<thead>";
	$pdfHtml .= "<tr>";
	$pdfHtml .= "<th style='width: 50px;'>L\\I</th>";
	for ($i = 1; $i <= 5; $i++) {
		$pdfHtml .= "<th style='width: 60px;'>I" . $i . "</th>";
	}
	$pdfHtml .= "</tr>";
	$pdfHtml .= "</thead>";
	$pdfHtml .= "<tbody>";
    
	for ($l = 5; $l >= 1; $l--) {
		$pdfHtml .= "<tr>";
		$pdfHtml .= "<td><strong>L" . $l . "</strong></td>";
		for ($i = 1; $i <= 5; $i++) {
			$cell = $matrix[$l][$i];
			$bgColor = $cell['level'] === 'Critical' ? '#ff6b6b' : 
					  ($cell['level'] === 'High' ? '#ffa94d' : 
					  ($cell['level'] === 'Medium' ? '#ffe066' : '#a8e6cf'));
			$count = $cell['count'];
			$textColor = $bgColor === '#a8e6cf' ? '#333' : '#fff';
			$pdfHtml .= "<td style='background-color: " . $bgColor . "; color: " . $textColor . ";'>" . ($count > 0 ? $count : '—') . "</td>";
		}
		$pdfHtml .= "</tr>";
	}
    
	$pdfHtml .= "</tbody>";
	$pdfHtml .= "</table>";
	$pdfHtml .= "<p class='text-muted text-center'><small>🔴 Critical | 🟠 High | 🟡 Medium | 🟢 Low</small></p>";
	$pdfHtml .= "</div>";
    
	$pdfHtml .= "</body></html>";
    
	$dompdf = new Dompdf\Dompdf();
	$dompdf->loadHtml($pdfHtml);
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
