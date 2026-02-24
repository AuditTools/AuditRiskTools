<?php
/**
 * SRM-Audit - Report helpers
 */

function getReportData($pdo, $auditId, $userId) {
    $stmt = $pdo->prepare("SELECT a.*, o.organization_name, o.industry
        FROM audit_sessions a
        JOIN organizations o ON a.organization_id = o.id
        WHERE a.id = ? AND o.user_id = ?");
    $stmt->execute([$auditId, $userId]);
    $audit = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$audit) {
        return null;
    }

    $stmt = $pdo->prepare("SELECT COUNT(*) AS total FROM assets WHERE audit_id = ?");
    $stmt->execute([$auditId]);
    $assetsCount = (int)($stmt->fetch(PDO::FETCH_ASSOC)['total'] ?? 0);

    $stmt = $pdo->prepare("SELECT COUNT(*) AS total FROM findings WHERE audit_id = ?");
    $stmt->execute([$auditId]);
    $findingsCount = (int)($stmt->fetch(PDO::FETCH_ASSOC)['total'] ?? 0);

    $stmt = $pdo->prepare("SELECT risk_level, COUNT(*) AS total FROM findings WHERE audit_id = ? GROUP BY risk_level");
    $stmt->execute([$auditId]);
    $riskLevels = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $stmt = $pdo->prepare("SELECT audit_status, COUNT(*) AS total FROM findings WHERE audit_id = ? GROUP BY audit_status");
    $stmt->execute([$auditId]);
    $compliance = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $stmt = $pdo->prepare("SELECT remediation_status, COUNT(*) AS total FROM findings WHERE audit_id = ? GROUP BY remediation_status");
    $stmt->execute([$auditId]);
    $remediation = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $stmt = $pdo->prepare("SELECT title, risk_score, risk_level, nist_function, audit_status, remediation_status
        FROM findings
        WHERE audit_id = ?
        ORDER BY risk_score DESC, created_at DESC
        LIMIT 10");
    $stmt->execute([$auditId]);
    $topFindings = $stmt->fetchAll(PDO::FETCH_ASSOC);

    return [
        'audit' => $audit,
        'assets_count' => $assetsCount,
        'findings_count' => $findingsCount,
        'risk_levels' => $riskLevels,
        'compliance' => $compliance,
        'remediation' => $remediation,
        'top_findings' => $topFindings,
    ];
}

function renderReportHtml($data) {
    $audit = $data['audit'];
    $riskLevels = mapCountPairs($data['risk_levels'], 'risk_level');
    $compliance = mapCountPairs($data['compliance'], 'audit_status');
    $remediation = mapCountPairs($data['remediation'], 'remediation_status');

    $html = "";
    $html .= "<div class='report-card'>";
    $html .= "<h3>Executive Summary</h3>";
    $html .= "<p><strong>Organization:</strong> " . htmlspecialchars($audit['organization_name']) . "</p>";
    $html .= "<p><strong>Audit:</strong> " . htmlspecialchars($audit['session_name']) . " (" . htmlspecialchars($audit['audit_date']) . ")</p>";
    $html .= "<p><strong>Industry:</strong> " . htmlspecialchars($audit['industry']) . "</p>";
    $html .= "</div>";

    $html .= "<div class='report-grid'>";
    $html .= "<div class='report-card'><h4>Exposure</h4><p><strong>Level:</strong> " . htmlspecialchars($audit['exposure_level'] ?? 'Low') . "</p><p><strong>Score:</strong> " . number_format((float)($audit['exposure_score'] ?? 0), 2) . "</p></div>";
    $html .= "<div class='report-card'><h4>Assets</h4><p><strong>Total:</strong> " . (int)$data['assets_count'] . "</p><p><strong>Avg Criticality:</strong> " . number_format((float)($audit['avg_asset_criticality'] ?? 0), 2) . "/5</p></div>";
    $html .= "<div class='report-card'><h4>Risk</h4><p><strong>Final Level:</strong> " . htmlspecialchars($audit['final_risk_level'] ?? 'Low') . "</p><p><strong>Final Score:</strong> " . number_format((float)($audit['final_risk_score'] ?? 0), 2) . "/25</p></div>";
    $html .= "<div class='report-card'><h4>Compliance</h4><p><strong>Compliance %:</strong> " . number_format((float)($audit['compliance_percentage'] ?? 0), 2) . "%</p><p><strong>NIST Maturity:</strong> " . htmlspecialchars($audit['nist_maturity_level'] ?? 'Initial') . "</p></div>";
    $html .= "</div>";

    $html .= "<div class='report-card'>";
    $html .= "<h4>Risk Distribution</h4>";
    $html .= "<div class='report-stats'>";
    $html .= "<span>Low: " . (int)($riskLevels['Low'] ?? 0) . "</span>";
    $html .= "<span>Medium: " . (int)($riskLevels['Medium'] ?? 0) . "</span>";
    $html .= "<span>High: " . (int)($riskLevels['High'] ?? 0) . "</span>";
    $html .= "<span>Critical: " . (int)($riskLevels['Critical'] ?? 0) . "</span>";
    $html .= "</div>";
    $html .= "</div>";

    $html .= "<div class='report-card'>";
    $html .= "<h4>Compliance Breakdown</h4>";
    $html .= "<div class='report-stats'>";
    $html .= "<span>Compliant: " . (int)($compliance['Compliant'] ?? 0) . "</span>";
    $html .= "<span>Partial: " . (int)($compliance['Partially Compliant'] ?? 0) . "</span>";
    $html .= "<span>Non-Compliant: " . (int)($compliance['Non-Compliant'] ?? 0) . "</span>";
    $html .= "</div>";
    $html .= "</div>";

    $html .= "<div class='report-card'>";
    $html .= "<h4>Remediation Status</h4>";
    $html .= "<div class='report-stats'>";
    $html .= "<span>Open: " . (int)($remediation['Open'] ?? 0) . "</span>";
    $html .= "<span>In Progress: " . (int)($remediation['In Progress'] ?? 0) . "</span>";
    $html .= "<span>Resolved: " . (int)($remediation['Resolved'] ?? 0) . "</span>";
    $html .= "<span>Accepted Risk: " . (int)($remediation['Accepted Risk'] ?? 0) . "</span>";
    $html .= "</div>";
    $html .= "</div>";

    $html .= "<div class='report-card'>";
    $html .= "<h4>Top Findings</h4>";
    $html .= "<table class='report-table'>";
    $html .= "<thead><tr><th>Title</th><th>Score</th><th>Level</th><th>NIST</th><th>Compliance</th><th>Remediation</th></tr></thead>";
    $html .= "<tbody>";

    if (!empty($data['top_findings'])) {
        foreach ($data['top_findings'] as $finding) {
            $html .= "<tr>";
            $html .= "<td>" . htmlspecialchars($finding['title']) . "</td>";
            $html .= "<td>" . htmlspecialchars($finding['risk_score']) . "</td>";
            $html .= "<td>" . htmlspecialchars($finding['risk_level']) . "</td>";
            $html .= "<td>" . htmlspecialchars($finding['nist_function']) . "</td>";
            $html .= "<td>" . htmlspecialchars($finding['audit_status']) . "</td>";
            $html .= "<td>" . htmlspecialchars($finding['remediation_status']) . "</td>";
            $html .= "</tr>";
        }
    } else {
        $html .= "<tr><td colspan='6' style='text-align:center;'>No findings yet</td></tr>";
    }

    $html .= "</tbody></table>";
    $html .= "</div>";

    return $html;
}

function mapCountPairs($rows, $keyName) {
    $result = [];
    foreach ($rows as $row) {
        $result[$row[$keyName]] = (int)$row['total'];
    }
    return $result;
}
?>