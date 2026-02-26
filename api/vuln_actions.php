<?php
/**
 * SRM-Audit - Vulnerability Assessment API
 * Handles OWASP vulnerability selection per asset,
 * auto-creates findings with risk mapping and audit checklist items.
 */
session_start();
require_once '../functions/db.php';
require_once '../functions/auth.php';
require_once '../functions/risk.php';
require_once '../functions/owasp_library.php';

header('Content-Type: application/json');

if (!isLoggedIn()) {
    echo json_encode(['success' => false, 'message' => 'Unauthorized']);
    exit();
}

$userId = $_SESSION['user_id'];
$action = $_GET['action'] ?? '';

// Block auditee from write operations
$writeActions = ['assess', 'remove'];
if (in_array($action, $writeActions, true)) {
    requireWriteAccess();
}

try {
    switch ($action) {

        // ============================================
        // GET OWASP LIBRARY (grouped by category)
        // ============================================
        case 'get_library':
            $grouped = getOwaspLibraryGrouped();
            echo json_encode(['success' => true, 'data' => $grouped]);
            break;

        // ============================================
        // GET EXISTING ASSESSMENTS for an asset
        // ============================================
        case 'get_assessment':
            $auditId = intval($_GET['audit_id'] ?? 0);
            $assetId = intval($_GET['asset_id'] ?? 0);

            if (!$auditId || !$assetId) {
                throw new Exception('audit_id and asset_id are required');
            }

            // Verify access
            verifyAuditAccess($pdo, $auditId, $userId);

            // Get existing findings with OWASP category for this asset
            $stmt = $pdo->prepare("
                SELECT id, title, owasp_category, cwe_id, likelihood, impact, 
                       risk_score, risk_level, nist_function, audit_status, recommendation
                FROM findings 
                WHERE audit_id = ? AND asset_id = ? AND owasp_category IS NOT NULL AND owasp_category != ''
                ORDER BY risk_score DESC
            ");
            $stmt->execute([$auditId, $assetId]);
            $existing = $stmt->fetchAll(PDO::FETCH_ASSOC);

            // Extract already-selected OWASP vuln names
            $selectedNames = array_column($existing, 'owasp_category');

            echo json_encode([
                'success' => true, 
                'data' => [
                    'findings' => $existing,
                    'selected_vulns' => $selectedNames
                ]
            ]);
            break;

        // ============================================
        // SUBMIT VULNERABILITY ASSESSMENT
        // Auto-creates findings from selected OWASP vulns
        // ============================================
        case 'assess':
            if (!verifyCSRFToken($_POST['csrf_token'] ?? '')) {
                throw new Exception('Invalid CSRF token');
            }

            $auditId = intval($_POST['audit_id'] ?? 0);
            $assetId = intval($_POST['asset_id'] ?? 0);
            $vulnIds = $_POST['vuln_ids'] ?? [];

            if (!$auditId || !$assetId) {
                throw new Exception('audit_id and asset_id are required');
            }

            if (empty($vulnIds) || !is_array($vulnIds)) {
                throw new Exception('Please select at least one vulnerability');
            }

            // Verify audit ownership
            verifyAuditAccess($pdo, $auditId, $userId);

            // Verify asset belongs to this audit
            $stmt = $pdo->prepare("
                SELECT a.id, a.asset_name FROM assets a 
                JOIN audit_sessions s ON a.audit_id = s.id 
                JOIN organizations o ON s.organization_id = o.id 
                WHERE a.id = ? AND a.audit_id = ? AND o.user_id = ?
            ");
            $stmt->execute([$assetId, $auditId, $userId]);
            $asset = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$asset) {
                throw new Exception('Asset not found for this audit');
            }

            // Get selected vulnerabilities from library
            $vulnIds = array_map('intval', $vulnIds);
            $selectedVulns = getOwaspVulnsByIds($vulnIds);

            if (empty($selectedVulns)) {
                throw new Exception('No valid vulnerabilities selected');
            }

            // Check which vulns are already assessed for this asset (avoid duplicates)
            $stmt = $pdo->prepare("
                SELECT owasp_category FROM findings 
                WHERE audit_id = ? AND asset_id = ? AND owasp_category IS NOT NULL
            ");
            $stmt->execute([$auditId, $assetId]);
            $existingVulns = array_column($stmt->fetchAll(PDO::FETCH_ASSOC), 'owasp_category');

            $created = 0;
            $skipped = 0;
            $findings = [];

            $insertStmt = $pdo->prepare("
                INSERT INTO findings 
                (audit_id, asset_id, title, description, owasp_category, cwe_id, 
                 likelihood, impact, risk_score, risk_level, nist_function, 
                 audit_status, recommendation)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ");

            foreach ($selectedVulns as $vuln) {
                // Skip if already assessed
                if (in_array($vuln['name'], $existingVulns)) {
                    $skipped++;
                    continue;
                }

                // Allow user overrides for likelihood/impact if provided
                $likelihood = intval($_POST['likelihood_' . $vuln['id']] ?? $vuln['default_likelihood']);
                $impact = intval($_POST['impact_' . $vuln['id']] ?? $vuln['default_impact']);

                // Clamp to 1-5
                $likelihood = max(1, min(5, $likelihood));
                $impact = max(1, min(5, $impact));

                // Calculate risk
                $riskScore = $likelihood * $impact;
                if ($riskScore >= 20) $riskLevel = 'Critical';
                elseif ($riskScore >= 15) $riskLevel = 'High';
                elseif ($riskScore >= 10) $riskLevel = 'Medium';
                else $riskLevel = 'Low';

                // Build finding title and description
                $title = $vuln['name'] . ' — ' . $asset['asset_name'];
                $description = $vuln['description'] . "\n\nThreat: " . $vuln['threat'] 
                             . "\n\nAudit Check: " . $vuln['audit_checklist'];

                $insertStmt->execute([
                    $auditId,
                    $assetId,
                    $title,
                    $description,
                    $vuln['name'],       // owasp_category
                    $vuln['cwe_id'],     // cwe_id
                    $likelihood,
                    $impact,
                    $riskScore,
                    $riskLevel,
                    $vuln['nist_function'],
                    'Non-Compliant',     // Default to non-compliant since vulnerability was found
                    $vuln['recommendation']
                ]);

                $findingId = $pdo->lastInsertId();
                $created++;

                $findings[] = [
                    'id' => $findingId,
                    'name' => $vuln['name'],
                    'risk_score' => $riskScore,
                    'risk_level' => $riskLevel
                ];

                logAction($pdo, $userId, 'ADD_VULN_FINDING', 'findings', $findingId);
            }

            // Update audit metrics after all findings are created
            if ($created > 0) {
                updateAuditMetrics($pdo, $auditId);
                
                // Also update compliance
                $compliance = getComplianceAndMaturity($pdo, $auditId);
                $stmt = $pdo->prepare("
                    UPDATE audit_sessions 
                    SET compliance_percentage = ?, nist_maturity_level = ?
                    WHERE id = ?
                ");
                $stmt->execute([$compliance['percentage'], $compliance['maturity'], $auditId]);
            }

            echo json_encode([
                'success' => true,
                'message' => "$created finding(s) created" . ($skipped > 0 ? ", $skipped already existed (skipped)" : ""),
                'data' => [
                    'created' => $created,
                    'skipped' => $skipped,
                    'findings' => $findings
                ]
            ]);
            break;

        // ============================================
        // REMOVE a vulnerability assessment finding
        // ============================================
        case 'remove':
            $data = json_decode(file_get_contents('php://input'), true);
            if (isset($data['csrf_token']) && !verifyCSRFToken($data['csrf_token'])) {
                throw new Exception('Invalid CSRF token');
            }

            $findingId = intval($data['finding_id'] ?? 0);
            if (!$findingId) {
                throw new Exception('finding_id is required');
            }

            // Verify user owns this finding
            $stmt = $pdo->prepare("
                SELECT f.id, f.audit_id FROM findings f
                JOIN audit_sessions a ON f.audit_id = a.id
                JOIN organizations o ON a.organization_id = o.id
                WHERE f.id = ? AND o.user_id = ?
            ");
            $stmt->execute([$findingId, $userId]);
            $finding = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$finding) {
                throw new Exception('Finding not found or access denied');
            }

            $auditId = (int)$finding['audit_id'];
            $stmt = $pdo->prepare("DELETE FROM findings WHERE id = ?");
            $stmt->execute([$findingId]);

            updateAuditMetrics($pdo, $auditId);
            
            // Update compliance
            $compliance = getComplianceAndMaturity($pdo, $auditId);
            $stmt = $pdo->prepare("
                UPDATE audit_sessions 
                SET compliance_percentage = ?, nist_maturity_level = ?
                WHERE id = ?
            ");
            $stmt->execute([$compliance['percentage'], $compliance['maturity'], $auditId]);

            logAction($pdo, $userId, 'REMOVE_VULN_FINDING', 'findings', $findingId);

            echo json_encode(['success' => true, 'message' => 'Vulnerability finding removed']);
            break;

        default:
            throw new Exception('Invalid action. Use: get_library, get_assessment, assess, remove');
    }
} catch (Exception $e) {
    echo json_encode(['success' => false, 'message' => $e->getMessage()]);
}

// ============================================
// Helper Functions
// ============================================

function verifyAuditAccess($pdo, $auditId, $userId) {
    $stmt = $pdo->prepare("
        SELECT a.id FROM audit_sessions a 
        JOIN organizations o ON a.organization_id = o.id 
        WHERE a.id = ? AND o.user_id = ?
    ");
    $stmt->execute([$auditId, $userId]);
    if (!$stmt->fetch()) {
        throw new Exception('Audit session not found or access denied');
    }
}

function logAction($pdo, $userId, $action, $table, $recordId) {
    try {
        $stmt = $pdo->prepare("
            INSERT INTO audit_logs (user_id, action, table_name, record_id, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?, ?)
        ");
        $stmt->execute([
            $userId, $action, $table, $recordId,
            $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? ''
        ]);
    } catch (Exception $e) {
        error_log('Failed to log action: ' . $e->getMessage());
    }
}
