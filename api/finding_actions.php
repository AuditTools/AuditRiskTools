<?php
/**
 * SRM-Audit - Finding Actions API
 */
session_start();
require_once '../functions/db.php';
require_once '../functions/auth.php';
require_once '../functions/risk.php';

header('Content-Type: application/json');

if (!isLoggedIn()) {
    echo json_encode(['success' => false, 'message' => 'Unauthorized']);
    exit();
}

$userId = $_SESSION['user_id'];
$action = $_GET['action'] ?? 'add';

try {
    switch ($action) {
        case 'add':
            if (!verifyCSRFToken($_POST['csrf_token'] ?? '')) {
                throw new Exception('Invalid CSRF token');
            }

            $auditId = intval($_POST['audit_id']);
            $assetId = intval($_POST['asset_id']);
            $title = trim($_POST['title'] ?? '');
            $description = trim($_POST['description'] ?? '');
            $nistFunction = $_POST['nist_function'] ?? 'Identify';
            $auditStatus = $_POST['audit_status'] ?? 'Non-Compliant';
            $likelihood = intval($_POST['likelihood']);
            $impact = intval($_POST['impact']);

            if ($likelihood < 1 || $likelihood > 5 || $impact < 1 || $impact > 5) {
                throw new Exception('Likelihood and impact must be between 1 and 5');
            }

            if (!$title) {
                throw new Exception('Title is required');
            }

            // Verify audit ownership
            $stmt = $pdo->prepare("SELECT a.id FROM audit_sessions a JOIN organizations o ON a.organization_id = o.id WHERE a.id = ? AND o.user_id = ?");
            $stmt->execute([$auditId, $userId]);
            if (!$stmt->fetch()) {
                throw new Exception('Audit session not found or access denied');
            }

            // Verify asset belongs to audit and user
            $stmt = $pdo->prepare("SELECT a.id FROM assets a JOIN audit_sessions s ON a.audit_id = s.id JOIN organizations o ON s.organization_id = o.id WHERE a.id = ? AND a.audit_id = ? AND o.user_id = ?");
            $stmt->execute([$assetId, $auditId, $userId]);
            if (!$stmt->fetch()) {
                throw new Exception('Asset not found for this audit');
            }

            // 1. Calculate Risk Score & Level
            $riskScore = $likelihood * $impact;
            
            if ($riskScore >= 20) $riskLevel = 'Critical';
            elseif ($riskScore >= 15) $riskLevel = 'High';
            elseif ($riskScore >= 10) $riskLevel = 'Medium';
            else $riskLevel = 'Low';

            // 2. Insert using your exact schema fields
            $stmt = $pdo->prepare("INSERT INTO findings
                (audit_id, asset_id, title, description, likelihood, impact, risk_score, risk_level, nist_function, audit_status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
            $stmt->execute([
                $auditId, $assetId, $title, $description, $likelihood, 
                $impact, $riskScore, $riskLevel, $nistFunction, $auditStatus
            ]);

            $findingId = $pdo->lastInsertId();
            
            // 3. Update dashboard metrics using Hybrid function (Removed the 'true' parameter)
            updateAuditMetrics($pdo, $auditId);
            
            logAction($pdo, $userId, 'ADD_FINDING', 'findings', $findingId);

            echo json_encode(['success' => true, 'message' => 'Finding added', 'finding_id' => $findingId]);
            break;

        case 'update_remediation':
            if (!verifyCSRFToken($_POST['csrf_token'] ?? '')) {
                throw new Exception('Invalid CSRF token');
            }

            $findingId = intval($_POST['finding_id']);
            $status = $_POST['remediation_status'] ?? 'Open';
            $deadline = !empty($_POST['remediation_deadline']) ? $_POST['remediation_deadline'] : null;

            $finding = getFindingForUser($pdo, $findingId, $userId);
            if (!$finding) {
                throw new Exception('Finding not found or access denied');
            }

            $stmt = $pdo->prepare("UPDATE findings SET remediation_status = ?, remediation_deadline = ? WHERE id = ?");
            $stmt->execute([$status, $deadline, $findingId]);

            logAction($pdo, $userId, 'UPDATE_REMEDIATION', 'findings', $findingId);

            echo json_encode(['success' => true, 'message' => 'Remediation updated']);
            break;

        case 'delete':
            $data = json_decode(file_get_contents('php://input'), true);
            $findingId = intval($data['id']);

            if (isset($data['csrf_token']) && !verifyCSRFToken($data['csrf_token'])) {
                throw new Exception('Invalid CSRF token');
            }

            $finding = getFindingForUser($pdo, $findingId, $userId);
            if (!$finding) {
                throw new Exception('Finding not found or access denied');
            }

            $stmt = $pdo->prepare("DELETE FROM findings WHERE id = ?");
            $stmt->execute([$findingId]);

            // Update dashboard metrics using Hybrid function
            updateAuditMetrics($pdo, (int)$finding['audit_id']);
            
            logAction($pdo, $userId, 'DELETE_FINDING', 'findings', $findingId);

            echo json_encode(['success' => true, 'message' => 'Finding deleted']);
            break;

        default:
            throw new Exception('Invalid action');
    }
} catch (Exception $e) {
    echo json_encode(['success' => false, 'message' => $e->getMessage()]);
}

function getFindingForUser($pdo, $findingId, $userId) {
    $stmt = $pdo->prepare("SELECT f.id, f.audit_id
        FROM findings f
        JOIN audit_sessions a ON f.audit_id = a.id
        JOIN organizations o ON a.organization_id = o.id
        WHERE f.id = ? AND o.user_id = ?");
    $stmt->execute([$findingId, $userId]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
}

function logAction($pdo, $userId, $action, $table, $recordId) {
    try {
        $stmt = $pdo->prepare("INSERT INTO audit_logs (user_id, action, table_name, record_id, ip_address, user_agent)
                              VALUES (?, ?, ?, ?, ?, ?)");
        $stmt->execute([
            $userId,
            $action,
            $table,
            $recordId,
            $_SERVER['REMOTE_ADDR'],
            $_SERVER['HTTP_USER_AGENT'],
        ]);
    } catch (Exception $e) {
        error_log('Failed to log action: ' . $e->getMessage());
    }
}
?>