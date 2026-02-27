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

// Block auditee from auditor-only write operations
$auditorWriteActions = ['add', 'delete'];
if (in_array($action, $auditorWriteActions, true)) {
    requireWriteAccess();
}
// update_remediation and close_finding: auditor only
if (in_array($action, ['update_remediation', 'close_finding'], true)) {
    requireWriteAccess();
}

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
            $owaspCategory = trim($_POST['owasp_category'] ?? '');
            $recommendation = trim($_POST['recommendation'] ?? '');

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

            // 2. Insert with OWASP category and recommendation support
            $stmt = $pdo->prepare("INSERT INTO findings
                (audit_id, asset_id, title, description, owasp_category, likelihood, impact, risk_score, risk_level, nist_function, audit_status, recommendation)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
            $stmt->execute([
                $auditId, $assetId, $title, $description, $owaspCategory ?: null,
                $likelihood, $impact, $riskScore, $riskLevel, $nistFunction, $auditStatus,
                $recommendation ?: null
            ]);

            $findingId = $pdo->lastInsertId();
            
            // Handle evidence file uploads
            if (!empty($_FILES['evidence_file']['name'][0])) {
                $uploadDir = '../uploads/evidence/';
                if (!is_dir($uploadDir)) {
                    mkdir($uploadDir, 0755, true);
                }
                
                $allowedMimes = ['image/jpeg', 'image/png', 'application/pdf', 
                                 'application/msword', 
                                 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                                 'application/vnd.ms-excel',
                                 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                                 'text/plain'];
                $maxSize = 10 * 1024 * 1024; // 10MB
                
                $fileCount = count($_FILES['evidence_file']['name']);
                for ($i = 0; $i < $fileCount; $i++) {
                    if (empty($_FILES['evidence_file']['name'][$i])) continue;
                    
                    $fileName = $_FILES['evidence_file']['name'][$i];
                    $fileTmp = $_FILES['evidence_file']['tmp_name'][$i];
                    $fileSize = $_FILES['evidence_file']['size'][$i];
                    $fileType = $_FILES['evidence_file']['type'][$i];
                    
                    if ($fileSize > $maxSize) {
                        continue; // Skip if too large
                    }
                    
                    if (!in_array($fileType, $allowedMimes)) {
                        continue; // Skip if not allowed
                    }
                    
                    $fileExt = pathinfo($fileName, PATHINFO_EXTENSION);
                    $storedFileName = 'evidence_' . $findingId . '_' . time() . '_' . uniqid() . '.' . $fileExt;
                    $filePath = $uploadDir . $storedFileName;
                    
                    if (move_uploaded_file($fileTmp, $filePath)) {
                        $stmt = $pdo->prepare("INSERT INTO audit_evidence
                            (finding_id, audit_id, original_filename, stored_filename, file_path, file_type, file_size, evidence_type, created_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?, 'Finding Evidence', NOW())");
                        $stmt->execute([$findingId, $auditId, $fileName, $storedFileName, $filePath, $fileType, $fileSize]);
                    }
                }
            }
            
            // 3. Update dashboard metrics using Hybrid function (Removed the 'true' parameter)
            updateAuditMetrics($pdo, $auditId);
            
            // Notify assigned auditees about the new finding
            $stmtAuditees = $pdo->prepare("SELECT auditee_user_id FROM audit_auditees WHERE audit_id = ?");
            $stmtAuditees->execute([$auditId]);
            $auditeeIds = $stmtAuditees->fetchAll(PDO::FETCH_COLUMN);
            foreach ($auditeeIds as $auditeeId) {
                createNotification($pdo, $auditeeId, $auditId, 'finding_created',
                    "New finding: \"$title\" — " . $riskLevel . " risk. Please review and upload evidence.");
            }

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

        case 'management_response':
            // Auditee submits management response to a finding
            $role = $_SESSION['user_role'] ?? 'auditor';
            if ($role !== 'auditee') {
                throw new Exception('Only auditees can submit management responses');
            }

            $findingId = intval($_POST['finding_id']);
            $response = trim($_POST['management_response'] ?? '');
            $auditId = intval($_POST['audit_id'] ?? 0);

            if (empty($response)) {
                throw new Exception('Management response cannot be empty');
            }

            // Verify auditee is assigned to this audit
            if (!isAuditeeAssigned($pdo, $auditId, $userId)) {
                throw new Exception('You are not assigned to this audit');
            }

            // Verify finding belongs to this audit
            $stmt = $pdo->prepare("SELECT id, audit_id, title FROM findings WHERE id = ? AND audit_id = ?");
            $stmt->execute([$findingId, $auditId]);
            $finding = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$finding) {
                throw new Exception('Finding not found in this audit');
            }

            // Update management response
            $stmt = $pdo->prepare("UPDATE findings SET management_response = ?, response_date = NOW(), responded_by = ?, remediation_status = 'In Progress' WHERE id = ?");
            $stmt->execute([$response, $userId, $findingId]);

            // Notify auditor
            $stmt = $pdo->prepare("SELECT o.user_id FROM audit_sessions a JOIN organizations o ON a.organization_id = o.id WHERE a.id = ?");
            $stmt->execute([$auditId]);
            $auditorInfo = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($auditorInfo) {
                $userName = $_SESSION['user_name'] ?? 'Auditee';
                createNotification($pdo, $auditorInfo['user_id'], $auditId, 'response_submitted', 
                    "$userName responded to finding: " . $finding['title']);
            }

            logAction($pdo, $userId, 'MANAGEMENT_RESPONSE', 'findings', $findingId);

            echo json_encode(['success' => true, 'message' => 'Management response submitted']);
            break;

        case 'close_finding':
            // Auditor closes a finding (mark as Resolved)
            if (!verifyCSRFToken($_POST['csrf_token'] ?? '')) {
                throw new Exception('Invalid CSRF token');
            }

            $findingId = intval($_POST['finding_id']);
            
            $finding = getFindingForUser($pdo, $findingId, $userId);
            if (!$finding) {
                throw new Exception('Finding not found or access denied');
            }

            $deadline = !empty($_POST['remediation_deadline']) ? $_POST['remediation_deadline'] : null;
            $stmt = $pdo->prepare("UPDATE findings SET remediation_status = 'Resolved', remediation_deadline = COALESCE(?, remediation_deadline), updated_at = NOW() WHERE id = ?");
            $stmt->execute([$deadline, $findingId]);

            // Notify assigned auditees that the finding was closed
            $closedAuditId = (int)$finding['audit_id'];
            $stmtAuditees = $pdo->prepare("SELECT auditee_user_id FROM audit_auditees WHERE audit_id = ?");
            $stmtAuditees->execute([$closedAuditId]);
            $auditeeIds = $stmtAuditees->fetchAll(PDO::FETCH_COLUMN);
            $findingTitle = $finding['title'] ?? 'Finding';
            foreach ($auditeeIds as $auditeeId) {
                createNotification($pdo, $auditeeId, $closedAuditId, 'finding_closed',
                    "Finding resolved: \"$findingTitle\" has been closed by the auditor.");
            }

            updateAuditMetrics($pdo, $closedAuditId);
            logAction($pdo, $userId, 'CLOSE_FINDING', 'findings', $findingId);

            echo json_encode(['success' => true, 'message' => 'Finding closed successfully']);
            break;

        case 'reopen_finding':
            // Auditor reopens a finding (mark as Open again)
            requireWriteAccess();
            
            $findingId = intval($_POST['finding_id']);
            
            $finding = getFindingForUser($pdo, $findingId, $userId);
            if (!$finding) {
                throw new Exception('Finding not found or access denied');
            }

            $stmt = $pdo->prepare("UPDATE findings SET remediation_status = 'Open', updated_at = NOW() WHERE id = ?");
            $stmt->execute([$findingId]);

            // Notify auditee that finding was reopened
            $auditId = (int)$finding['audit_id'];
            $stmtAuditees = $pdo->prepare("SELECT auditee_user_id FROM audit_auditees WHERE audit_id = ?");
            $stmtAuditees->execute([$auditId]);
            $auditees = $stmtAuditees->fetchAll(PDO::FETCH_COLUMN);
            foreach ($auditees as $auditeeId) {
                createNotification($pdo, $auditeeId, $auditId, 'finding_reopened', 
                    "Finding reopened — additional action required.");
            }

            updateAuditMetrics($pdo, $auditId);
            logAction($pdo, $userId, 'REOPEN_FINDING', 'findings', $findingId);

            echo json_encode(['success' => true, 'message' => 'Finding reopened']);
            break;

        case 'list':
            // List findings for an audit (accessible by auditor + assigned auditee)
            $auditId = intval($_GET['audit_id']);
            $role = $_SESSION['user_role'] ?? 'auditor';

            if ($role === 'auditee') {
                if (!isAuditeeAssigned($pdo, $auditId, $userId)) {
                    throw new Exception('You are not assigned to this audit');
                }
            } else {
                $stmt = $pdo->prepare("SELECT a.id FROM audit_sessions a JOIN organizations o ON a.organization_id = o.id WHERE a.id = ? AND o.user_id = ?");
                $stmt->execute([$auditId, $userId]);
                if (!$stmt->fetch()) {
                    throw new Exception('Audit session not found or access denied');
                }
            }

            $stmt = $pdo->prepare("SELECT f.*, a.asset_name, 
                                   u.name as responder_name
                                   FROM findings f
                                   JOIN assets a ON f.asset_id = a.id
                                   LEFT JOIN users u ON f.responded_by = u.id
                                   WHERE f.audit_id = ?
                                   ORDER BY f.risk_score DESC, f.created_at DESC");
            $stmt->execute([$auditId]);
            $findings = $stmt->fetchAll(PDO::FETCH_ASSOC);

            echo json_encode(['success' => true, 'data' => $findings]);
            break;

        default:
            throw new Exception('Invalid action');
    }
} catch (Exception $e) {
    echo json_encode(['success' => false, 'message' => $e->getMessage()]);
}

function getFindingForUser($pdo, $findingId, $userId) {
    $stmt = $pdo->prepare("SELECT f.id, f.audit_id, f.title
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