<?php
/**
 * SRM-Audit - Audit Session Actions API
 * Handle CRUD operations for audit sessions
 */

// Suppress display errors but keep error logging
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);

// Start output buffering to catch any stray output
ob_start();

session_start();
require_once '../functions/db.php';
require_once '../functions/auth.php';
require_once '../functions/risk.php';

// Clear any buffered output if exists
if (ob_get_length()) {
    ob_end_clean();
}

header('Content-Type: application/json');

// Check authentication
if (!isLoggedIn()) {
    echo json_encode(['success' => false, 'message' => 'Unauthorized']);
    exit();
}

$userId = $_SESSION['user_id'];
$action = $_GET['action'] ?? '';

try {
    switch ($action) {
        case 'create':
            // Create new audit session
            $orgId = intval($_POST['organization_id']);
            $sessionName = trim($_POST['session_name'] ?? '');
            $digitalScale = $_POST['digital_scale'];
            $auditDate = $_POST['audit_date'];
            $notes = trim($_POST['notes'] ?? '');
            
            // Verify organization ownership
            $stmt = $pdo->prepare("SELECT id, industry FROM organizations WHERE id = ? AND user_id = ?");
            $stmt->execute([$orgId, $userId]);
            $org = $stmt->fetch();
            
            if (!$org) {
                throw new Exception('Organization not found or access denied');
            }
            
            // Calculate exposure score
            $exposureData = calculateExposureScore($org['industry'], $digitalScale);
            
            // Insert audit session
            $stmt = $pdo->prepare("INSERT INTO audit_sessions 
                                  (organization_id, session_name, digital_scale, audit_date, 
                                   exposure_score, exposure_level, status, notes) 
                                  VALUES (?, ?, ?, ?, ?, ?, 'Planning', ?)");
            $stmt->execute([
                $orgId, 
                $sessionName, 
                $digitalScale, 
                $auditDate, 
                $exposureData['score'], 
                $exposureData['level'],
                $notes
            ]);
            
            $auditId = $pdo->lastInsertId();
            
            echo json_encode([
                'success' => true, 
                'message' => 'Audit session created successfully',
                'audit_id' => $auditId,
                'exposure_score' => $exposureData['score'],
                'exposure_level' => $exposureData['level']
            ]);
            break;
            
        case 'update':
            // Update audit session
            $auditId = intval($_POST['id']);
            $sessionName = trim($_POST['session_name'] ?? '');
            $digitalScale = $_POST['digital_scale'];
            $auditDate = $_POST['audit_date'];
            $status = $_POST['status'] ?? 'Planning';
            $notes = trim($_POST['notes'] ?? '');
            
            // Verify ownership
            $stmt = $pdo->prepare("SELECT a.id, o.industry 
                                  FROM audit_sessions a 
                                  JOIN organizations o ON a.organization_id = o.id 
                                  WHERE a.id = ? AND o.user_id = ?");
            $stmt->execute([$auditId, $userId]);
            $audit = $stmt->fetch();
            
            if (!$audit) {
                throw new Exception('Audit session not found or access denied');
            }
            
            // Recalculate exposure if digital scale changed
            $exposureData = calculateExposureScore($audit['industry'], $digitalScale);
            
            $stmt = $pdo->prepare("UPDATE audit_sessions 
                                  SET session_name = ?, digital_scale = ?, audit_date = ?, 
                                      exposure_score = ?, exposure_level = ?, status = ?, notes = ?,
                                      updated_at = NOW()
                                  WHERE id = ?");
            $stmt->execute([
                $sessionName, 
                $digitalScale, 
                $auditDate, 
                $exposureData['score'], 
                $exposureData['level'],
                $status,
                $notes,
                $auditId
            ]);
            
            logAction($pdo, $userId, 'UPDATE_AUDIT_SESSION', 'audit_sessions', $auditId);
            
            echo json_encode(['success' => true, 'message' => 'Audit session updated successfully']);
            break;
            
        case 'delete':
            // Delete audit session
            $data = json_decode(file_get_contents('php://input'), true);
            $auditId = intval($data['id']);
            
            // Verify ownership
            $stmt = $pdo->prepare("SELECT a.id 
                                  FROM audit_sessions a 
                                  JOIN organizations o ON a.organization_id = o.id 
                                  WHERE a.id = ? AND o.user_id = ?");
            $stmt->execute([$auditId, $userId]);
            
            if (!$stmt->fetch()) {
                throw new Exception('Audit session not found or access denied');
            }
            
            // Delete audit session (CASCADE will delete related records)
            $stmt = $pdo->prepare("DELETE FROM audit_sessions WHERE id = ?");
            $stmt->execute([$auditId]);
            
            logAction($pdo, $userId, 'DELETE_AUDIT_SESSION', 'audit_sessions', $auditId);
            
            echo json_encode(['success' => true, 'message' => 'Audit session deleted successfully']);
            break;
            
        case 'calculate_risk':
            // Recalculate final risk score for audit
            $auditId = intval($_POST['audit_id']);
            
            // Verify ownership
            $stmt = $pdo->prepare("SELECT a.* 
                                  FROM audit_sessions a 
                                  JOIN organizations o ON a.organization_id = o.id 
                                  WHERE a.id = ? AND o.user_id = ?");
            $stmt->execute([$auditId, $userId]);
            $audit = $stmt->fetch();
            
            if (!$audit) {
                throw new Exception('Audit session not found or access denied');
            }
            
            // Calculate risk metrics
            $riskData = calculateAuditRisk($pdo, $auditId);
            
            // Update audit session with calculated risk
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
                $riskData['avg_asset_criticality'],
                $riskData['avg_risk_score'],
                $riskData['final_risk_score'],
                $riskData['final_risk_level'],
                $riskData['compliance_percentage'],
                $riskData['nist_maturity_level'],
                $auditId
            ]);
            
            logAction($pdo, $userId, 'CALCULATE_AUDIT_RISK', 'audit_sessions', $auditId);
            
            echo json_encode([
                'success' => true, 
                'message' => 'Risk calculated successfully',
                'data' => $riskData
            ]);
            break;
            
        case 'get':
            // Get single audit session
            $auditId = intval($_GET['id']);
            
            $stmt = $pdo->prepare("SELECT a.*, o.organization_name, o.industry 
                                  FROM audit_sessions a 
                                  JOIN organizations o ON a.organization_id = o.id 
                                  WHERE a.id = ? AND o.user_id = ?");
            $stmt->execute([$auditId, $userId]);
            $audit = $stmt->fetch();
            
            if (!$audit) {
                throw new Exception('Audit session not found');
            }
            
            echo json_encode(['success' => true, 'data' => $audit]);
            break;
            
        case 'list':
            // List all audit sessions for organization
            $orgId = intval($_GET['organization_id'] ?? 0);
            
            if ($orgId > 0) {
                // Verify organization ownership
                $stmt = $pdo->prepare("SELECT id FROM organizations WHERE id = ? AND user_id = ?");
                $stmt->execute([$orgId, $userId]);
                if (!$stmt->fetch()) {
                    throw new Exception('Organization not found or access denied');
                }
                
                $stmt = $pdo->prepare("SELECT * FROM audit_sessions WHERE organization_id = ? ORDER BY audit_date DESC");
                $stmt->execute([$orgId]);
            } else {
                // List all audits for user's organizations
                $stmt = $pdo->prepare("SELECT a.*, o.organization_name 
                                      FROM audit_sessions a 
                                      JOIN organizations o ON a.organization_id = o.id 
                                      WHERE o.user_id = ? 
                                      ORDER BY a.audit_date DESC");
                $stmt->execute([$userId]);
            }
            
            $audits = $stmt->fetchAll();
            
            echo json_encode(['success' => true, 'data' => $audits]);
            break;
            
        default:
            throw new Exception('Invalid action');
    }
    
} catch (Throwable $e) {
    echo json_encode(['success' => false, 'message' => 'System Error: ' . $e->getMessage()]);
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
            $_SERVER['HTTP_USER_AGENT']
        ]);
    } catch (Exception $e) {
        error_log("Failed to log action: " . $e->getMessage());
    }
}
?>
