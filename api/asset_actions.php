<?php
/**
 * SRM-Audit - Asset Actions API
 * Handle CRUD operations for assets
 */
session_start();
require_once '../functions/db.php';
require_once '../functions/auth.php';
require_once '../functions/risk.php';

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
        case 'add':
            // Add new asset
            if (!verifyCSRFToken($_POST['csrf_token'] ?? '')) {
                throw new Exception('Invalid CSRF token');
            }

            $auditId = intval($_POST['audit_id']);
            $assetName = trim($_POST['asset_name']);
            $ipAddress = trim($_POST['ip_address'] ?? '');
            $assetType = trim($_POST['asset_type']);
            $description = trim($_POST['description'] ?? '');
            $owner = trim($_POST['owner'] ?? '');
            $department = trim($_POST['department'] ?? '');
            
            // CIA ratings
            $confidentiality = intval($_POST['confidentiality']);
            $integrity = intval($_POST['integrity']);
            $availability = intval($_POST['availability']);
            
            // Validate CIA ratings
            if ($confidentiality < 1 || $confidentiality > 5 ||
                $integrity < 1 || $integrity > 5 ||
                $availability < 1 || $availability > 5) {
                throw new Exception('CIA ratings must be between 1 and 5');
            }
            
            // Verify audit ownership
            $stmt = $pdo->prepare("SELECT a.id 
                                  FROM audit_sessions a 
                                  JOIN organizations o ON a.organization_id = o.id 
                                  WHERE a.id = ? AND o.user_id = ?");
            $stmt->execute([$auditId, $userId]);
            
            if (!$stmt->fetch()) {
                throw new Exception('Audit session not found or access denied');
            }
            
            // Calculate criticality
            $criticalityScore = ($confidentiality + $integrity + $availability) / 3;
            $criticalityLevel = calculateCriticalityLevel($criticalityScore);
            
            // Insert asset
            $stmt = $pdo->prepare("INSERT INTO assets 
                                  (audit_id, asset_name, ip_address, asset_type, description, owner, department,
                                   confidentiality, integrity, availability, criticality_score, criticality_level) 
                                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
            $stmt->execute([
                $auditId, $assetName, $ipAddress, $assetType, $description, $owner, $department,
                $confidentiality, $integrity, $availability, $criticalityScore, $criticalityLevel
            ]);
            
            $assetId = $pdo->lastInsertId();
            
            // Update audit summary metrics
            updateAuditCriticality($pdo, $auditId);
            
            logAction($pdo, $userId, 'ADD_ASSET', 'assets', $assetId);
            
            echo json_encode([
                'success' => true, 
                'message' => 'Asset added successfully',
                'asset_id' => $assetId,
                'criticality_score' => $criticalityScore,
                'criticality_level' => $criticalityLevel
            ]);
            break;
            
        case 'update':
            // Update asset
            if (!verifyCSRFToken($_POST['csrf_token'] ?? '')) {
                throw new Exception('Invalid CSRF token');
            }

            $assetId = intval($_POST['id']);
            $assetName = trim($_POST['asset_name']);
            $ipAddress = trim($_POST['ip_address'] ?? '');
            $assetType = trim($_POST['asset_type']);
            $description = trim($_POST['description'] ?? '');
            $owner = trim($_POST['owner'] ?? '');
            $department = trim($_POST['department'] ?? '');
            
            // CIA ratings
            $confidentiality = intval($_POST['confidentiality']);
            $integrity = intval($_POST['integrity']);
            $availability = intval($_POST['availability']);
            
            // Validate CIA ratings
            if ($confidentiality < 1 || $confidentiality > 5 ||
                $integrity < 1 || $integrity > 5 ||
                $availability < 1 || $availability > 5) {
                throw new Exception('CIA ratings must be between 1 and 5');
            }
            
            // Verify ownership
            $stmt = $pdo->prepare("SELECT a.audit_id 
                                  FROM assets a 
                                  JOIN audit_sessions au ON a.audit_id = au.id 
                                  JOIN organizations o ON au.organization_id = o.id 
                                  WHERE a.id = ? AND o.user_id = ?");
            $stmt->execute([$assetId, $userId]);
            $asset = $stmt->fetch();
            
            if (!$asset) {
                throw new Exception('Asset not found or access denied');
            }
            
            // Calculate criticality
            $criticalityScore = ($confidentiality + $integrity + $availability) / 3;
            $criticalityLevel = calculateCriticalityLevel($criticalityScore);
            
            // Update asset
            $stmt = $pdo->prepare("UPDATE assets 
                                  SET asset_name = ?, ip_address = ?, asset_type = ?, description = ?,
                                      owner = ?, department = ?,
                                      confidentiality = ?, integrity = ?, availability = ?,
                                      criticality_score = ?, criticality_level = ?, updated_at = NOW()
                                  WHERE id = ?");
            $stmt->execute([
                $assetName, $ipAddress, $assetType, $description, $owner, $department,
                $confidentiality, $integrity, $availability, $criticalityScore, $criticalityLevel,
                $assetId
            ]);
            
            // Update audit summary metrics
            updateAuditCriticality($pdo, $asset['audit_id']);
            
            logAction($pdo, $userId, 'UPDATE_ASSET', 'assets', $assetId);
            
            echo json_encode(['success' => true, 'message' => 'Asset updated successfully']);
            break;
            
        case 'delete':
            // Delete asset
            $data = json_decode(file_get_contents('php://input'), true);
            $assetId = intval($data['id']);

            if (isset($data['csrf_token']) && !verifyCSRFToken($data['csrf_token'])) {
                throw new Exception('Invalid CSRF token');
            }
            
            // Verify ownership and get audit_id
            $stmt = $pdo->prepare("SELECT a.audit_id 
                                  FROM assets a 
                                  JOIN audit_sessions au ON a.audit_id = au.id 
                                  JOIN organizations o ON au.organization_id = o.id 
                                  WHERE a.id = ? AND o.user_id = ?");
            $stmt->execute([$assetId, $userId]);
            $asset = $stmt->fetch();
            
            if (!$asset) {
                throw new Exception('Asset not found or access denied');
            }
            
            // Delete asset
            $stmt = $pdo->prepare("DELETE FROM assets WHERE id = ?");
            $stmt->execute([$assetId]);
            
            // Update audit summary metrics
            updateAuditCriticality($pdo, $asset['audit_id']);
            
            logAction($pdo, $userId, 'DELETE_ASSET', 'assets', $assetId);
            
            echo json_encode(['success' => true, 'message' => 'Asset deleted successfully']);
            break;
            
        case 'get':
            // Get single asset
            $assetId = intval($_GET['id']);
            
            $stmt = $pdo->prepare("SELECT a.* 
                                  FROM assets a 
                                  JOIN audit_sessions au ON a.audit_id = au.id 
                                  JOIN organizations o ON au.organization_id = o.id 
                                  WHERE a.id = ? AND o.user_id = ?");
            $stmt->execute([$assetId, $userId]);
            $asset = $stmt->fetch();
            
            if (!$asset) {
                throw new Exception('Asset not found');
            }
            
            echo json_encode(['success' => true, 'data' => $asset]);
            break;
            
        case 'list':
            // List all assets for audit
            $auditId = intval($_GET['audit_id']);
            
            // Verify audit ownership
            $stmt = $pdo->prepare("SELECT a.id 
                                  FROM audit_sessions a 
                                  JOIN organizations o ON a.organization_id = o.id 
                                  WHERE a.id = ? AND o.user_id = ?");
            $stmt->execute([$auditId, $userId]);
            
            if (!$stmt->fetch()) {
                throw new Exception('Audit session not found or access denied');
            }
            
            $stmt = $pdo->prepare("SELECT * FROM assets WHERE audit_id = ? ORDER BY criticality_score DESC");
            $stmt->execute([$auditId]);
            $assets = $stmt->fetchAll();
            
            echo json_encode(['success' => true, 'data' => $assets]);
            break;
            
        default:
            throw new Exception('Invalid action');
    }
    
} catch (Exception $e) {
    echo json_encode(['success' => false, 'message' => $e->getMessage()]);
}

function updateAuditCriticality($pdo, $auditId) {
    updateAuditMetrics($pdo, $auditId, true);
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
