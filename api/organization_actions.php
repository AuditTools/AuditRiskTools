<?php
/**
 * SRM-Audit - Organization Actions API
 * Handle CRUD operations for organizations
 */

// Suppress display errors but keep error logging
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ob_start();

session_start();
require_once '../functions/db.php';
require_once '../functions/auth.php';

ob_end_clean();
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
            // Add new organization
            $orgName = trim($_POST['organization_name']);
            $industry = $_POST['industry'];
            $contactPerson = trim($_POST['contact_person'] ?? '');
            $contactEmail = trim($_POST['contact_email'] ?? '');
            $contactPhone = trim($_POST['contact_phone'] ?? '');
            $address = trim($_POST['address'] ?? '');
            
            if (empty($orgName) || empty($industry)) {
                throw new Exception('Organization name and industry are required');
            }
            
            $stmt = $pdo->prepare("INSERT INTO organizations 
                                  (user_id, organization_name, industry, contact_person, contact_email, contact_phone, address) 
                                  VALUES (?, ?, ?, ?, ?, ?, ?)");
            $stmt->execute([$userId, $orgName, $industry, $contactPerson, $contactEmail, $contactPhone, $address]);
            
            $orgId = $pdo->lastInsertId();
            
            // Log action
            logAction($pdo, $userId, 'CREATE_ORGANIZATION', 'organizations', $orgId);
            
            echo json_encode([
                'success' => true, 
                'message' => 'Organization added successfully',
                'organization_id' => $orgId
            ]);
            break;
            
        case 'update':
            // Update organization
            $orgId = intval($_POST['id']);
            $orgName = trim($_POST['organization_name']);
            $industry = $_POST['industry'];
            $contactPerson = trim($_POST['contact_person'] ?? '');
            $contactEmail = trim($_POST['contact_email'] ?? '');
            $contactPhone = trim($_POST['contact_phone'] ?? '');
            $address = trim($_POST['address'] ?? '');
            
            // Verify ownership
            $stmt = $pdo->prepare("SELECT id FROM organizations WHERE id = ? AND user_id = ?");
            $stmt->execute([$orgId, $userId]);
            if (!$stmt->fetch()) {
                throw new Exception('Organization not found or access denied');
            }
            
            $stmt = $pdo->prepare("UPDATE organizations 
                                  SET organization_name = ?, industry = ?, contact_person = ?, 
                                      contact_email = ?, contact_phone = ?, address = ?, updated_at = NOW()
                                  WHERE id = ? AND user_id = ?");
            $stmt->execute([$orgName, $industry, $contactPerson, $contactEmail, $contactPhone, $address, $orgId, $userId]);
            
            logAction($pdo, $userId, 'UPDATE_ORGANIZATION', 'organizations', $orgId);
            
            echo json_encode(['success' => true, 'message' => 'Organization updated successfully']);
            break;
            
        case 'delete':
            // Delete organization
            $data = json_decode(file_get_contents('php://input'), true);
            $orgId = intval($data['id']);
            
            // Verify ownership
            $stmt = $pdo->prepare("SELECT id FROM organizations WHERE id = ? AND user_id = ?");
            $stmt->execute([$orgId, $userId]);
            if (!$stmt->fetch()) {
                throw new Exception('Organization not found or access denied');
            }
            
            // Delete organization (CASCADE will delete related records)
            $stmt = $pdo->prepare("DELETE FROM organizations WHERE id = ? AND user_id = ?");
            $stmt->execute([$orgId, $userId]);
            
            logAction($pdo, $userId, 'DELETE_ORGANIZATION', 'organizations', $orgId);
            
            echo json_encode(['success' => true, 'message' => 'Organization deleted successfully']);
            break;
            
        case 'get':
            // Get single organization
            $orgId = intval($_GET['id']);
            
            $stmt = $pdo->prepare("SELECT * FROM organizations WHERE id = ? AND user_id = ?");
            $stmt->execute([$orgId, $userId]);
            $org = $stmt->fetch();
            
            if (!$org) {
                throw new Exception('Organization not found');
            }
            
            echo json_encode(['success' => true, 'data' => $org]);
            break;
            
        case 'list':
            // List all organizations for user
            $stmt = $pdo->prepare("SELECT o.*, 
                                  (SELECT COUNT(*) FROM audit_sessions WHERE organization_id = o.id) as audit_count
                                  FROM organizations o 
                                  WHERE o.user_id = ? AND o.is_active = 1
                                  ORDER BY o.created_at DESC");
            $stmt->execute([$userId]);
            $organizations = $stmt->fetchAll();
            
            echo json_encode(['success' => true, 'data' => $organizations]);
            break;
            
        default:
            throw new Exception('Invalid action');
    }
    
} catch (Exception $e) {
    echo json_encode(['success' => false, 'message' => $e->getMessage()]);
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
        // Log error but don't fail the main operation
        error_log("Failed to log action: " . $e->getMessage());
    }
}
?>
