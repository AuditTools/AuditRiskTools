<?php
/**
 * SRM-Audit - AI Actions API (Using .env configuration)
 * Handle AI report generation and chatbot interactions
 */

// Suppress display errors but keep error logging
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);

// Start output buffering
ob_start();

header('Content-Type: application/json');

// Check action first
$action = $_GET['action'] ?? '';

// Test endpoint doesn't need authentication or database
if ($action === 'test') {
    ob_end_clean(); // Clear buffer before output
    try {
        require_once '../functions/ai_api.php';
        $result = testAIConnection();
        echo json_encode($result);
    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'error' => $e->getMessage()
        ]);
    }
    exit();
}

// All other actions require authentication
session_start();
require_once '../functions/db.php';
require_once '../functions/auth.php';
require_once '../functions/ai_api.php';

ob_end_clean(); // Clear buffer after includes

if (!isLoggedIn()) {
    echo json_encode(['success' => false, 'message' => 'Unauthorized']);
    exit();
}

$userId = $_SESSION['user_id'];

try {
    switch ($action) {
        case 'generate_report':
            // Generate AI Audit Report
            $auditId = intval($_POST['audit_id']);
            
            // Verify ownership and get audit data
            $stmt = $pdo->prepare("
                SELECT a.*, o.organization_name, o.industry, o.user_id
                FROM audit_sessions a 
                JOIN organizations o ON a.organization_id = o.id 
                WHERE a.id = ? AND o.user_id = ?
            ");
            $stmt->execute([$auditId, $userId]);
            $audit = $stmt->fetch();
            
            if (!$audit) {
                throw new Exception('Audit session not found or access denied');
            }
            
            // Get Top 5 Risks
            $stmt = $pdo->prepare("
                SELECT title, description, likelihood, impact, risk_score, nist_function
                FROM findings 
                WHERE audit_id = ? 
                ORDER BY risk_score DESC 
                LIMIT 5
            ");
            $stmt->execute([$auditId]);
            $findings = $stmt->fetchAll();
            
            // Prepare audit data for AI
            $auditData = [
                'organization_name' => $audit['organization_name'],
                'industry' => $audit['industry'],
                'exposure_level' => $audit['exposure_level'] ?? 'Unknown',
                'final_risk_level' => $audit['final_risk_level'] ?? 'Unknown',
                'compliance_percentage' => $audit['compliance_percentage'] ?? 0,
                'top_5_risks' => $findings
            ];
            
            // Generate report via AI
            $result = generateAuditReport($auditData);
            
            if (!$result['success']) {
                throw new Exception($result['error']);
            }
            
            $reportContent = $result['report'];
            $aiProvider = $result['provider'];
            
            // Save generated report to database
            $stmt = $pdo->prepare("
                INSERT INTO ai_reports (audit_session_id, report_type, report_content, model_used) 
                VALUES (?, 'executive_summary', ?, ?)
            ");
            $stmt->execute([$auditId, $reportContent, $aiProvider]);
            
            $reportId = $pdo->lastInsertId();
            
            // Update audit session
            $stmt = $pdo->prepare("UPDATE audit_sessions SET last_report_generated = NOW() WHERE id = ?");
            $stmt->execute([$auditId]);
            
            logAction($pdo, $userId, 'GENERATE_AI_REPORT', 'ai_reports', $reportId);
            
            echo json_encode([
                'success' => true,
                'message' => 'Report generated successfully',
                'report_id' => $reportId,
                'report_content' => $reportContent,
                'ai_provider' => $aiProvider
            ]);
            break;
            
        case 'chatbot':
            // Process chatbot question
            $question = trim($_POST['question'] ?? '');
            
            if (empty($question)) {
                throw new Exception('Question is required');
            }
            
            // Character limit check
            if (strlen($question) > 500) {
                throw new Exception('Question too long. Maximum 500 characters.');
            }
            
            // Process via AI
            $result = chatbotGuidance($question);
            
            if (!$result['success']) {
                throw new Exception($result['error']);
            }
            
            $answer = $result['answer'];
            
            // Optional: Save chat history
            if ($userId) {
                try {
                    $stmt = $pdo->prepare("
                        INSERT INTO chatbot_history (user_id, question, answer, model_used) 
                        VALUES (?, ?, ?, ?)
                    ");
                    $stmt->execute([$userId, $question, $answer, AI_PROVIDER]);
                } catch (Exception $e) {
                    // Log but don't fail
                    error_log("Failed to save chat history: " . $e->getMessage());
                }
            }
            
            echo json_encode([
                'success' => true,
                'answer' => $answer,
                'provider' => AI_PROVIDER
            ]);
            break;
            
        case 'get_report':
            // Get saved AI report
            $reportId = intval($_GET['id']);
            
            $stmt = $pdo->prepare("
                SELECT r.*, a.id as audit_id
                FROM ai_reports r
                JOIN audit_sessions a ON r.audit_session_id = a.id
                JOIN organizations o ON a.organization_id = o.id
                WHERE r.id = ? AND o.user_id = ?
            ");
            $stmt->execute([$reportId, $userId]);
            $report = $stmt->fetch();
            
            if (!$report) {
                throw new Exception('Report not found or access denied');
            }
            
            echo json_encode(['success' => true, 'data' => $report]);
            break;
            
        case 'list_reports':
            // List all reports for user
            $stmt = $pdo->prepare("
                SELECT r.*, a.session_name, o.organization_name
                FROM ai_reports r
                JOIN audit_sessions a ON r.audit_session_id = a.id
                JOIN organizations o ON a.organization_id = o.id
                WHERE o.user_id = ?
                ORDER BY r.created_at DESC
            ");
            $stmt->execute([$userId]);
            $reports = $stmt->fetchAll();
            
            echo json_encode(['success' => true, 'data' => $reports]);
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
            $_SERVER['REMOTE_ADDR'] ?? 'unknown', 
            $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
        ]);
    } catch (Exception $e) {
        error_log("Failed to log action: " . $e->getMessage());
    }
}
?>

