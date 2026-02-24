<?php
/**
 * SRM-Audit - AI Actions API
 * Handle AI report generation and chatbot interactions
 */
session_start();
require_once '../functions/db.php';
require_once '../functions/auth.php';
require_once '../functions/ai_api.php';

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
                WHERE audit_session_id = ? 
                ORDER BY risk_score DESC 
                LIMIT 5
            ");
            $stmt->execute([$auditId]);
            $findings = $stmt->fetchAll();
            
            // Format top 5 risks
            $top5Text = "";
            foreach ($findings as $index => $finding) {
                $num = $index + 1;
                $top5Text .= "{$num}. {$finding['title']}\n";
                $top5Text .= "   Risk Score: {$finding['risk_score']} (L:{$finding['likelihood']} × I:{$finding['impact']})\n";
                $top5Text .= "   NIST Function: {$finding['nist_function']}\n";
                $top5Text .= "   Description: {$finding['description']}\n\n";
            }
            
            // Prepare audit data for AI
            $auditData = [
                'organization_name' => $audit['organization_name'],
                'industry' => $audit['industry'],
                'exposure_level' => $audit['exposure_level'] ?? 'Unknown',
                'final_risk_level' => $audit['final_risk_level'] ?? 'Unknown',
                'compliance_percentage' => $audit['compliance_percentage'] ?? 0,
                'top_5_risks' => $top5Text
            ];
            
            // Generate report via AI
            $result = generateAuditReport($auditData);
            
            if (!$result['success']) {
                throw new Exception($result['message']);
            }
            
            $reportContent = $result['data']['response'];
            $tokensUsed = $result['data']['tokens_used'];
            
            // Save generated report to database
            $stmt = $pdo->prepare("
                INSERT INTO ai_reports (audit_session_id, report_type, report_content, tokens_used, model_used) 
                VALUES (?, 'executive_summary', ?, ?, ?)
            ");
            $stmt->execute([$auditId, $reportContent, $tokensUsed, OPENAI_MODEL]);
            
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
                'tokens_used' => $tokensUsed
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
            $result = processChatbotQuestion($question);
            
            if (!$result['success']) {
                throw new Exception($result['message']);
            }
            
            $answer = $result['data']['response'];
            $tokensUsed = $result['data']['tokens_used'];
            
            // Optional: Save chat history
            $stmt = $pdo->prepare("
                INSERT INTO chatbot_history (user_id, question, answer, tokens_used, model_used) 
                VALUES (?, ?, ?, ?, ?)
            ");
            $stmt->execute([$userId, $question, $answer, $tokensUsed, OPENAI_MODEL]);
            
            echo json_encode([
                'success' => true,
                'answer' => $answer,
                'tokens_used' => $tokensUsed
            ]);
            break;
            
        case 'get_report':
            // Get saved AI report
            $reportId = intval($_GET['report_id']);
            
            $stmt = $pdo->prepare("
                SELECT r.*, a.organization_id, o.user_id
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
            // List all reports for an audit session
            $auditId = intval($_GET['audit_id']);
            
            // Verify ownership
            $stmt = $pdo->prepare("
                SELECT a.id
                FROM audit_sessions a 
                JOIN organizations o ON a.organization_id = o.id 
                WHERE a.id = ? AND o.user_id = ?
            ");
            $stmt->execute([$auditId, $userId]);
            
            if (!$stmt->fetch()) {
                throw new Exception('Audit session not found or access denied');
            }
            
            // Get reports
            $stmt = $pdo->prepare("
                SELECT id, report_type, created_at, tokens_used, model_used
                FROM ai_reports 
                WHERE audit_session_id = ? 
                ORDER BY created_at DESC
            ");
            $stmt->execute([$auditId]);
            $reports = $stmt->fetchAll();
            
            echo json_encode(['success' => true, 'data' => $reports]);
            break;
            
        case 'test':
            // Test AI API connection
            $testResult = callOpenAI(
                "You are a test assistant.",
                "Respond with: 'API connection successful'",
                50
            );
            
            echo json_encode($testResult);
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
