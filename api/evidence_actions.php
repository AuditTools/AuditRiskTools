<?php
/**
 * SRM-Audit - Evidence Upload API
 * Handle evidence file uploads for audit findings
 */
session_start();
require_once '../functions/db.php';
require_once '../functions/auth.php';

header('Content-Type: application/json');

if (!isLoggedIn()) {
    echo json_encode(['success' => false, 'message' => 'Unauthorized']);
    exit();
}

$userId = $_SESSION['user_id'];
$action = $_GET['action'] ?? 'upload';
$uploadDir = '../uploads/evidence/';

// Ensure upload directory exists
if (!is_dir($uploadDir)) {
    mkdir($uploadDir, 0755, true);
}

try {
    switch ($action) {
        case 'upload':
            if (!isset($_FILES['evidence_file'])) {
                throw new Exception('No file provided');
            }

            if (!verifyCSRFToken($_POST['csrf_token'] ?? '')) {
                throw new Exception('Invalid CSRF token');
            }

            $findingId = intval($_POST['finding_id']);
            $auditId = intval($_POST['audit_id']);
            $evidenceType = $_POST['evidence_type'] ?? 'Other';
            $description = trim($_POST['description'] ?? '');
            $role = $_SESSION['user_role'] ?? 'auditor';

            // Role-based access check
            if ($role === 'auditee') {
                // Auditee must be assigned to this audit
                if (!isAuditeeAssigned($pdo, $auditId, $userId)) {
                    throw new Exception('You are not assigned to this audit');
                }
                // Verify finding belongs to this audit
                $stmt = $pdo->prepare("SELECT id FROM findings WHERE id = ? AND audit_id = ?");
                $stmt->execute([$findingId, $auditId]);
                if (!$stmt->fetch()) {
                    throw new Exception('Finding not found in this audit');
                }
            } else {
                // Auditor: verify finding ownership + audit
                $stmt = $pdo->prepare("SELECT f.id FROM findings f
                    JOIN audit_sessions a ON f.audit_id = a.id
                    JOIN organizations o ON a.organization_id = o.id
                    WHERE f.id = ? AND f.audit_id = ? AND o.user_id = ?");
                $stmt->execute([$findingId, $auditId, $userId]);
                if (!$stmt->fetch()) {
                    throw new Exception('Finding not found or access denied');
                }
            }

            // Whitelist allowed MIME types
            $allowedMimes = [
                'image/jpeg', 'image/png', 'image/gif',
                'application/pdf',
                'application/msword',
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                'application/vnd.ms-excel',
                'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                'text/plain',
            ];
            
            // Handle multiple files
            $maxSize = 10 * 1024 * 1024;
            $files = $_FILES['evidence_file'];
            $fileCount = is_array($files['name']) ? count($files['name']) : 1;
            
            $uploadedCount = 0;
            
            for ($i = 0; $i < $fileCount; $i++) {
                $fileName = is_array($files['name']) ? $files['name'][$i] : $files['name'];
                $fileTmp = is_array($files['tmp_name']) ? $files['tmp_name'][$i] : $files['tmp_name'];
                $fileSize = is_array($files['size']) ? $files['size'][$i] : $files['size'];
                $fileError = is_array($files['error']) ? $files['error'][$i] : $files['error'];

                if (empty($fileName)) continue;

                if ($fileError !== UPLOAD_ERR_OK) {
                    continue; // Skip this file
                }

                // Validate file size (max 10MB)
                if ($fileSize > $maxSize) {
                    continue; // Skip this file
                }

                // Validate MIME type
                $mime = mime_content_type($fileTmp);
                if (!in_array($mime, $allowedMimes)) {
                    continue; // Skip this file
                }

                // Generate safe filename
                $ext = pathinfo($fileName, PATHINFO_EXTENSION);
                $storedFilename = 'evidence_' . $findingId . '_' . time() . '_' . bin2hex(random_bytes(4)) . '.' . $ext;
                $filePath = $uploadDir . $storedFilename;

                if (!move_uploaded_file($fileTmp, $filePath)) {
                    continue; // Skip this file
                }

                // Store in database
                $stmt = $pdo->prepare("INSERT INTO audit_evidence
                    (finding_id, audit_id, original_filename, stored_filename, file_path, file_type, file_size, evidence_type, description, uploaded_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
                $stmt->execute([
                    $findingId,
                    $auditId,
                    $fileName,
                    $storedFilename,
                    'uploads/evidence/' . $storedFilename,
                    $mime,
                    $fileSize,
                    $evidenceType,
                    $description,
                    $userId,
                ]);
                
                $uploadedCount++;
            }
            
            if ($uploadedCount === 0) {
                throw new Exception('No files were successfully uploaded');
            }

            echo json_encode([
                'success' => true,
                'message' => $uploadedCount . ' file(s) uploaded successfully',
                'count' => $uploadedCount
            ]);
            break;

        case 'list':
            $findingId = intval($_GET['finding_id']);
            $auditId = intval($_GET['audit_id']);
            $role = $_SESSION['user_role'] ?? 'auditor';

            // Role-based access check
            if ($role === 'auditee') {
                if (!isAuditeeAssigned($pdo, $auditId, $userId)) {
                    throw new Exception('You are not assigned to this audit');
                }
            } else {
                $stmt = $pdo->prepare("SELECT f.id FROM findings f
                    JOIN audit_sessions a ON f.audit_id = a.id
                    JOIN organizations o ON a.organization_id = o.id
                    WHERE f.id = ? AND f.audit_id = ? AND o.user_id = ?");
                $stmt->execute([$findingId, $auditId, $userId]);
                if (!$stmt->fetch()) {
                    throw new Exception('Finding not found or access denied');
                }
            }

            $stmt = $pdo->prepare("SELECT ae.id, ae.original_filename, ae.file_path, ae.file_type, ae.file_size, ae.evidence_type, ae.description, ae.created_at, ae.uploaded_by, ae.evidence_status, ae.review_notes,
                    COALESCE(u.name, 'Unknown') AS uploader_name, COALESCE(u.role, '') AS uploader_role
                FROM audit_evidence ae
                LEFT JOIN users u ON ae.uploaded_by = u.id
                WHERE ae.finding_id = ? AND ae.audit_id = ?
                ORDER BY ae.created_at DESC");
            $stmt->execute([$findingId, $auditId]);
            $evidence = $stmt->fetchAll(PDO::FETCH_ASSOC);

            echo json_encode(['success' => true, 'data' => $evidence]);
            break;

        case 'delete':
            $data = json_decode(file_get_contents('php://input'), true);
            $evidenceId = intval($data['id']);

            if (isset($data['csrf_token']) && !verifyCSRFToken($data['csrf_token'])) {
                throw new Exception('Invalid CSRF token');
            }

            // Verify ownership + get filepath
            $role = $_SESSION['user_role'] ?? 'auditor';
            if ($role === 'auditee') {
                // Auditee can only delete their own uploads
                $stmt = $pdo->prepare("SELECT ae.file_path, ae.finding_id, f.audit_id
                    FROM audit_evidence ae
                    JOIN findings f ON ae.finding_id = f.id
                    WHERE ae.id = ? AND ae.uploaded_by = ?");
                $stmt->execute([$evidenceId, $userId]);
            } else {
                $stmt = $pdo->prepare("SELECT ae.file_path, ae.finding_id, f.audit_id
                    FROM audit_evidence ae
                    JOIN findings f ON ae.finding_id = f.id
                    JOIN audit_sessions a ON f.audit_id = a.id
                    JOIN organizations o ON a.organization_id = o.id
                    WHERE ae.id = ? AND o.user_id = ?");
                $stmt->execute([$evidenceId, $userId]);
            }
            $ev = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$ev) {
                throw new Exception('Evidence not found or access denied');
            }

            // Delete file
            $fullPath = '../' . $ev['file_path'];
            if (file_exists($fullPath)) {
                unlink($fullPath);
            }

            // Delete from DB
            $stmt = $pdo->prepare("DELETE FROM audit_evidence WHERE id = ?");
            $stmt->execute([$evidenceId]);

            echo json_encode(['success' => true, 'message' => 'Evidence deleted']);
            break;

        case 'review':
            // Auditor-only: accept, reject, or request revision for evidence
            $role = $_SESSION['user_role'] ?? 'auditor';
            if ($role !== 'auditor' && $role !== 'admin') {
                throw new Exception('Only auditors can review evidence');
            }

            $data = json_decode(file_get_contents('php://input'), true);
            $evidenceId = intval($data['evidence_id'] ?? 0);
            $newStatus = $data['evidence_status'] ?? '';
            $reviewNotes = trim($data['review_notes'] ?? '');

            if (isset($data['csrf_token']) && !verifyCSRFToken($data['csrf_token'])) {
                throw new Exception('Invalid CSRF token');
            }

            $allowedStatuses = ['Pending Review', 'Accepted', 'Rejected', 'Needs Revision'];
            if (!in_array($newStatus, $allowedStatuses)) {
                throw new Exception('Invalid evidence status');
            }

            // Verify auditor owns the org for this evidence
            $stmt = $pdo->prepare("SELECT ae.id FROM audit_evidence ae
                JOIN findings f ON ae.finding_id = f.id
                JOIN audit_sessions a ON f.audit_id = a.id
                JOIN organizations o ON a.organization_id = o.id
                WHERE ae.id = ? AND o.user_id = ?");
            $stmt->execute([$evidenceId, $userId]);
            if (!$stmt->fetch()) {
                throw new Exception('Evidence not found or access denied');
            }

            $stmt = $pdo->prepare("UPDATE audit_evidence SET evidence_status = ?, review_notes = ?, reviewed_by = ?, reviewed_at = NOW() WHERE id = ?");
            $stmt->execute([$newStatus, $reviewNotes, $userId, $evidenceId]);

            // Notify the uploader about the review result
            $stmtUploader = $pdo->prepare("SELECT ae.uploaded_by, ae.original_filename, f.audit_id FROM audit_evidence ae JOIN findings f ON ae.finding_id = f.id WHERE ae.id = ?");
            $stmtUploader->execute([$evidenceId]);
            $uploaderInfo = $stmtUploader->fetch(PDO::FETCH_ASSOC);
            if ($uploaderInfo && $uploaderInfo['uploaded_by'] && $uploaderInfo['uploaded_by'] != $userId) {
                $statusMsg = $newStatus === 'Accepted' ? 'Your evidence has been accepted' :
                            ($newStatus === 'Rejected' ? 'Your evidence was rejected' :
                             'Your evidence needs revision');
                $msg = $statusMsg . ': "' . $uploaderInfo['original_filename'] . '"';
                if (!empty($reviewNotes)) $msg .= ' — Note: ' . $reviewNotes;
                createNotification($pdo, $uploaderInfo['uploaded_by'], $uploaderInfo['audit_id'], 'evidence_reviewed', $msg);
            }

            echo json_encode(['success' => true, 'message' => 'Evidence marked as ' . $newStatus]);
            break;

        default:
            throw new Exception('Invalid action');
    }
} catch (Exception $e) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => $e->getMessage()]);
}

function getUploadErrorMessage($errorCode) {
    $errors = [
        UPLOAD_ERR_OK => 'No error',
        UPLOAD_ERR_INI_SIZE => 'File exceeds upload_max_filesize',
        UPLOAD_ERR_FORM_SIZE => 'File exceeds max_file_size',
        UPLOAD_ERR_PARTIAL => 'File only partially uploaded',
        UPLOAD_ERR_NO_FILE => 'No file uploaded',
        UPLOAD_ERR_NO_TMP_DIR => 'Missing temp directory',
        UPLOAD_ERR_CANT_WRITE => 'Cannot write to disk',
        UPLOAD_ERR_EXTENSION => 'Extension blocked upload',
    ];
    return $errors[$errorCode] ?? 'Unknown error';
}
?>
