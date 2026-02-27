<?php
/**
 * SRM-Audit - Authentication Functions
 * Secure session management and authentication utilities
 */

/**
 * Check if user is logged in
 */
function isLoggedIn() {
    return isset($_SESSION['user_id']) && isset($_SESSION['user_email']);
}

/**
 * Require user to be logged in (redirect if not)
 */
function requireLogin() {
    if (!isLoggedIn()) {
        header('Location: login.php?redirect=' . urlencode($_SERVER['REQUEST_URI']));
        exit();
    }
}

/**
 * Login user with session regeneration (prevents session fixation)
 */
function loginUser($userId, $userEmail, $userName, $userRole = 'auditor') {
    // Regenerate session ID to prevent session fixation attacks
    session_regenerate_id(true);
    
    // Set session variables
    $_SESSION['user_id'] = $userId;
    $_SESSION['user_email'] = $userEmail;
    $_SESSION['user_name'] = $userName;
    $_SESSION['user_role'] = $userRole;
    $_SESSION['login_time'] = time();
    $_SESSION['last_activity'] = time();
    
    // Set session security settings
    setSessionSecuritySettings();
    
    return true;
}

/**
 * Logout user securely
 */
function logoutUser() {
    // Unset all session variables
    $_SESSION = array();
    
    // Destroy session cookie
    if (isset($_COOKIE[session_name()])) {
        setcookie(session_name(), '', time() - 3600, '/');
    }
    
    // Destroy session
    session_destroy();
}

/**
 * Check session timeout (30 minutes of inactivity)
 */
function checkSessionTimeout($timeout = 1800) {
    if (isset($_SESSION['last_activity'])) {
        $elapsed = time() - $_SESSION['last_activity'];
        
        if ($elapsed > $timeout) {
            logoutUser();
            header('Location: login.php?session_expired=1');
            exit();
        }
    }
    
    // Update last activity time
    $_SESSION['last_activity'] = time();
}

/**
 * Set secure session settings
 */
function setSessionSecuritySettings() {
    // Prevent session hijacking
    if (!isset($_SESSION['user_ip'])) {
        $_SESSION['user_ip'] = $_SERVER['REMOTE_ADDR'];
    }
    
    if (!isset($_SESSION['user_agent'])) {
        $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
    }
    
    // Validate session
    if ($_SESSION['user_ip'] !== $_SERVER['REMOTE_ADDR'] || 
        $_SESSION['user_agent'] !== $_SERVER['HTTP_USER_AGENT']) {
        // Potential session hijacking detected
        logoutUser();
        header('Location: login.php?session_invalid=1');
        exit();
    }
}

/**
 * Initialize secure session
 */
function initSecureSession() {
    // Set secure session parameters
    ini_set('session.cookie_httponly', 1); // Prevent JavaScript access to session cookie
    ini_set('session.use_only_cookies', 1); // Use only cookies for session ID
    ini_set('session.cookie_secure', 0); // Set to 1 if using HTTPS
    ini_set('session.cookie_samesite', 'Strict'); // CSRF protection
    
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    
    // Check timeout if user is logged in
    if (isLoggedIn()) {
        checkSessionTimeout();
        setSessionSecuritySettings();
    }
}

/**
 * Generate CSRF token
 */
function generateCSRFToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Verify CSRF token
 */
function verifyCSRFToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

/**
 * Validate CSRF token from incoming request.
 * Supports POST form token and X-CSRF-Token header.
 */
function isValidCSRFRequest() {
    $token = $_POST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    return verifyCSRFToken($token);
}

/**
 * Get CSRF token HTML input
 */
function csrfTokenInput() {
    return '<input type="hidden" name="csrf_token" value="' . htmlspecialchars(generateCSRFToken()) . '">';
}

/**
 * Sanitize output to prevent XSS
 */
function e($string) {
    return htmlspecialchars($string ?? '', ENT_QUOTES, 'UTF-8');
}

/**
 * Sanitize input
 */
function sanitizeInput($input) {
    return trim(strip_tags($input));
}

/**
 * Hash password securely
 */
function hashPassword($password) {
    return password_hash($password, PASSWORD_DEFAULT);
}

/**
 * Verify password
 */
function verifyPassword($password, $hash) {
    return password_verify($password, $hash);
}

/**
 * Generate random token
 */
function generateToken($length = 32) {
    return bin2hex(random_bytes($length));
}

/**
 * Rate limiting check
 */
function checkRateLimit($identifier, $maxAttempts = 5, $timeWindow = 300) {
    $key = 'rate_limit_' . $identifier;
    
    if (!isset($_SESSION[$key])) {
        $_SESSION[$key] = [
            'attempts' => 0,
            'timestamp' => time()
        ];
    }
    
    $elapsed = time() - $_SESSION[$key]['timestamp'];
    
    // Reset after time window
    if ($elapsed >= $timeWindow) {
        $_SESSION[$key] = [
            'attempts' => 1,
            'timestamp' => time()
        ];
        return true;
    }
    
    // Check limit
    if ($_SESSION[$key]['attempts'] >= $maxAttempts) {
        return false;
    }
    
    $_SESSION[$key]['attempts']++;
    return true;
}

/**
 * Log security event
 */
function logSecurityEvent($pdo, $userId, $event, $details = '') {
    try {
        $stmt = $pdo->prepare("INSERT INTO audit_logs 
                              (user_id, action, table_name, old_values, ip_address, user_agent) 
                              VALUES (?, ?, 'security', ?, ?, ?)");
        $stmt->execute([
            $userId,
            $event,
            $details,
            $_SERVER['REMOTE_ADDR'],
            $_SERVER['HTTP_USER_AGENT']
        ]);
    } catch (Exception $e) {
        error_log("Failed to log security event: " . $e->getMessage());
    }
}

/**
 * Get user role
 */
function getUserRole($userId = null) {
    global $pdo;
    
    if ($userId === null) {
        $userId = $_SESSION['user_id'] ?? null;
    }
    
    if (!$userId) {
        return null;
    }
    
    $stmt = $pdo->prepare("SELECT role FROM users WHERE id = ?");
    $stmt->execute([$userId]);
    $result = $stmt->fetch(PDO::FETCH_ASSOC);
    
    return $result['role'] ?? null;
}

/**
 * Check if user has specific role
 */
function hasRole($requiredRole, $userId = null) {
    $userRole = getUserRole($userId);
    return $userRole === $requiredRole;
}

/**
 * Check if user is admin
 */
function isAdmin($userId = null) {
    return hasRole('admin', $userId);
}

/**
 * Check if user is auditor
 */
function isAuditor($userId = null) {
    return hasRole('auditor', $userId);
}

/**
 * Check if user is auditee
 */
function isAuditee($userId = null) {
    return hasRole('auditee', $userId);
}

/**
 * Require admin role (redirect if not)
 */
function requireAdmin() {
    if (!isLoggedIn()) {
        header('Location: login.php');
        exit();
    }
    if (!isAdmin()) {
        http_response_code(403);
        die('Access denied. Admin role required.');
    }
}

/**
 * Require auditor role (redirect if not)
 */
function requireAuditor() {
    if (!isLoggedIn()) {
        header('Location: login.php');
        exit();
    }
    if (!isAuditor() && !isAdmin()) {
        header('Location: dashboard.php?error=access_denied');
        exit();
    }
}

/**
 * Check if current session user can write (admin or auditor).
 * For use in API endpoints — returns false for auditee.
 */
function canWrite() {
    $role = $_SESSION['user_role'] ?? 'auditee';
    return in_array($role, ['admin', 'auditor'], true);
}

/**
 * Block write operations for auditee role (API JSON response).
 * Call this at the top of any add/update/delete action.
 */
function requireWriteAccess() {
    if (!canWrite()) {
        header('Content-Type: application/json');
        echo json_encode(['success' => false, 'message' => 'Access denied. Auditee role is read-only.']);
        exit();
    }
}

/**
 * Check if auditee is assigned to a specific audit session.
 */
function isAuditeeAssigned($pdo, $auditId, $userId = null) {
    if ($userId === null) {
        $userId = $_SESSION['user_id'] ?? 0;
    }
    $stmt = $pdo->prepare("SELECT id FROM audit_auditees WHERE audit_id = ? AND auditee_user_id = ?");
    $stmt->execute([$auditId, $userId]);
    return (bool)$stmt->fetch();
}

/**
 * Get all audit IDs assigned to an auditee.
 */
function getAuditeeAssignedAudits($pdo, $userId = null) {
    if ($userId === null) {
        $userId = $_SESSION['user_id'] ?? 0;
    }
    $stmt = $pdo->prepare("SELECT audit_id FROM audit_auditees WHERE auditee_user_id = ?");
    $stmt->execute([$userId]);
    return $stmt->fetchAll(PDO::FETCH_COLUMN);
}

/**
 * Verify audit access for any role:
 * - Admin/Auditor: must own org
 * - Auditee: must be assigned
 * Returns true/false.
 */
function canAccessAudit($pdo, $auditId, $userId = null) {
    if ($userId === null) {
        $userId = $_SESSION['user_id'] ?? 0;
    }
    $role = $_SESSION['user_role'] ?? 'auditor';

    if ($role === 'auditee') {
        return isAuditeeAssigned($pdo, $auditId, $userId);
    }

    // Admin/Auditor: verify through org ownership
    $stmt = $pdo->prepare("SELECT a.id FROM audit_sessions a 
                           JOIN organizations o ON a.organization_id = o.id 
                           WHERE a.id = ? AND o.user_id = ?");
    $stmt->execute([$auditId, $userId]);
    return (bool)$stmt->fetch();
}

/**
 * Create a notification for a user.
 */
function createNotification($pdo, $userId, $auditId, $type, $message) {
    try {
        $stmt = $pdo->prepare("INSERT INTO notifications (user_id, audit_id, type, message) VALUES (?, ?, ?, ?)");
        $stmt->execute([$userId, $auditId, $type, $message]);
    } catch (Exception $e) {
        error_log("Failed to create notification: " . $e->getMessage());
    }
}

/**
 * Get unread notifications count for a user.
 */
function getUnreadNotificationCount($pdo, $userId = null) {
    if ($userId === null) {
        $userId = $_SESSION['user_id'] ?? 0;
    }
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0");
    $stmt->execute([$userId]);
    return (int)$stmt->fetchColumn();
}

/**
 * Get notifications for a user.
 */
function getNotifications($pdo, $userId = null, $limit = 20) {
    if ($userId === null) {
        $userId = $_SESSION['user_id'] ?? 0;
    }
    $stmt = $pdo->prepare("SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT ?");
    $stmt->execute([$userId, $limit]);
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

/**
 * Mark specific notifications as read.
 */
function markNotificationsRead($pdo, $notificationIds, $userId) {
    if (empty($notificationIds)) return;
    $placeholders = implode(',', array_fill(0, count($notificationIds), '?'));
    $params = array_merge($notificationIds, [$userId]);
    $stmt = $pdo->prepare("UPDATE notifications SET is_read = 1 WHERE id IN ($placeholders) AND user_id = ?");
    $stmt->execute($params);
}

/**
 * Mark ALL notifications as read for a user.
 */
function markAllNotificationsRead($pdo, $userId) {
    $stmt = $pdo->prepare("UPDATE notifications SET is_read = 1 WHERE user_id = ? AND is_read = 0");
    $stmt->execute([$userId]);
}
?>
