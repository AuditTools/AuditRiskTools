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
function loginUser($userId, $userEmail, $userName) {
    // Regenerate session ID to prevent session fixation attacks
    session_regenerate_id(true);
    
    // Set session variables
    $_SESSION['user_id'] = $userId;
    $_SESSION['user_email'] = $userEmail;
    $_SESSION['user_name'] = $userName;
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
?>
