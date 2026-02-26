<?php
/**
 * SRM-Audit - Authentication Actions API
 * Handle login, registration, and authentication
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

$action = $_GET['action'] ?? '';

try {
    switch ($action) {
        case 'login':
            // Handle login
            $email = filter_var(trim($_POST['email']), FILTER_VALIDATE_EMAIL);
            $password = $_POST['password'] ?? '';
            
            if (!$email || empty($password)) {
                throw new Exception('Invalid email or password');
            }
            
            // Rate limiting: max 5 login attempts per 5 minutes
            if (!checkRateLimit('login_' . $email, 5, 300)) {
                throw new Exception('Too many login attempts. Please try again later.');
            }
            
            // Get user from database (include role)
            $stmt = $pdo->prepare("SELECT id, name, email, password_hash, role, is_active, failed_login_attempts 
                                  FROM users WHERE email = ?");
            $stmt->execute([$email]);
            $user = $stmt->fetch();
            
            if (!$user) {
                // Don't reveal if user exists (security best practice)
                throw new Exception('Invalid email or password');
            }
            
            // Check if account is active
            if (!$user['is_active']) {
                throw new Exception('Account is disabled. Please contact administrator.');
            }
            
            // Check if account is locked (after 5 failed attempts)
            if ($user['failed_login_attempts'] >= 5) {
                throw new Exception('Account is locked due to multiple failed login attempts. Please reset your password.');
            }
            
            // Verify password
            if (!password_verify($password, $user['password_hash'])) {
                // Increment failed attempts
                $stmt = $pdo->prepare("UPDATE users 
                                      SET failed_login_attempts = failed_login_attempts + 1 
                                      WHERE id = ?");
                $stmt->execute([$user['id']]);
                
                logSecurityEvent($pdo, $user['id'], 'LOGIN_FAILED', 'Invalid password');
                
                throw new Exception('Invalid email or password');
            }
            
            // Successful login - reset failed attempts
            $stmt = $pdo->prepare("UPDATE users 
                                  SET failed_login_attempts = 0, last_login = NOW() 
                                  WHERE id = ?");
            $stmt->execute([$user['id']]);
            
            // Set session with security measures (include role)
            loginUser($user['id'], $user['email'], $user['name'], $user['role'] ?? 'auditor');
            
            logSecurityEvent($pdo, $user['id'], 'LOGIN_SUCCESS', 'User logged in successfully');
            
            echo json_encode([
                'success' => true,
                'message' => 'Login successful',
                'role' => $user['role'] ?? 'auditor',
                'redirect' => 'dashboard.php'
            ]);
            break;
            
        case 'register':
            // Handle registration
            $name = sanitizeInput($_POST['name'] ?? '');
            $email = filter_var(trim($_POST['email']), FILTER_VALIDATE_EMAIL);
            $password = $_POST['password'] ?? '';
            $confirmPassword = $_POST['confirm_password'] ?? '';
            
            // Validation
            if (empty($name) || !$email) {
                throw new Exception('Please provide valid name and email');
            }
            
            if (strlen($password) < 8) {
                throw new Exception('Password must be at least 8 characters long');
            }
            
            if ($password !== $confirmPassword) {
                throw new Exception('Passwords do not match');
            }
            
            // Check if email already exists
            $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
            $stmt->execute([$email]);
            if ($stmt->fetch()) {
                throw new Exception('Email already registered');
            }
            
            // Hash password
            $passwordHash = password_hash($password, PASSWORD_DEFAULT);
            
            // Self-registration is auditor-only.
            // Auditee accounts are created by auditors via audit management.
            // Admin accounts are created by existing admins via User Management.
            $role = 'auditor';
            
            // Insert user with role
            $stmt = $pdo->prepare("INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)");
            $stmt->execute([$name, $email, $passwordHash, $role]);
            
            $userId = $pdo->lastInsertId();
            
            // Auto-login after registration
            loginUser($userId, $email, $name, $role);
            
            logSecurityEvent($pdo, $userId, 'USER_REGISTERED', 'New user registered');
            
            echo json_encode([
                'success' => true,
                'message' => 'Registration successful',
                'redirect' => 'dashboard.php'
            ]);
            break;
            
        case 'logout':
            // Handle logout
            if (isLoggedIn()) {
                $userId = $_SESSION['user_id'];
                logSecurityEvent($pdo, $userId, 'LOGOUT', 'User logged out');
                logoutUser();
            }
            
            echo json_encode([
                'success' => true,
                'message' => 'Logged out successfully',
                'redirect' => 'login.php'
            ]);
            break;
            
        case 'check_session':
            // Check if session is valid
            if (isLoggedIn()) {
                echo json_encode([
                    'success' => true,
                    'logged_in' => true,
                    'user_name' => $_SESSION['user_name'],
                    'user_email' => $_SESSION['user_email']
                ]);
            } else {
                echo json_encode([
                    'success' => true,
                    'logged_in' => false
                ]);
            }
            break;
            
        case 'change_password':
            // Change password (requires authentication)
            if (!isLoggedIn()) {
                throw new Exception('Unauthorized');
            }
            
            $userId = $_SESSION['user_id'];
            $currentPassword = $_POST['current_password'] ?? '';
            $newPassword = $_POST['new_password'] ?? '';
            $confirmPassword = $_POST['confirm_password'] ?? '';
            
            if (empty($currentPassword) || empty($newPassword) || empty($confirmPassword)) {
                throw new Exception('All fields are required');
            }
            
            if ($newPassword !== $confirmPassword) {
                throw new Exception('New passwords do not match');
            }
            
            if (strlen($newPassword) < 8) {
                throw new Exception('Password must be at least 8 characters long');
            }
            
            // Verify current password
            $stmt = $pdo->prepare("SELECT password_hash FROM users WHERE id = ?");
            $stmt->execute([$userId]);
            $user = $stmt->fetch();
            
            if (!password_verify($currentPassword, $user['password_hash'])) {
                throw new Exception('Current password is incorrect');
            }
            
            // Update password
            $newPasswordHash = password_hash($newPassword, PASSWORD_DEFAULT);
            $stmt = $pdo->prepare("UPDATE users SET password_hash = ?, updated_at = NOW() WHERE id = ?");
            $stmt->execute([$newPasswordHash, $userId]);
            
            logSecurityEvent($pdo, $userId, 'PASSWORD_CHANGED', 'User changed password');
            
            echo json_encode([
                'success' => true,
                'message' => 'Password changed successfully'
            ]);
            break;
            
        default:
            throw new Exception('Invalid action');
    }
    
} catch (Exception $e) {
    echo json_encode([
        'success' => false,
        'message' => $e->getMessage()
    ]);
}
?>
