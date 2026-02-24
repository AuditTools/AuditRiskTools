<?php
/**
 * SRM-Audit - Forgot Password
 * Allows users to request password reset
 */
session_start();
require_once 'functions/db.php';

// If already logged in, redirect to dashboard
if (isset($_SESSION['user_id'])) {
    header('Location: dashboard.php');
    exit();
}

$error = '';
$success = '';
$step = 'request'; // request, verify, reset

// Check if token is provided (coming from email link)
if (isset($_GET['token']) && !empty($_GET['token'])) {
    $step = 'reset';
    $token = $_GET['token'];
    
    // Verify token validity
    $stmt = $pdo->prepare("SELECT user_id, expires_at FROM password_reset_tokens 
                          WHERE token = ? AND used = 0 AND expires_at > NOW()");
    $stmt->execute([$token]);
    $tokenData = $stmt->fetch();
    
    if (!$tokenData) {
        $error = 'Invalid or expired reset token. Please request a new password reset.';
        $step = 'request';
    }
}

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (isset($_POST['action'])) {
        if ($_POST['action'] == 'request_reset') {
            // Step 1: Request password reset
            $email = filter_var(trim($_POST['email']), FILTER_VALIDATE_EMAIL);
            
            if (!$email) {
                $error = 'Please enter a valid email address.';
            } else {
                // Check if user exists
                $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
                $stmt->execute([$email]);
                $user = $stmt->fetch();
                
                if ($user) {
                    // Generate reset token
                    $resetToken = bin2hex(random_bytes(32));
                    $expiresAt = date('Y-m-d H:i:s', strtotime('+1 hour'));
                    $ipAddress = $_SERVER['REMOTE_ADDR'];
                    $userAgent = $_SERVER['HTTP_USER_AGENT'];
                    
                    // Store token
                    $stmt = $pdo->prepare("INSERT INTO password_reset_tokens 
                                          (user_id, token, expires_at, ip_address, user_agent) 
                                          VALUES (?, ?, ?, ?, ?)");
                    $stmt->execute([$user['id'], $resetToken, $expiresAt, $ipAddress, $userAgent]);
                    
                    // In production, send email here
                    // For now, display the link (development only)
                    $resetLink = "http://" . $_SERVER['HTTP_HOST'] . dirname($_SERVER['PHP_SELF']) . "/forgot_pw.php?token=" . $resetToken;
                    
                    $success = "Password reset link has been generated. <br><br>
                               <strong>Reset Link:</strong><br>
                               <a href='{$resetLink}' class='btn btn-primary btn-sm mt-2'>Click here to reset password</a>";
                } else {
                    // Don't reveal if email exists (security best practice)
                    $success = "If the email exists in our system, a password reset link has been sent.";
                }
            }
        } elseif ($_POST['action'] == 'reset_password') {
            // Step 2: Reset password with token
            $token = $_POST['token'];
            $newPassword = $_POST['new_password'];
            $confirmPassword = $_POST['confirm_password'];
            
            if (empty($newPassword) || empty($confirmPassword)) {
                $error = 'Please fill in all fields.';
            } elseif ($newPassword !== $confirmPassword) {
                $error = 'Passwords do not match.';
            } elseif (strlen($newPassword) < 8) {
                $error = 'Password must be at least 8 characters long.';
            } else {
                // Verify token again
                $stmt = $pdo->prepare("SELECT user_id FROM password_reset_tokens 
                                      WHERE token = ? AND used = 0 AND expires_at > NOW()");
                $stmt->execute([$token]);
                $tokenData = $stmt->fetch();
                
                if ($tokenData) {
                    // Update password
                    $passwordHash = password_hash($newPassword, PASSWORD_DEFAULT);
                    $stmt = $pdo->prepare("UPDATE users SET password_hash = ?, updated_at = NOW() WHERE id = ?");
                    $stmt->execute([$passwordHash, $tokenData['user_id']]);
                    
                    // Mark token as used
                    $stmt = $pdo->prepare("UPDATE password_reset_tokens SET used = 1 WHERE token = ?");
                    $stmt->execute([$token]);
                    
                    $success = 'Password has been reset successfully. You can now login with your new password.';
                    $step = 'complete';
                } else {
                    $error = 'Invalid or expired token. Please request a new password reset.';
                    $step = 'request';
                }
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forgot Password - SRM-Audit</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .forgot-card {
            max-width: 500px;
            width: 100%;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
        }
        .card-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card forgot-card">
            <div class="card-header text-center py-4">
                <h3><i class="fas fa-key"></i> Password Reset</h3>
                <p class="mb-0 small">SRM-Audit System</p>
            </div>
            <div class="card-body p-4">
                <?php if (!empty($error)): ?>
                    <div class="alert alert-danger">
                        <i class="fas fa-exclamation-circle"></i> <?php echo htmlspecialchars($error); ?>
                    </div>
                <?php endif; ?>
                
                <?php if (!empty($success)): ?>
                    <div class="alert alert-success">
                        <i class="fas fa-check-circle"></i> <?php echo $success; ?>
                    </div>
                <?php endif; ?>

                <?php if ($step == 'request'): ?>
                    <!-- Step 1: Request Reset -->
                    <p class="text-muted mb-4">Enter your email address and we'll send you a link to reset your password.</p>
                    <form method="POST" action="">
                        <input type="hidden" name="action" value="request_reset">
                        <div class="mb-3">
                            <label class="form-label">Email Address</label>
                            <div class="input-group">
                                <span class="input-group-text"><i class="fas fa-envelope"></i></span>
                                <input type="email" name="email" class="form-control" placeholder="Enter your email" required>
                            </div>
                        </div>
                        <button type="submit" class="btn btn-primary w-100">
                            <i class="fas fa-paper-plane"></i> Send Reset Link
                        </button>
                    </form>

                <?php elseif ($step == 'reset'): ?>
                    <!-- Step 2: Reset Password -->
                    <p class="text-muted mb-4">Enter your new password below.</p>
                    <form method="POST" action="">
                        <input type="hidden" name="action" value="reset_password">
                        <input type="hidden" name="token" value="<?php echo htmlspecialchars($token); ?>">
                        
                        <div class="mb-3">
                            <label class="form-label">New Password</label>
                            <div class="input-group">
                                <span class="input-group-text"><i class="fas fa-lock"></i></span>
                                <input type="password" name="new_password" class="form-control" 
                                       placeholder="Enter new password" minlength="8" required>
                            </div>
                            <small class="text-muted">Minimum 8 characters</small>
                        </div>
                        
                        <div class="mb-3">
                            <label class="form-label">Confirm Password</label>
                            <div class="input-group">
                                <span class="input-group-text"><i class="fas fa-lock"></i></span>
                                <input type="password" name="confirm_password" class="form-control" 
                                       placeholder="Confirm new password" minlength="8" required>
                            </div>
                        </div>
                        
                        <button type="submit" class="btn btn-success w-100">
                            <i class="fas fa-check"></i> Reset Password
                        </button>
                    </form>

                <?php elseif ($step == 'complete'): ?>
                    <!-- Step 3: Complete -->
                    <div class="text-center">
                        <div class="mb-4">
                            <i class="fas fa-check-circle text-success" style="font-size: 4rem;"></i>
                        </div>
                        <a href="login.php" class="btn btn-primary">
                            <i class="fas fa-sign-in-alt"></i> Go to Login
                        </a>
                    </div>
                <?php endif; ?>

                <hr class="my-4">
                <div class="text-center">
                    <a href="login.php" class="text-decoration-none">
                        <i class="fas fa-arrow-left"></i> Back to Login
                    </a>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
