<?php
/**
 * SRM-Audit - Forgot Password
 * Allows users to request password reset
 */
session_start();
require_once 'functions/db.php';
require_once 'functions/auth.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception as MailException;

function sendPasswordResetEmail($email, $resetLink) {
    $fromAddress = MAIL_FROM_ADDRESS;
    if (!filter_var($fromAddress, FILTER_VALIDATE_EMAIL)) {
        $fromAddress = 'no-reply@localhost';
    }

    $subject = 'SRM-Audit Password Reset';
    $message = "Hello,\n\n"
             . "We received a request to reset your SRM-Audit password.\n"
             . "Use the link below to set a new password (valid for 1 hour):\n\n"
             . $resetLink . "\n\n"
             . "If you did not request this, you can ignore this email.\n";

    $canUseSmtp = MAIL_DRIVER === 'smtp' && SMTP_HOST !== '' && SMTP_USER !== '' && SMTP_PASS !== '';

    if ($canUseSmtp) {
        try {
            $mailer = new PHPMailer(true);
            $mailer->isSMTP();
            $mailer->Host = SMTP_HOST;
            $mailer->Port = SMTP_PORT > 0 ? SMTP_PORT : 587;
            $mailer->SMTPAuth = true;
            $mailer->Username = SMTP_USER;
            $mailer->Password = SMTP_PASS;

            if (strtolower(SMTP_ENCRYPTION) === 'ssl') {
                $mailer->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
            } elseif (strtolower(SMTP_ENCRYPTION) === 'none') {
                $mailer->SMTPSecure = false;
                $mailer->SMTPAutoTLS = false;
            } else {
                $mailer->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
            }

            $mailer->setFrom($fromAddress, MAIL_FROM_NAME);
            $mailer->addAddress($email);
            $mailer->Subject = $subject;
            $mailer->Body = $message;
            $mailer->isHTML(false);
            $mailer->send();

            return true;
        } catch (MailException $e) {
            error_log('SMTP password reset email failed for ' . $email . ': ' . $e->getMessage());
        }
    }

    $headers = [
        'MIME-Version: 1.0',
        'Content-Type: text/plain; charset=UTF-8',
        'From: ' . MAIL_FROM_NAME . ' <' . $fromAddress . '>',
        'Reply-To: ' . $fromAddress
    ];

    $nativeSent = @mail($email, $subject, $message, implode("\r\n", $headers));
    if (!$nativeSent) {
        error_log('Native password reset email failed for: ' . $email);
    }

    return $nativeSent;
}

function logPasswordResetEvent($pdo, $userId, $action, array $details = []) {
    try {
        $stmt = $pdo->prepare("INSERT INTO audit_logs (user_id, action, table_name, new_values, ip_address, user_agent) VALUES (?, ?, 'password_reset', ?, ?, ?)");
        $stmt->execute([
            $userId,
            $action,
            json_encode($details, JSON_UNESCAPED_SLASHES),
            $_SERVER['REMOTE_ADDR'] ?? null,
            $_SERVER['HTTP_USER_AGENT'] ?? null,
        ]);
    } catch (Exception $e) {
        error_log('Failed to log password reset event: ' . $e->getMessage());
    }
}

function countRecentResetRequestsByIp($pdo, $ipAddress, $minutes = 60) {
    if (!$ipAddress) {
        return 0;
    }

    $stmt = $pdo->prepare("SELECT COUNT(*) FROM password_reset_tokens WHERE ip_address = ? AND created_at >= (NOW() - INTERVAL ? MINUTE)");
    $stmt->execute([$ipAddress, intval($minutes)]);
    return intval($stmt->fetchColumn());
}

function countRecentResetRequestsByUser($pdo, $userId, $minutes = 60) {
    if (!$userId) {
        return 0;
    }

    $stmt = $pdo->prepare("SELECT COUNT(*) FROM password_reset_tokens WHERE user_id = ? AND created_at >= (NOW() - INTERVAL ? MINUTE)");
    $stmt->execute([intval($userId), intval($minutes)]);
    return intval($stmt->fetchColumn());
}

function buildResetLink($token) {
    $appUrl = rtrim(APP_URL, '/');
    if (!preg_match('/^https?:\/\//i', $appUrl)) {
        $appUrl = 'http://' . $appUrl;
    }

    return $appUrl . '/forgot_pw.php?token=' . urlencode($token);
}

// If already logged in, redirect to dashboard
if (isset($_SESSION['user_id'])) {
    header('Location: dashboard.php');
    exit();
}

$error = '';
$success = '';
$warning = '';
$step = 'request'; // request, verify, reset
$isDevelopment = (APP_ENV === 'development' && APP_DEBUG);

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
    if (!isValidCSRFRequest()) {
        $error = 'Invalid request token. Please refresh and try again.';
    } elseif (isset($_POST['action'])) {
        if ($_POST['action'] == 'request_reset') {
            // Step 1: Request password reset
            $email = filter_var(trim($_POST['email']), FILTER_VALIDATE_EMAIL);
            $requestIp = $_SERVER['REMOTE_ADDR'] ?? null;
            $requestUserAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';

            $rateWindowMinutes = $isDevelopment ? 10 : 60;
            $maxIpRequestsInWindow = $isDevelopment ? 20 : 10;
            $maxUserRequestsInWindow = $isDevelopment ? 5 : 3;

            // Throttle by IP to reduce abuse
            if (countRecentResetRequestsByIp($pdo, $requestIp, $rateWindowMinutes) >= $maxIpRequestsInWindow) {
                logPasswordResetEvent($pdo, null, 'PASSWORD_RESET_RATE_LIMITED_IP', [
                    'email' => $email ?: null,
                    'ip' => $requestIp,
                    'user_agent' => $requestUserAgent,
                ]);
                $warning = 'Too many reset requests from this device. Please wait a few minutes and try again.';
                $success = "If the email exists in our system, a password reset link has been sent.";
                goto render_done;
            }
            
            if (!$email) {
                $error = 'Please enter a valid email address.';
            } else {
                // Check if user exists
                $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
                $stmt->execute([$email]);
                $user = $stmt->fetch();
                
                if ($user) {
                    // Throttle by user/email
                    if (countRecentResetRequestsByUser($pdo, intval($user['id']), $rateWindowMinutes) >= $maxUserRequestsInWindow) {
                        logPasswordResetEvent($pdo, intval($user['id']), 'PASSWORD_RESET_RATE_LIMITED_USER', [
                            'email' => $email,
                            'ip' => $requestIp,
                            'user_agent' => $requestUserAgent,
                        ]);
                        $warning = 'This email has requested reset too many times. Please wait a few minutes before trying again.';
                        $success = "If the email exists in our system, a password reset link has been sent.";
                        goto render_done;
                    }

                    // Generate reset token
                    $resetToken = bin2hex(random_bytes(32));
                    $expiresAt = date('Y-m-d H:i:s', strtotime('+1 hour'));
                    $ipAddress = $requestIp;
                    $userAgent = $requestUserAgent;
                    
                    // Store token
                    $stmt = $pdo->prepare("INSERT INTO password_reset_tokens 
                                          (user_id, token, expires_at, ip_address, user_agent) 
                                          VALUES (?, ?, ?, ?, ?)");
                    $stmt->execute([$user['id'], $resetToken, $expiresAt, $ipAddress, $userAgent]);

                    logPasswordResetEvent($pdo, intval($user['id']), 'PASSWORD_RESET_TOKEN_CREATED', [
                        'email' => $email,
                        'ip' => $ipAddress,
                        'expires_at' => $expiresAt,
                    ]);
                    
                    // In production, send email here
                    // Development: show direct reset link
                    // Production: send reset link through email
                    $resetLink = buildResetLink($resetToken); // absolute, for email
                    $devResetLink = 'forgot_pw.php?token=' . urlencode($resetToken); // relative, for browser button
                    $mailSent = sendPasswordResetEmail($email, $resetLink);

                    if ($isDevelopment) {
                        if ($mailSent) {
                            logPasswordResetEvent($pdo, intval($user['id']), 'PASSWORD_RESET_EMAIL_SENT', [
                                'channel' => MAIL_DRIVER,
                                'email' => $email,
                                'ip' => $ipAddress,
                            ]);
                            $success = "Password reset email sent. <br><br>
                                       <strong>Dev Reset Link:</strong><br>
                                       <a href='{$devResetLink}' class='btn btn-primary btn-sm mt-2'>Click here to reset password</a>";
                        } else {
                            logPasswordResetEvent($pdo, intval($user['id']), 'PASSWORD_RESET_EMAIL_FAILED', [
                                'channel' => MAIL_DRIVER,
                                'email' => $email,
                                'ip' => $ipAddress,
                            ]);
                            $success = "Password reset email is not sent yet (check SMTP settings). <br><br>
                                       <strong>Dev Reset Link:</strong><br>
                                       <a href='{$devResetLink}' class='btn btn-primary btn-sm mt-2'>Click here to reset password</a>";
                        }
                    } else {
                        if (!$mailSent) {
                            error_log('Password reset delivery failed for: ' . $email);
                            logPasswordResetEvent($pdo, intval($user['id']), 'PASSWORD_RESET_EMAIL_FAILED', [
                                'channel' => MAIL_DRIVER,
                                'email' => $email,
                                'ip' => $ipAddress,
                            ]);
                        } else {
                            logPasswordResetEvent($pdo, intval($user['id']), 'PASSWORD_RESET_EMAIL_SENT', [
                                'channel' => MAIL_DRIVER,
                                'email' => $email,
                                'ip' => $ipAddress,
                            ]);
                        }
                        $success = "If the email exists in our system, a password reset link has been sent.";
                    }
                } else {
                    // Don't reveal if email exists (security best practice)
                    logPasswordResetEvent($pdo, null, 'PASSWORD_RESET_UNKNOWN_EMAIL', [
                        'email' => $email,
                        'ip' => $requestIp,
                        'user_agent' => $requestUserAgent,
                    ]);
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

render_done:
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
            margin: 0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .forgot-card {
            max-width: 500px;
            width: 100%;
            margin: 0 auto;
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

                <?php if (!empty($warning)): ?>
                    <div class="alert alert-warning">
                        <i class="fas fa-exclamation-triangle"></i> <?php echo htmlspecialchars($warning); ?>
                    </div>
                <?php endif; ?>

                <?php if ($step == 'request'): ?>
                    <!-- Step 1: Request Reset -->
                    <p class="text-muted mb-4">Enter your email address and we'll send you a link to reset your password.</p>
                    <form method="POST" action="">
                        <?= csrfTokenInput(); ?>
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
                        <?= csrfTokenInput(); ?>
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
