<?php
/**
 * SRM-Audit - Registration Page
 * User registration with secure password hashing
 */
session_start();
require_once 'functions/db.php';
require_once 'functions/auth.php';

// Redirect if already logged in
if (isLoggedIn()) {
    header('Location: dashboard.php');
    exit();
}

$error = '';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - SRM-Audit</title>
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
        .register-card {
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
        <div class="card register-card">
            <div class="card-header text-center py-4">
                <h3><i class="fas fa-shield-alt"></i> SRM-Audit</h3>
                <p class="mb-0 small">Create Your Account</p>
            </div>
            <div class="card-body p-4">
                <div id="alertContainer"></div>

                <form id="registerForm">
                    <?= csrfTokenInput(); ?>
                    <div class="mb-3">
                        <label class="form-label">Full Name *</label>
                        <div class="input-group">
                            <span class="input-group-text"><i class="fas fa-user"></i></span>
                            <input type="text" name="name" class="form-control" placeholder="Enter your full name" required>
                        </div>
                    </div>

                    <div class="mb-3">
                        <label class="form-label">Email Address *</label>
                        <div class="input-group">
                            <span class="input-group-text"><i class="fas fa-envelope"></i></span>
                            <input type="email" name="email" class="form-control" placeholder="Enter your email" required>
                        </div>
                    </div>

                    <div class="mb-3">
                        <label class="form-label">Password *</label>
                        <div class="input-group">
                            <span class="input-group-text"><i class="fas fa-lock"></i></span>
                            <input type="password" name="password" id="password" class="form-control" 
                                   placeholder="Minimum 8 characters" minlength="8" required>
                        </div>
                        <small class="text-muted">Minimum 8 characters</small>
                    </div>

                    <div class="mb-3">
                        <label class="form-label">Confirm Password *</label>
                        <div class="input-group">
                            <span class="input-group-text"><i class="fas fa-lock"></i></span>
                            <input type="password" name="confirm_password" id="confirm_password" 
                                   class="form-control" placeholder="Re-enter password" required>
                        </div>
                    </div>

                    <div class="mb-3 form-check">
                        <input type="checkbox" class="form-check-input" id="agreeTerms" required>
                        <label class="form-check-label" for="agreeTerms">
                            I agree to the Terms of Service and Privacy Policy
                        </label>
                    </div>

                    <button type="submit" class="btn btn-primary w-100 mb-3" id="registerBtn">
                        <i class="fas fa-user-plus"></i> Create Account
                    </button>
                </form>

                <hr class="my-4">

                <div class="text-center">
                    <p class="mb-0">Already have an account? <a href="login.php" class="text-decoration-none">Login here</a></p>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
    document.getElementById('registerForm').addEventListener('submit', function(e) {
        e.preventDefault();
        
        const password = document.getElementById('password').value;
        const confirmPassword = document.getElementById('confirm_password').value;
        
        if (password !== confirmPassword) {
            showAlert('danger', 'Passwords do not match');
            return;
        }
        
        const registerBtn = document.getElementById('registerBtn');
        const formData = new FormData(this);
        
        // Disable button and show loading
        registerBtn.disabled = true;
        registerBtn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Creating account...';
        
        fetch('api/auth_actions.php?action=register', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showAlert('success', data.message);
                setTimeout(() => {
                    window.location.href = data.redirect || 'dashboard.php';
                }, 500);
            } else {
                showAlert('danger', data.message);
                registerBtn.disabled = false;
                registerBtn.innerHTML = '<i class="fas fa-user-plus"></i> Create Account';
            }
        })
        .catch(error => {
            showAlert('danger', 'An error occurred. Please try again.');
            registerBtn.disabled = false;
            registerBtn.innerHTML = '<i class="fas fa-user-plus"></i> Create Account';
        });
    });
    
    function showAlert(type, message) {
        const alertContainer = document.getElementById('alertContainer');
        const alert = document.createElement('div');
        alert.className = `alert alert-${type} alert-dismissible fade show`;
        alert.innerHTML = `
            <i class="fas fa-${type === 'success' ? 'check' : 'exclamation'}-circle"></i> ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        alertContainer.innerHTML = '';
        alertContainer.appendChild(alert);
    }
    </script>
</body>
</html>
