<?php
/**
 * SRM-Audit - Index Page
 * Entry point - redirects to dashboard or login
 */
session_start();
require_once 'functions/db.php';
require_once 'functions/auth.php';

// Check if user is logged in
if (isset($_SESSION['user_id']) && isLoggedIn()) {
    // Redirect to dashboard
    header('Location: dashboard.php');
    exit();
} else {
    // Redirect to login
    header('Location: login.php');
    exit();
}
?>
