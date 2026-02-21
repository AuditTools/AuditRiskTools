<?php
/**
 * SRM-Audit - Logout
 * Destroys session and redirects to login
 */
session_start();

// Unset all session variables
$_SESSION = array();

// Destroy the session cookie
if (isset($_COOKIE[session_name()])) {
    setcookie(session_name(), '', time() - 3600, '/');
}

// Destroy the session
session_destroy();

// Redirect to login page
header('Location: login.php?logged_out=1');
exit();
?>
