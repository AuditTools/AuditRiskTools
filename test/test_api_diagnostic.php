<?php
/**
 * API Diagnostic Tool
 * Check what's causing HTML output before JSON
 */

echo "=== API DIAGNOSTIC ===\n\n";

// Test 1: Check output buffering
echo "Test 1: Output Buffering\n";
ob_start();
echo "This should be buffered";
$buffered = ob_get_clean();
echo "✓ Output buffering works\n\n";

// Test 2: Check config loading
echo "Test 2: Config Loading\n";
ob_start();
require_once 'config/config.php';
$configOutput = ob_get_clean();
if (empty($configOutput)) {
    echo "✓ Config loads clean (no output)\n";
} else {
    echo "✗ Config has output:\n";
    echo "  Length: " . strlen($configOutput) . " bytes\n";
    echo "  Content: " . substr($configOutput, 0, 100) . "\n";
}
echo "\n";

// Test 3: Check database connection
echo "Test 3: Database Connection\n";
ob_start();
require_once 'functions/db.php';
$dbOutput = ob_get_clean();
if (empty($dbOutput)) {
    echo "✓ Database loads clean (no output)\n";
} else {
    echo "✗ Database has output:\n";
    echo "  Length: " . strlen($dbOutput) . " bytes\n";
    echo "  Content: " . substr($dbOutput, 0, 200) . "\n";
}
echo "\n";

// Test 4: Check auth functions
echo "Test 4: Auth Functions\n";
ob_start();
require_once 'functions/auth.php';
$authOutput = ob_get_clean();
if (empty($authOutput)) {
    echo "✓ Auth loads clean (no output)\n";
} else {
    echo "✗ Auth has output:\n";
    echo "  Length: " . strlen($authOutput) . " bytes\n";
    echo "  Content: " . substr($authOutput, 0, 100) . "\n";
}
echo "\n";

// Test 5: Check risk functions
echo "Test 5: Risk Functions\n";
ob_start();
require_once 'functions/risk.php';
$riskOutput = ob_get_clean();
if (empty($riskOutput)) {
    echo "✓ Risk loads clean (no output)\n";
} else {
    echo "✗ Risk has output:\n";
    echo "  Length: " . strlen($riskOutput) . " bytes\n";
    echo "  Content: " . substr($riskOutput, 0, 100) . "\n";
}
echo "\n";

// Test 6: Simulate API request
echo "Test 6: Simulate API Request\n";
$_SERVER['REQUEST_URI'] = '/AuditRiskTools/api/audit_actions.php?action=create';
$_POST['organization_id'] = 1;
$_POST['session_name'] = 'Test';
$_POST['digital_scale'] = 'High';
$_POST['audit_date'] = '2026-02-24';

ob_start();
session_start();
$sessionOutput = ob_get_clean();
if (empty($sessionOutput)) {
    echo "✓ Session starts clean (no output)\n";
} else {
    echo "✗ Session has output:\n";
    echo "  Length: " . strlen($sessionOutput) . " bytes\n";
    echo "  First 200 chars: " . substr($sessionOutput, 0, 200) . "\n";
}
echo "\n";

echo "=== DIAGNOSTIC COMPLETE ===\n";
echo "\nIf any test shows output, that's the source of HTML before JSON.\n";
?>
