<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

echo "Testing AI Setup...\n\n";

// Test 1: Check if config loads
echo "1. Testing config loading...\n";
try {
    require_once __DIR__ . '/config/config.php';
    echo "   ✓ Config loaded successfully\n";
    echo "   AI_PROVIDER: " . AI_PROVIDER . "\n";
    echo "   GEMINI_API_KEY: " . (empty(GEMINI_API_KEY) ? "NOT SET" : "SET (length: " . strlen(GEMINI_API_KEY) . ")") . "\n\n";
} catch (Exception $e) {
    echo "   ✗ Config error: " . $e->getMessage() . "\n\n";
    exit(1);
}

// Test 2: Check if AI API functions load
echo "2. Testing AI API functions...\n";
try {
    require_once __DIR__ . '/functions/ai_api.php';
    echo "   ✓ AI API functions loaded\n\n";
} catch (Exception $e) {
    echo "   ✗ AI API error: " . $e->getMessage() . "\n\n";
    exit(1);
}

// Test 3: Test AI connection
echo "3. Testing AI connection...\n";
try {
    $result = testAIConnection();
    if ($result['success']) {
        echo "   ✓ AI connection successful!\n";
        echo "   Provider: " . $result['provider'] . "\n";
        echo "   Response: " . $result['response'] . "\n\n";
    } else {
        echo "   ✗ AI connection failed\n";
        echo "   Error: " . $result['error'] . "\n\n";
        exit(1);
    }
} catch (Exception $e) {
    echo "   ✗ AI test error: " . $e->getMessage() . "\n\n";
    exit(1);
}

echo "All tests passed! ✓\n";
?>
