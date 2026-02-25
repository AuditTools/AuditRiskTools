<?php
/**
 * Test Config API - Returns current .env configuration
 */
require_once 'config/config.php';

header('Content-Type: application/json');

try {
    echo json_encode([
        'success' => true,
        'config' => [
            'db_host' => DB_HOST,
            'db_port' => DB_PORT,
            'db_name' => DB_NAME,
            'ai_provider' => AI_PROVIDER,
            'app_env' => APP_ENV,
            'app_debug' => APP_DEBUG
        ]
    ]);
} catch (Exception $e) {
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage()
    ]);
}
?>
