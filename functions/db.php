<?php
/**
 * SRM-Audit - Database Connection
 * Using environment variables from .env file
 */

// Load configuration from .env
require_once __DIR__ . '/../config/config.php';

// Database connection
try {
    $dsn = "mysql:host=" . DB_HOST . ";port=" . DB_PORT . ";dbname=" . DB_NAME . ";charset=utf8mb4";
    
    $options = [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
    ];
    
    $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
    
} catch (PDOException $e) {
    // Log error
    error_log("Database Connection Error: " . $e->getMessage());
    
    // Check if this is an API request (return JSON)
    $isApiRequest = strpos($_SERVER['REQUEST_URI'] ?? '', '/api/') !== false;
    
    if ($isApiRequest) {
        // Output JSON error for API requests
        header('Content-Type: application/json');
        echo json_encode([
            'success' => false,
            'message' => 'Database connection failed',
            'error' => APP_DEBUG ? $e->getMessage() : 'Please check database configuration'
        ]);
        exit();
    }
    
    // Show error based on environment (for web pages)
    if (APP_DEBUG) {
        die("
            <!DOCTYPE html>
            <html>
            <head>
                <title>Database Connection Error</title>
                <style>
                    body { font-family: Arial; padding: 50px; background: #f5f5f5; }
                    .error-box { 
                        max-width: 700px; 
                        margin: 0 auto; 
                        background: white; 
                        padding: 30px; 
                        border-radius: 8px; 
                        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    }
                    h2 { color: #dc3545; }
                    .error-msg { background: #fff3cd; padding: 15px; border-radius: 5px; border-left: 4px solid #ffc107; margin: 15px 0; }
                    .steps { background: #f8f9fa; padding: 15px; border-radius: 5px; margin-top: 20px; }
                    code { background: #e9ecef; padding: 2px 6px; border-radius: 3px; font-family: monospace; }
                    .info { color: #666; font-size: 0.9em; margin-top: 20px; }
                </style>
            </head>
            <body>
                <div class='error-box'>
                    <h2>❌ Database Connection Error</h2>
                    
                    <div class='error-msg'>
                        <strong>Error Message:</strong><br>
                        " . htmlspecialchars($e->getMessage()) . "
                    </div>
                    
                    <div class='steps'>
                        <h4>🔧 Setup Checklist:</h4>
                        <ol>
                            <li><strong>Check .env file</strong>
                                <br>• Make sure <code>.env</code> exists in project root
                                <br>• Copy from <code>.env.example</code> if missing
                                <br>• Update DB credentials: DB_USER, DB_PASS
                            </li>
                            <br>
                            <li><strong>Start MySQL Server</strong>
                                <br>• Open Laragon/XAMPP Control Panel
                                <br>• Click 'Start All' or start MySQL service
                            </li>
                            <br>
                            <li><strong>Import Database Schema</strong>
                                <br>• Open phpMyAdmin: <a href='http://localhost/phpmyadmin' target='_blank'>http://localhost/phpmyadmin</a>
                                <br>• Click 'Import' tab
                                <br>• Choose <code>database_schema.sql</code>
                                <br>• Click 'Go' to execute
                            </li>
                            <br>
                            <li><strong>Install Dependencies</strong>
                                <br>• Run: <code>composer install</code>
                                <br>• This installs required packages (dotenv, etc.)
                            </li>
                            <br>
                            <li><strong>Refresh this page</strong></li>
                        </ol>
                    </div>
                    
                    <div class='info'>
                        <strong>📋 Current Configuration (.env):</strong><br>
                        Host: " . DB_HOST . ":" . DB_PORT . "<br>
                        Database: " . DB_NAME . "<br>
                        User: " . DB_USER . "<br>
                        Environment: " . APP_ENV . "
                    </div>
                </div>
            </body>
            </html>
        ");
    } else {
        // Production: Simple error message
        http_response_code(503);
        die("
            <!DOCTYPE html>
            <html>
            <head>
                <title>Service Unavailable</title>
                <style>
                    body { font-family: Arial; padding: 50px; background: #f5f5f5; text-align: center; }
                    .error-box { max-width: 500px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; }
                    h2 { color: #dc3545; }
                </style>
            </head>
            <body>
                <div class='error-box'>
                    <h2>⚠️ Service Temporarily Unavailable</h2>
                    <p>We're experiencing technical difficulties. Please try again later.</p>
                    <p><small>Error Code: DB_CONNECTION_FAILED</small></p>
                </div>
            </body>
            </html>
        ");
    }
}
?>
