<?php
/**
 * SRM-Audit - Configuration Loader
 * Loads environment variables from .env file
 */

// Load Composer autoloader
require_once __DIR__ . '/../vendor/autoload.php';

use Dotenv\Dotenv;

// Load .env file
$dotenv = Dotenv::createImmutable(__DIR__ . '/..');
$dotenv->load();

// Required environment variables
$dotenv->required([
    'DB_HOST',
    'DB_NAME',
    'DB_USER',
    'AI_PROVIDER'
]);

// Database Configuration
define('DB_HOST', $_ENV['DB_HOST']);
define('DB_PORT', $_ENV['DB_PORT'] ?? '3306');
define('DB_NAME', $_ENV['DB_NAME']);
define('DB_USER', $_ENV['DB_USER']);
define('DB_PASS', $_ENV['DB_PASS'] ?? '');

// AI Configuration
define('AI_PROVIDER', $_ENV['AI_PROVIDER']); // gemini, openai, ollama

// Gemini API
define('GEMINI_API_KEY', $_ENV['GEMINI_API_KEY'] ?? '');
define('GEMINI_API_URL', 'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent');

// OpenAI API (optional)
define('OPENAI_API_KEY', $_ENV['OPENAI_API_KEY'] ?? '');
define('OPENAI_API_URL', 'https://api.openai.com/v1/chat/completions');
define('OPENAI_MODEL', $_ENV['OPENAI_MODEL'] ?? 'gpt-4o-mini');

// Ollama API (optional - local)
define('OLLAMA_API_URL', $_ENV['OLLAMA_API_URL'] ?? 'http://localhost:11434/api/generate');
define('OLLAMA_MODEL', $_ENV['OLLAMA_MODEL'] ?? 'llama3.2:3b');

// App Configuration
define('APP_ENV', $_ENV['APP_ENV'] ?? 'production');
define('APP_DEBUG', filter_var($_ENV['APP_DEBUG'] ?? false, FILTER_VALIDATE_BOOLEAN));
define('APP_URL', $_ENV['APP_URL'] ?? 'http://localhost');

// Error reporting based on environment
if (APP_ENV === 'development' && APP_DEBUG) {
    error_reporting(E_ALL);
    ini_set('display_errors', 1);
} else {
    error_reporting(E_ALL & ~E_NOTICE & ~E_DEPRECATED);
    ini_set('display_errors', 0);
    ini_set('log_errors', 1);
}

// Set timezone
date_default_timezone_set('Asia/Jakarta');

// Session configuration (only if session not started yet)
if (session_status() === PHP_SESSION_NONE) {
    ini_set('session.cookie_httponly', 1);
    ini_set('session.use_only_cookies', 1);
    ini_set('session.cookie_samesite', 'Lax');
    
    if (APP_ENV === 'production') {
        ini_set('session.cookie_secure', 1); // HTTPS only in production
    }
}
?>
