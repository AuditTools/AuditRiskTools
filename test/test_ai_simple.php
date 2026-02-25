<?php
/**
 * Simple AI Test - Direct Gemini API call
 */

// Suppress any errors for clean JSON output
error_reporting(0);
ini_set('display_errors', 0);

header('Content-Type: application/json');

try {
    // Load .env
    require_once __DIR__ . '/vendor/autoload.php';
    $dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
    $dotenv->load();
    
    $provider = $_ENV['AI_PROVIDER'] ?? 'gemini';
    $apiKey = $_ENV['GEMINI_API_KEY'] ?? '';
    
    if (empty($apiKey)) {
        throw new Exception("GEMINI_API_KEY not found in .env file");
    }
    
    // Simple Gemini API call
    $url = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=' . $apiKey;
    
    $data = [
        'contents' => [
            [
                'parts' => [
                    ['text' => "Say 'Connection successful!' if you receive this message."]
                ]
            ]
        ],
        'generationConfig' => [
            'temperature' => 0.7,
            'maxOutputTokens' => 50
        ]
    ];
    
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);
    
    if ($error) {
        throw new Exception("CURL Error: $error");
    }
    
    if ($httpCode !== 200) {
        $errorData = json_decode($response, true);
        throw new Exception("Gemini API Error: " . ($errorData['error']['message'] ?? "HTTP $httpCode"));
    }
    
    $result = json_decode($response, true);
    $aiResponse = $result['candidates'][0]['content']['parts'][0]['text'] ?? 'No response';
    
    echo json_encode([
        'success' => true,
        'provider' => $provider,
        'message' => 'AI connection successful!',
        'response' => $aiResponse,
        'api_key_configured' => !empty($apiKey)
    ]);
    
} catch (Exception $e) {
    echo json_encode([
        'success' => false,
        'provider' => $provider ?? 'unknown',
        'error' => $e->getMessage()
    ]);
}
?>
