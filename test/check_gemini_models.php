<?php
/**
 * Check Available Gemini Models
 * This will list all models available for your API key
 */

// Load .env to get API key
require_once __DIR__ . '/vendor/autoload.php';
use Dotenv\Dotenv;
$dotenv = Dotenv::createImmutable(__DIR__);
$dotenv->load();

$apiKey = $_ENV['GEMINI_API_KEY'] ?? '';

if (empty($apiKey)) {
    die("Error: GEMINI_API_KEY not found in .env file\n");
}

echo "=== Checking Available Gemini Models ===\n\n";
echo "API Key: " . substr($apiKey, 0, 20) . "...\n\n";

// Call ListModels API
$url = 'https://generativelanguage.googleapis.com/v1beta/models?key=' . $apiKey;

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'Content-Type: application/json'
]);

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$error = curl_error($ch);
curl_close($ch);

if ($error) {
    die("CURL Error: $error\n");
}

echo "HTTP Code: $httpCode\n\n";

if ($httpCode !== 200) {
    echo "Error Response:\n";
    echo $response . "\n";
    exit(1);
}

$data = json_decode($response, true);

if (isset($data['models']) && is_array($data['models'])) {
    echo "✅ Found " . count($data['models']) . " models:\n\n";
    
    echo "Models that support 'generateContent':\n";
    echo str_repeat("=", 80) . "\n";
    
    foreach ($data['models'] as $model) {
        $name = $model['name'] ?? 'Unknown';
        $displayName = $model['displayName'] ?? 'Unknown';
        $supportedMethods = $model['supportedGenerationMethods'] ?? [];
        
        // Only show models that support generateContent
        if (in_array('generateContent', $supportedMethods)) {
            // Extract model ID from name (e.g., models/gemini-pro -> gemini-pro)
            $modelId = str_replace('models/', '', $name);
            
            echo "\n📌 Model ID: $modelId\n";
            echo "   Display Name: $displayName\n";
            echo "   Full Name: $name\n";
            echo "   Supported Methods: " . implode(', ', $supportedMethods) . "\n";
            
            // Show if it's a recommended model
            if (strpos($modelId, 'flash') !== false) {
                echo "   ⚡ FLASH MODEL (Fast & Free)\n";
            }
            if (strpos($modelId, 'pro') !== false && strpos($modelId, 'flash') === false) {
                echo "   💎 PRO MODEL (High Quality)\n";
            }
            if (strpos($modelId, 'latest') !== false) {
                echo "   🆕 LATEST VERSION\n";
            }
        }
    }
    
    echo "\n" . str_repeat("=", 80) . "\n";
    echo "\n📝 RECOMMENDATION:\n";
    echo "Use the model ID in your .env or config.php\n";
    echo "For free tier, use a model with 'flash' in the name\n\n";
    
    // Find the best flash model
    $flashModels = [];
    foreach ($data['models'] as $model) {
        $name = $model['name'] ?? '';
        $supportedMethods = $model['supportedGenerationMethods'] ?? [];
        
        if (in_array('generateContent', $supportedMethods) && 
            strpos($name, 'flash') !== false) {
            $modelId = str_replace('models/', '', $name);
            $flashModels[] = $modelId;
        }
    }
    
    if (!empty($flashModels)) {
        echo "✅ RECOMMENDED MODEL(S) FOR FREE TIER:\n";
        foreach ($flashModels as $model) {
            echo "   - $model\n";
        }
        
        // Get the first flash model
        $recommendedModel = $flashModels[0];
        echo "\n🎯 USE THIS IN YOUR CODE:\n";
        echo "   define('GEMINI_API_URL', 'https://generativelanguage.googleapis.com/v1beta/models/$recommendedModel:generateContent');\n\n";
    }
    
} else {
    echo "❌ No models found or unexpected response format\n";
    echo "Full Response:\n";
    echo json_encode($data, JSON_PRETTY_PRINT) . "\n";
}
?>
