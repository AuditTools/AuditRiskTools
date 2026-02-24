<?php
/**
 * SRM-Audit - AI API Integration
 * Handles communication with OpenAI API for report generation and chatbot
 */

// ==============================================
// AI CONFIGURATION
// ==============================================

// OpenAI API Configuration
define('OPENAI_API_KEY', 'your-openai-api-key-here'); // Replace with your actual API key
define('OPENAI_MODEL', 'gpt-4o-mini'); // Cost-effective and powerful
define('OPENAI_API_URL', 'https://api.openai.com/v1/chat/completions');

// Alternative: Use GPT-4o for higher quality (more expensive)
// define('OPENAI_MODEL', 'gpt-4o');

// ==============================================
// RECOMMENDED AI MODELS FOR SRM-AUDIT
// ==============================================
/*
1️⃣ BEST CHOICE: OpenAI GPT-4o-mini
   - Cost: $0.15/1M input tokens, $0.60/1M output tokens
   - Speed: Very fast
   - Quality: Excellent for structured reports
   - Perfect for: Report generation + Chatbot
   
2️⃣ PREMIUM: OpenAI GPT-4o
   - Cost: $2.50/1M input tokens, $10/1M output tokens  
   - Speed: Fast
   - Quality: Highest reasoning ability
   - Use for: Complex audit analysis
   
3️⃣ BUDGET: OpenAI GPT-3.5-turbo
   - Cost: $0.50/1M input tokens, $1.50/1M output tokens
   - Speed: Fastest
   - Quality: Good for chatbot
   - Use for: Chatbot only (not report generation)

4️⃣ ALTERNATIVE: Anthropic Claude 3.5 Sonnet
   - Via Anthropic API
   - Excellent reasoning and formal writing
   - Need to modify code for Claude API format
*/

// ==============================================
// AI PROMPT TEMPLATES
// ==============================================

/**
 * Get Executive Summary Report Prompt
 * Used for generating formal audit reports
 */
function getReportPrompt($auditData) {
    $prompt = "You are a professional Cybersecurity Auditor integrated into the SRM-Audit system.

Based ONLY on the audit data below:

Organization: {$auditData['organization_name']}
Industry: {$auditData['industry']}
Exposure Level: {$auditData['exposure_level']}
Final Risk Level: {$auditData['final_risk_level']}
Compliance Percentage: {$auditData['compliance_percentage']}%

Top 5 Risks:
{$auditData['top_5_risks']}

Generate:
1. Executive Summary (business focused)
2. Organizational Risk Overview
3. Strategic Recommendations

Constraints:
- Use formal corporate tone
- Do not recalculate scores
- Do not add new risks
- Only use provided data
- Maximum 400 words";

    return $prompt;
}

/**
 * Get Chatbot Guidance Prompt
 * Used for educational Q&A about audit frameworks
 */
function getChatbotSystemPrompt() {
    return "You are an educational Cybersecurity GRC assistant.

Rules:
- Explain frameworks simply
- Do not access database
- Do not provide contextual decisions
- Do not modify scores
- Keep answer under 150 words";
}

// ==============================================
// AI API FUNCTIONS
// ==============================================

/**
 * Call OpenAI Chat Completion API
 * 
 * @param string $systemPrompt System instructions
 * @param string $userMessage User input
 * @param int $maxTokens Maximum response tokens
 * @return array Response with 'success', 'message', 'data'
 */
function callOpenAI($systemPrompt, $userMessage, $maxTokens = 500) {
    // Check if API key is configured
    if (OPENAI_API_KEY === 'your-openai-api-key-here') {
        return [
            'success' => false,
            'message' => 'OpenAI API key not configured. Please set OPENAI_API_KEY in functions/ai_api.php'
        ];
    }
    
    $data = [
        'model' => OPENAI_MODEL,
        'messages' => [
            ['role' => 'system', 'content' => $systemPrompt],
            ['role' => 'user', 'content' => $userMessage]
        ],
        'max_tokens' => $maxTokens,
        'temperature' => 0.7
    ];
    
    $ch = curl_init(OPENAI_API_URL);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json',
        'Authorization: Bearer ' . OPENAI_API_KEY
    ]);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);
    
    if ($error) {
        return [
            'success' => false,
            'message' => 'API request failed: ' . $error
        ];
    }
    
    if ($httpCode !== 200) {
        $errorData = json_decode($response, true);
        return [
            'success' => false,
            'message' => 'API error: ' . ($errorData['error']['message'] ?? 'Unknown error')
        ];
    }
    
    $result = json_decode($response, true);
    
    if (!isset($result['choices'][0]['message']['content'])) {
        return [
            'success' => false,
            'message' => 'Invalid API response format'
        ];
    }
    
    return [
        'success' => true,
        'data' => [
            'response' => trim($result['choices'][0]['message']['content']),
            'tokens_used' => $result['usage']['total_tokens'] ?? 0
        ]
    ];
}

/**
 * Generate AI Audit Report
 * 
 * @param array $auditData Audit session data
 * @return array Response with generated report
 */
function generateAuditReport($auditData) {
    $systemPrompt = "You are a professional Cybersecurity Auditor. Generate formal audit reports in Markdown format with proper headings.";
    $userPrompt = getReportPrompt($auditData);
    
    return callOpenAI($systemPrompt, $userPrompt, 1000);
}

/**
 * Process Chatbot Question
 * 
 * @param string $question User question
 * @return array Response with answer
 */
function processChatbotQuestion($question) {
    $systemPrompt = getChatbotSystemPrompt();
    
    return callOpenAI($systemPrompt, $question, 300);
}

// ==============================================
// SETUP INSTRUCTIONS
// ==============================================
/*
📋 HOW TO SET UP AI:

1️⃣ Get OpenAI API Key:
   - Go to: https://platform.openai.com/api-keys
   - Create account or login
   - Click "Create new secret key"
   - Copy the key (starts with sk-...)

2️⃣ Configure this file:
   - Replace 'your-openai-api-key-here' with your actual key
   - Line 13: define('OPENAI_API_KEY', 'sk-your-actual-key');

3️⃣ Test the integration:
   - Use api/ai_actions.php?action=test
   - Check if connection works

4️⃣ Cost Estimation for GPT-4o-mini:
   Report Generation:
   - Input: ~500 tokens ($0.000075)
   - Output: ~400 tokens ($0.00024)
   - Total per report: ~$0.0003 (0.03 cents)
   
   Chatbot:
   - Per question: ~$0.0001 (0.01 cents)
   
   Monthly cost for 1000 reports + 5000 questions:
   - Reports: $0.30
   - Chat: $0.50
   - Total: ~$0.80/month

5️⃣ Security Best Practices:
   - Store API key in environment variable (not in code)
   - Use .env file with PHP dotenv library
   - Never commit API key to Git
   - Add rate limiting to prevent abuse
*/
?>
