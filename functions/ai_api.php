<?php
/**
 * SRM-Audit - AI Integration with Multi-Provider Support
 * Supports: Gemini (free)
 * Configuration via .env file
 */

// Load configuration from .env
require_once __DIR__ . '/../config/config.php';

// ==============================================
// MAIN AI ROUTER
// ==============================================

/**
 * Main AI API caller - routes to correct provider based on .env
 */
function callAI($prompt, $maxTokens = 1000) {
    switch (AI_PROVIDER) {
        case 'gemini':
            return callGeminiAPI($prompt, $maxTokens);
        default:
            throw new Exception("Invalid AI provider in .env: " . AI_PROVIDER);
    }
}

// ==============================================
// GEMINI API (FREE)
// ==============================================

/**
 * Gemini API Integration (FREE)
 * Get API key from: https://aistudio.google.com/app/apikey
 */
function callGeminiAPI($prompt, $maxTokens = 1000) {
    if (empty(GEMINI_API_KEY)) {
        throw new Exception("Gemini API key not configured. Add GEMINI_API_KEY to .env file");
    }
    
    $data = [
        'contents' => [
            [
                'parts' => [
                    ['text' => $prompt]
                ]
            ]
        ],
        'generationConfig' => [
            'temperature' => 0.7,
            'maxOutputTokens' => $maxTokens,
            'topP' => 0.8,
            'topK' => 40
        ],
        'safetySettings' => [
            [
                'category' => 'HARM_CATEGORY_HARASSMENT',
                'threshold' => 'BLOCK_NONE'
            ],
            [
                'category' => 'HARM_CATEGORY_HATE_SPEECH',
                'threshold' => 'BLOCK_NONE'
            ]
        ]
    ];
    
    $url = GEMINI_API_URL . '?key=' . GEMINI_API_KEY;
    
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
    curl_setopt($ch, CURLOPT_TIMEOUT, 120);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 15);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);
    
    if ($error) {
        throw new Exception("CURL Error: $error");
    }
    
    if ($httpCode !== 200) {
        $errorData = json_decode($response, true);
        $errorMsg = $errorData['error']['message'] ?? "HTTP Error $httpCode";
        throw new Exception("Gemini API Error: $errorMsg");
    }
    
    $result = json_decode($response, true);
    
    if (isset($result['candidates'][0]['content']['parts'][0]['text'])) {
        return $result['candidates'][0]['content']['parts'][0]['text'];
    }
    
    throw new Exception("Unexpected Gemini API response format");
}

// ==============================================
// PROMPT TEMPLATES
// ==============================================

/**
 * Build Executive Summary Report Prompt
 */
function buildReportPrompt($auditData) {
    $org = $auditData['organization_name'];
    $industry = $auditData['industry'];
    $exposure = $auditData['exposure_level'];
    $riskLevel = $auditData['final_risk_level'];
    $compliance = $auditData['compliance_percentage'];
    
    // Format top 5 risks
    $risksList = "";
    if (isset($auditData['top_5_risks']) && is_array($auditData['top_5_risks'])) {
        foreach ($auditData['top_5_risks'] as $i => $risk) {
            $num = $i + 1;
            $risksList .= "{$num}. {$risk['title']}\n";
            $risksList .= "   - Likelihood: {$risk['likelihood']}/5\n";
            $risksList .= "   - Impact: {$risk['impact']}/5\n";
            $risksList .= "   - Risk Score: {$risk['risk_score']}\n";
            $risksList .= "   - NIST Function: {$risk['nist_function']}\n";
            $risksList .= "   - Description: {$risk['description']}\n\n";
        }
    }
    
    $prompt = <<<PROMPT
You are a professional Cybersecurity Auditor integrated into the SRM-Audit system.

Based ONLY on the audit data below:

**Organization:** {$org}
**Industry:** {$industry}
**Exposure Level:** {$exposure}
**Final Risk Level:** {$riskLevel}
**Compliance Percentage:** {$compliance}%

**Top 5 Critical Risks:**
{$risksList}

**Generate a comprehensive audit report with these sections:**

# 1. EXECUTIVE SUMMARY
Brief overview for C-level executives highlighting key risks and business impact.

# 2. ORGANIZATIONAL RISK OVERVIEW  
Current security posture, exposure analysis, and risk landscape summary.

# 3. TOP 5 CRITICAL RISKS ANALYSIS
Detailed explanation of each risk, business impact, and urgency assessment.

# 4. MITIGATION RECOMMENDATIONS
Specific actionable steps with priority ranking and resource requirements.

# 5. NIST CSF ALIGNMENT
Framework mapping, compliance gaps, and improvement roadmap.

# 6. STRATEGIC RECOMMENDATIONS
Long-term security strategy and investment priorities.

# 7. CONCLUSION
Summary of findings and next steps.

**Strict Constraints:**
- Use formal corporate tone suitable for board presentations
- Do NOT recalculate any scores or metrics
- Do NOT add new risks beyond the provided list
- Only use the data provided above
- Use professional audit report structure
- Include actionable, specific recommendations
- Generate ALL sections completely — do NOT stop early or truncate
- Ensure every section has substantive content

Generate the complete report now:
PROMPT;

    return $prompt;
}

/**
 * Build Chatbot Guidance Prompt
 */
function buildChatbotPrompt($userQuestion) {
    $prompt = <<<PROMPT
You are an educational Cybersecurity GRC (Governance, Risk, and Compliance) assistant for the SRM-Audit system.

**Your Role:**
- Explain audit concepts and frameworks clearly
- Help users understand cybersecurity terminology  
- Provide educational guidance on risk assessment methodologies

**Strict Rules You MUST Follow:**
- You do NOT have access to any database or user data
- You CANNOT provide contextual decisions about specific audits
- You CANNOT modify, calculate, or recalculate any scores
- You CANNOT access real audit data or findings
- Keep answers under 250 words - provide complete, helpful explanations
- Use simple, clear, educational language
- Always finish your thoughts completely

**Topics You CAN Explain:**
- Risk assessment concepts (Likelihood, Impact, Risk Score)
- CIA Triad (Confidentiality, Integrity, Availability)
- NIST Cybersecurity Framework and its 5 functions
- Vulnerability assessment methodologies
- Threat vs Risk vs Vulnerability differences
- How to prioritize security risks
- Basic audit terminology and concepts

**User Question:**
{$userQuestion}

**Your Educational Answer (max 150 words):**
PROMPT;

    return $prompt;
}

// ==============================================
// HIGH-LEVEL WRAPPER FUNCTIONS
// ==============================================

/**
 * Generate Audit Report with AI
 * 
 * @param array $auditData Must contain: organization_name, industry, exposure_level,
 *                         final_risk_level, compliance_percentage, top_5_risks
 * @return array ['success' => bool, 'report' => string, 'provider' => string] or ['success' => bool, 'error' => string]
 */
function generateAuditReport($auditData) {
    try {
        $prompt = buildReportPrompt($auditData);
        $report = callAI($prompt, 8192);
        
        return [
            'success' => true,
            'report' => $report,
            'provider' => AI_PROVIDER
        ];
    } catch (Exception $e) {
        return [
            'success' => false,
            'error' => $e->getMessage()
        ];
    }
}

/**
 * Process Chatbot Question with AI
 * 
 * @param string $question User's question
 * @return array ['success' => bool, 'answer' => string] or ['success' => bool, 'error' => string]
 */
function chatbotGuidance($userQuestion) {
    try {
        $prompt = buildChatbotPrompt($userQuestion);
        $answer = callAI($prompt, 600);
        
        return [
            'success' => true,
            'answer' => $answer
        ];
    } catch (Exception $e) {
        return [
            'success' => false,
            'error' => $e->getMessage()
        ];
    }
}

/**
 * Test AI Connection
 * 
 * @return array ['success' => bool, 'provider' => string, 'message' => string, 'response' => string]
 */
function testAIConnection() {
    try {
        $response = callAI("Say 'Connection successful!' if you receive this message.", 50);
        return [
            'success' => true,
            'provider' => AI_PROVIDER,
            'message' => 'AI connection successful!',
            'response' => $response
        ];
    } catch (Exception $e) {
        return [
            'success' => false,
            'provider' => AI_PROVIDER,
            'error' => $e->getMessage()
        ];
    }
}

// ==============================================
// CONFIGURATION GUIDE
// ==============================================
/*
📋 SETUP INSTRUCTIONS:

1️⃣ Choose AI Provider (edit .env file):
   
   AI_PROVIDER=gemini    # FREE, recommended for students


2️⃣ Add API Key to .env:

   For Gemini (FREE):
   - Get key: https://aistudio.google.com/app/apikey
   - Add to .env: GEMINI_API_KEY=AIzaSy...


3️⃣ Test Connection:
   http://localhost/AuditRiskTools/api/ai_actions.php?action=test

4️⃣ Security Best Practices:
   ✓ API keys are in .env (NOT in code)
   ✓ .env is in .gitignore (NOT committed to Git)
   ✓ Use .env.example as template for others
   ✓ Different .env for development/production

📊 COST COMPARISON:
   
   Gemini (FREE forever):
   - 15 requests/minute
   - 1,500 requests/day
   - Perfect for: Student projects, demos
   
*/

?>
