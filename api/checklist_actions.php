<?php
/**
 * SRM-Audit - Control Checklist Actions API
 * Manages NIST CSF control audit checklist per audit session.
 *
 * Actions:
 *   GET  ?action=get_controls          → Return full NIST control library
 *   GET  ?action=get_checklist&audit_id=X → Get saved checklist for audit
 *   POST ?action=save                  → Save/update one control result
 *   POST ?action=save_bulk             → Save/update multiple controls at once
 *   GET  ?action=summary&audit_id=X    → Get compliance summary stats
 */
session_start();
require_once '../functions/db.php';
require_once '../functions/auth.php';
require_once '../functions/risk.php';
require_once '../functions/nist_controls.php';

header('Content-Type: application/json');

if (!isLoggedIn()) {
    echo json_encode(['success' => false, 'message' => 'Unauthorized']);
    exit();
}

$userId = $_SESSION['user_id'];
$action = $_GET['action'] ?? '';

try {
    switch ($action) {

        /**
         * Return the full NIST CSF control library (read-only reference data)
         */
        case 'get_controls':
            $grouped = getNistControlsByFunction();
            echo json_encode(['success' => true, 'controls' => $grouped, 'total' => getNistControlTotal()]);
            break;

        /**
         * Get saved checklist results for a specific audit session
         */
        case 'get_checklist':
            $auditId = intval($_GET['audit_id'] ?? 0);
            verifyAuditAccess($pdo, $auditId, $userId);

            $stmt = $pdo->prepare("SELECT control_id, status, notes FROM control_checklist WHERE audit_id = ?");
            $stmt->execute([$auditId]);
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

            // Key by control_id for easy JS lookup
            $saved = [];
            foreach ($rows as $r) {
                $saved[$r['control_id']] = [
                    'status' => $r['status'],
                    'notes' => $r['notes']
                ];
            }

            echo json_encode(['success' => true, 'checklist' => $saved]);
            break;

        /**
         * Save / update a single control result
         */
        case 'save':
            if (!verifyCSRFToken($_POST['csrf_token'] ?? '')) {
                throw new Exception('Invalid CSRF token');
            }

            $auditId   = intval($_POST['audit_id'] ?? 0);
            $controlId = trim($_POST['control_id'] ?? '');
            $status    = $_POST['status'] ?? 'Not Assessed';
            $notes     = trim($_POST['notes'] ?? '');

            verifyAuditAccess($pdo, $auditId, $userId);
            validateStatus($status);

            upsertChecklistItem($pdo, $auditId, $controlId, $status, $notes);

            // Recalculate compliance
            updateAuditMetrics($pdo, $auditId);

            echo json_encode(['success' => true, 'message' => 'Control saved']);
            break;

        /**
         * Bulk save - saves multiple controls at once (the main Save All button)
         */
        case 'save_bulk':
            $input = json_decode(file_get_contents('php://input'), true);

            if (!verifyCSRFToken($input['csrf_token'] ?? '')) {
                throw new Exception('Invalid CSRF token');
            }

            $auditId = intval($input['audit_id'] ?? 0);
            $items   = $input['items'] ?? [];

            verifyAuditAccess($pdo, $auditId, $userId);

            $pdo->beginTransaction();
            $savedCount = 0;
            foreach ($items as $item) {
                $controlId = trim($item['control_id'] ?? '');
                $status    = $item['status'] ?? 'Not Assessed';
                $notes     = trim($item['notes'] ?? '');

                validateStatus($status);
                upsertChecklistItem($pdo, $auditId, $controlId, $status, $notes);
                $savedCount++;
            }
            $pdo->commit();

            // Recalculate compliance
            updateAuditMetrics($pdo, $auditId);

            echo json_encode(['success' => true, 'message' => "$savedCount controls saved", 'saved' => $savedCount]);
            break;

        /**
         * Get compliance summary statistics for an audit
         */
        case 'summary':
            $auditId = intval($_GET['audit_id'] ?? 0);
            verifyAuditAccess($pdo, $auditId, $userId);

            $summary = getChecklistSummary($pdo, $auditId);
            echo json_encode(['success' => true, 'summary' => $summary]);
            break;

        default:
            throw new Exception('Invalid action');
    }
} catch (Exception $e) {
    if ($pdo->inTransaction()) $pdo->rollBack();
    echo json_encode(['success' => false, 'message' => $e->getMessage()]);
}

// ─── Helper Functions ────────────────────────────────────────

/**
 * Verify the current user owns this audit session
 */
function verifyAuditAccess($pdo, $auditId, $userId) {
    if ($auditId <= 0) throw new Exception('Invalid audit ID');
    $stmt = $pdo->prepare("SELECT a.id FROM audit_sessions a JOIN organizations o ON a.organization_id = o.id WHERE a.id = ? AND o.user_id = ?");
    $stmt->execute([$auditId, $userId]);
    if (!$stmt->fetch()) {
        throw new Exception('Audit session not found or access denied');
    }
}

/**
 * Validate status enum value
 */
function validateStatus($status) {
    $allowed = ['Not Assessed', 'Compliant', 'Partially Compliant', 'Non-Compliant', 'Not Applicable'];
    if (!in_array($status, $allowed, true)) {
        throw new Exception("Invalid status: $status");
    }
}

/**
 * Insert or update a checklist item (upsert by audit_id + control_id unique key)
 */
function upsertChecklistItem($pdo, $auditId, $controlId, $status, $notes) {
    $stmt = $pdo->prepare("
        INSERT INTO control_checklist (audit_id, control_id, status, notes)
        VALUES (?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE status = VALUES(status), notes = VALUES(notes)
    ");
    $stmt->execute([$auditId, $controlId, $status, $notes ?: null]);
}

/**
 * Get compliance summary by function and overall
 */
function getChecklistSummary($pdo, $auditId) {
    $stmt = $pdo->prepare("SELECT control_id, status FROM control_checklist WHERE audit_id = ?");
    $stmt->execute([$auditId]);
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Build a map: control_id → NIST function
    $allControls = getNistCsfControls();
    $controlFuncMap = [];
    foreach ($allControls as $c) {
        $controlFuncMap[$c['control_id']] = $c['function'];
    }

    $totalControls = count($allControls);
    $stats = [
        'Compliant' => 0,
        'Partially Compliant' => 0,
        'Non-Compliant' => 0,
        'Not Applicable' => 0,
        'Not Assessed' => 0,
    ];
    $byFunction = [];

    // Initialize per-function counters
    foreach (['Identify', 'Protect', 'Detect', 'Respond', 'Recover'] as $fn) {
        $byFunction[$fn] = [
            'Compliant' => 0,
            'Partially Compliant' => 0,
            'Non-Compliant' => 0,
            'Not Applicable' => 0,
            'Not Assessed' => 0,
            'total' => 0
        ];
    }
    // Count totals per function from library
    foreach ($allControls as $c) {
        $byFunction[$c['function']]['total']++;
    }

    // Tally saved statuses
    foreach ($rows as $r) {
        $st = $r['status'];
        if (isset($stats[$st])) $stats[$st]++;
        $fn = $controlFuncMap[$r['control_id']] ?? null;
        if ($fn && isset($byFunction[$fn][$st])) {
            $byFunction[$fn][$st]++;
        }
    }

    // Count not-assessed (controls not yet in DB)
    $assessedCount = count($rows);
    $stats['Not Assessed'] = $totalControls - $assessedCount;
    foreach ($byFunction as $fn => &$d) {
        $assessedInFn = $d['Compliant'] + $d['Partially Compliant'] + $d['Non-Compliant'] + $d['Not Applicable'];
        $d['Not Assessed'] = $d['total'] - $assessedInFn;
    }
    unset($d);

    // Overall compliance % (Compliant + Partially * 0.5) / (Total - N/A)
    $applicable = $totalControls - $stats['Not Applicable'];
    $complianceScore = 0;
    if ($applicable > 0) {
        $complianceScore = round((($stats['Compliant'] + $stats['Partially Compliant'] * 0.5) / $applicable) * 100, 1);
    }

    return [
        'total_controls' => $totalControls,
        'assessed' => $assessedCount,
        'stats' => $stats,
        'by_function' => $byFunction,
        'compliance_score' => $complianceScore,
    ];
}
