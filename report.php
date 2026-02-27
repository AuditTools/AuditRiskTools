<?php
session_start();
require_once 'functions/db.php';
require_once 'functions/auth.php';
require_once 'functions/risk.php';
require_once 'functions/report.php';

requireLogin();

$userId = $_SESSION['user_id'];
$userRole = $_SESSION['user_role'] ?? 'auditor';
$audit_id = intval($_GET['audit_id'] ?? ($_SESSION['active_audit_id'] ?? 0));
$selectedOrgId = intval($_GET['org_id'] ?? 0);
$pageError = '';
$reportData = null;

$organizations = [];
$allAudits = [];

if ($userRole === 'auditee') {
    $assignedIds = getAuditeeAssignedAudits($pdo, $userId);
    if (!empty($assignedIds)) {
        $placeholders = implode(',', array_fill(0, count($assignedIds), '?'));
        $stmtAuditList = $pdo->prepare("SELECT a.id, a.organization_id, a.session_name, a.audit_date, o.organization_name FROM audit_sessions a JOIN organizations o ON a.organization_id = o.id WHERE a.id IN ($placeholders) ORDER BY a.audit_date DESC, a.created_at DESC");
        $stmtAuditList->execute($assignedIds);
        $allAudits = $stmtAuditList->fetchAll(PDO::FETCH_ASSOC);
        $orgIds = array_unique(array_column($allAudits, 'organization_id'));
        if (!empty($orgIds)) {
            $orgPlaceholders = implode(',', array_fill(0, count($orgIds), '?'));
            $stmtOrgList = $pdo->prepare("SELECT id, organization_name FROM organizations WHERE id IN ($orgPlaceholders) ORDER BY organization_name ASC");
            $stmtOrgList->execute(array_values($orgIds));
            $organizations = $stmtOrgList->fetchAll(PDO::FETCH_ASSOC);
        }
    }
} elseif ($userRole === 'admin') {
    $stmtOrgList = $pdo->prepare("SELECT id, organization_name FROM organizations WHERE is_active = 1 ORDER BY organization_name ASC");
    $stmtOrgList->execute();
    $organizations = $stmtOrgList->fetchAll(PDO::FETCH_ASSOC);
    $stmtAuditList = $pdo->prepare("SELECT a.id, a.organization_id, a.session_name, a.audit_date, o.organization_name FROM audit_sessions a JOIN organizations o ON a.organization_id = o.id ORDER BY a.audit_date DESC, a.created_at DESC");
    $stmtAuditList->execute();
    $allAudits = $stmtAuditList->fetchAll(PDO::FETCH_ASSOC);
} else {
    $stmtOrgList = $pdo->prepare("SELECT id, organization_name FROM organizations WHERE user_id = ? AND is_active = 1 ORDER BY organization_name ASC");
    $stmtOrgList->execute([$userId]);
    $organizations = $stmtOrgList->fetchAll(PDO::FETCH_ASSOC);
    $stmtAuditList = $pdo->prepare("SELECT a.id, a.organization_id, a.session_name, a.audit_date, o.organization_name FROM audit_sessions a JOIN organizations o ON a.organization_id = o.id WHERE o.user_id = ? ORDER BY a.audit_date DESC, a.created_at DESC");
    $stmtAuditList->execute([$userId]);
    $allAudits = $stmtAuditList->fetchAll(PDO::FETCH_ASSOC);
}

if ($audit_id > 0) {
    // Role-based access check
    if ($userRole === 'auditee') {
        if (!isAuditeeAssigned($pdo, $audit_id, $userId)) {
            $pageError = 'Audit not found or access denied.';
            $audit_id = 0;
            unset($_SESSION['active_audit_id']);
        }
    } elseif ($userRole === 'admin') {
        // Admin can view any audit - just verify it exists
        $stmtAccess = $pdo->prepare("SELECT id FROM audit_sessions WHERE id = ?");
        $stmtAccess->execute([$audit_id]);
        if (!$stmtAccess->fetch()) {
            $pageError = 'Audit not found.';
            $audit_id = 0;
            unset($_SESSION['active_audit_id']);
        }
    } else {
        $stmtAccess = $pdo->prepare("SELECT a.id, a.organization_id FROM audit_sessions a JOIN organizations o ON a.organization_id = o.id WHERE a.id = ? AND o.user_id = ?");
        $stmtAccess->execute([$audit_id, $userId]);
        if (!$stmtAccess->fetch()) {
            $pageError = 'Audit not found or access denied.';
            $audit_id = 0;
            unset($_SESSION['active_audit_id']);
        }
    }

    if ($audit_id > 0) {
        $_SESSION['active_audit_id'] = $audit_id;
        updateAuditMetrics($pdo, $audit_id);
        $reportData = getReportData($pdo, $audit_id, $userId, $userRole);

        // Load latest saved AI report (if any)
        $savedAiReport = loadSavedAiReport($pdo, $audit_id);
    }
}

include 'includes/header.php';
include 'includes/sidebar.php';
?>

<style>
    .report-card { border: 1px solid #e5e7eb; border-radius: 10px; padding: 16px; margin-bottom: 16px; background: #fff; }
    .report-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; }
    .report-table { width: 100%; border-collapse: collapse; }
    .report-table th, .report-table td { border: 1px solid #e5e7eb; padding: 8px; text-align: left; }
    .report-table th { background: #f3f4f6; }
    .report-stats { display: flex; gap: 14px; flex-wrap: wrap; }
    .ai-report-content { line-height: 1.7; }
    .ai-report-content h3 { color: #1f2937; border-bottom: 2px solid #e5e7eb; padding-bottom: 8px; }
    .ai-report-content h4 { color: #374151; }
    .ai-report-content h5 { color: #4b5563; }
    .ai-report-content ul { padding-left: 20px; }
    .ai-report-content li { margin-bottom: 4px; }
    .ai-report-content strong { color: #1f2937; }
</style>

<div class="container mt-4">
    <h2 class="mb-4">Audit Report</h2>

    <div class="card shadow-sm mb-4">
        <div class="card-body">
            <h5 class="mb-3">Choose Organization & Audit Session</h5>
            <form id="reportAuditSwitcher" class="row g-2">
                <div class="col-md-5">
                    <select id="orgSelect" class="form-select">
                        <option value="">All Organization</option>
                        <?php foreach ($organizations as $org): ?>
                            <option value="<?= intval($org['id']) ?>" <?= $selectedOrgId === intval($org['id']) ? 'selected' : '' ?>>
                                <?= htmlspecialchars($org['organization_name']) ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="col-md-5">
                    <select id="auditSelect" class="form-select">
                        <option value="">Choose the Audit Session</option>
                        <?php foreach ($allAudits as $auditItem): ?>
                            <option value="<?= intval($auditItem['id']) ?>"
                                    data-org-id="<?= intval($auditItem['organization_id']) ?>"
                                    <?= $audit_id === intval($auditItem['id']) ? 'selected' : '' ?>>
                                <?= htmlspecialchars($auditItem['organization_name'] . ' - ' . $auditItem['session_name'] . ' (' . $auditItem['audit_date'] . ')') ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="col-md-2 d-grid">
                    <button class="btn btn-primary" type="submit">Open</button>
                </div>
            </form>
        </div>
    </div>

    <?php if (!empty($pageError)): ?>
        <div class="alert alert-danger"><?= htmlspecialchars($pageError) ?></div>
    <?php endif; ?>

    <?php if (!$audit_id): ?>
        <div class="alert alert-warning">Choose audit session first before see the report.</div>
    <?php elseif ($reportData): ?>
        <div class="d-flex flex-wrap gap-2 mb-3">
            <a class="btn btn-outline-secondary" href="api/report_actions.php?action=preview&audit_id=<?= intval($audit_id) ?>" target="_blank">Open Full Preview</a>
            <?php if ($userRole === 'auditor' || $userRole === 'admin'): ?>
                <a class="btn btn-outline-primary" href="api/report_actions.php?action=download_pdf&audit_id=<?= intval($audit_id) ?>">Download PDF</a>
            <?php endif; ?>
            <button class="btn btn-outline-dark" id="aiSummaryBtn" type="button">
                <?= !empty($savedAiReport['content']) ? 'Regenerate AI Summary' : 'Generate AI Summary' ?>
            </button>
        </div>

        <div class="report-card" id="aiSummaryCard">
            <h4>AI Executive Summary</h4>
            <?php if (!empty($savedAiReport['content'])): ?>
                <div id="aiSummaryText">
                    <div id="aiSavedReport"></div>
                    <hr>
                    <p class="text-muted text-end"><small>Generated by: <?= htmlspecialchars($savedAiReport['model'] ?? 'AI') ?> &mdash; <?= !empty($savedAiReport['created_at']) ? date('d M Y, H:i', strtotime($savedAiReport['created_at'])) : '' ?></small></p>
                </div>
                <script id="aiSavedRaw" type="application/json"><?= json_encode($savedAiReport['content']) ?></script>
            <?php else: ?>
                <p class="text-muted" id="aiSummaryText">Click the button to generate summary.</p>
            <?php endif; ?>
        </div>

        <div class="report-card">
            <h4>🔐 Audit Opinion</h4>
            <?php 
                $opinionData = calculateAuditOpinion($pdo, $audit_id);
                $opinion = $opinionData['opinion'];
                $opinionClass = $opinion === 'Secure' ? 'badge-srm-success' : ($opinion === 'Acceptable Risk' ? 'badge-srm-warning' : 'badge-srm-danger');
            ?>
            <h3 class="text-center">
                <span class="badge <?= $opinionClass ?>" style="font-size: 1.1em;">
                    <?= htmlspecialchars($opinion) ?>
                </span>
            </h3>
            <p class="text-center text-muted">
                Based on compliance (<?= number_format($opinionData['compliance'], 2) ?>%), 
                open Critical findings (<?= $opinionData['open_critical'] ?>), 
                open High findings (<?= $opinionData['open_high'] ?>)
            </p>
            <div class="text-center mt-2">
                <small class="text-muted">
                    <strong>Secure:</strong> ≥85% compliance &amp; no open High/Critical |
                    <strong>Acceptable:</strong> 60-84% compliance |
                    <strong>Immediate:</strong> &lt;60% compliance or any open Critical
                </small>
            </div>
        </div>

        <div class="report-card">
            <h4>Risk Matrix (Likelihood × Impact)</h4>
            <table class="report-table">
                <thead>
                    <tr>
                        <th style="width: 50px;">L\I</th>
                        <?php for ($i = 1; $i <= 5; $i++): ?>
                            <th style="text-align: center; width: 60px;">I<?= $i ?></th>
                        <?php endfor; ?>
                    </tr>
                </thead>
                <tbody>
                    <?php 
                        $matrix = getRiskMatrixData($pdo, $audit_id);
                        for ($l = 5; $l >= 1; $l--):
                    ?>
                        <tr>
                            <td><strong>L<?= $l ?></strong></td>
                            <?php for ($i = 1; $i <= 5; $i++): 
                                $cell = $matrix[$l][$i];
                                $bgColor = $cell['level'] === 'Critical' ? '#ff6b6b' : 
                                          ($cell['level'] === 'High' ? '#ffa94d' : 
                                          ($cell['level'] === 'Medium' ? '#ffe066' : '#a8e6cf'));
                                $count = $cell['count'];
                            ?>
                                <td style="background-color: <?= $bgColor ?>; text-align: center; font-weight: bold;">
                                    <?= $count > 0 ? $count : '—' ?>
                                </td>
                            <?php endfor; ?>
                        </tr>
                    <?php endfor; ?>
                </tbody>
            </table>
            <p class="text-muted text-center mt-2">
                <small>🔴 Critical | 🟠 High | 🟡 Medium | 🟢 Low</small>
            </p>
        </div>

        <?= renderReportHtml($reportData) ?>
    <?php endif; ?>
</div>

<script>
const orgSelect = document.getElementById('orgSelect');
const auditSelect = document.getElementById('auditSelect');

function filterAuditsByOrg() {
    const orgId = orgSelect.value;

    Array.from(auditSelect.options).forEach((opt, index) => {
        if (index === 0) {
            opt.hidden = false;
            return;
        }
        const optionOrgId = opt.dataset.orgId || '';
        opt.hidden = orgId !== '' && optionOrgId !== orgId;
    });

    if (auditSelect.selectedOptions.length && auditSelect.selectedOptions[0].hidden) {
        auditSelect.value = '';
    }
}

orgSelect.addEventListener('change', filterAuditsByOrg);
filterAuditsByOrg();

document.getElementById('reportAuditSwitcher').addEventListener('submit', function(e) {
    e.preventDefault();
    const selectedAuditId = auditSelect.value;
    const selectedOrgId = orgSelect.value;

    if (selectedAuditId) {
        window.location.href = 'report.php?audit_id=' + encodeURIComponent(selectedAuditId);
        return;
    }

    if (selectedOrgId) {
        window.location.href = 'report.php?org_id=' + encodeURIComponent(selectedOrgId);
    }
});

/** Simple markdown-to-HTML renderer for AI report output */
function renderMarkdown(md) {
    let html = md
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;') // escape HTML
        .replace(/^### (.+)$/gm, '<h5 class="mt-3 mb-2">$1</h5>')
        .replace(/^## (.+)$/gm, '<h4 class="mt-4 mb-2">$1</h4>')
        .replace(/^# (.+)$/gm, '<h3 class="mt-4 mb-3">$1</h3>')
        .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
        .replace(/\*(.+?)\*/g, '<em>$1</em>')
        .replace(/^[-*] (.+)$/gm, '<li>$1</li>')
        .replace(/^(\d+)\. (.+)$/gm, '<li>$2</li>')
        .replace(/(<li>.*<\/li>\n?)+/gs, function(m) {
            return '<ul class="mb-2">' + m + '</ul>';
        })
        .replace(/\n{2,}/g, '</p><p>')
        .replace(/\n/g, '<br>');
    return '<div class="ai-report-content"><p>' + html + '</p></div>';
}

const aiButton = document.getElementById('aiSummaryBtn');
if (aiButton) {
    aiButton.addEventListener('click', () => {
        const summaryText = document.getElementById('aiSummaryText');
        const summaryCard = document.getElementById('aiSummaryCard');
        aiButton.disabled = true;
        aiButton.textContent = 'Generating... (may take up to 60s)';
        summaryText.innerHTML = '<div class="text-center"><div class="spinner-border text-secondary" role="status"></div><p class="mt-2">Generating AI report, please wait...</p></div>';

        const formData = new FormData();
        formData.append('audit_id', '<?= intval($audit_id) ?>');

        fetch('api/ai_actions.php?action=generate_report', {
            method: 'POST',
            body: formData
        })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    summaryText.innerHTML = renderMarkdown(data.report_content);
                    summaryText.innerHTML += '<hr><p class="text-muted text-end"><small>Generated by: ' + data.ai_provider + '</small></p>';
                    summaryCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
                } else {
                    summaryText.innerHTML = '<div class="alert alert-danger">Error: ' + (data.message || data.error || 'Failed to generate report.') + '</div>';
                }
                aiButton.disabled = false;
                aiButton.textContent = 'Regenerate AI Summary';
            })
            .catch((error) => {
                summaryText.innerHTML = '<div class="alert alert-danger">Failed to generate report: ' + error.message + '</div>';
                aiButton.disabled = false;
                aiButton.textContent = 'Regenerate AI Summary';
            });
    });
}

// Render saved AI report markdown on page load
const savedRawScript = document.getElementById('aiSavedRaw');
if (savedRawScript) {
    try {
        const raw = JSON.parse(savedRawScript.textContent);
        const container = document.getElementById('aiSavedReport');
        if (container && raw) {
            container.innerHTML = renderMarkdown(raw);
        }
    } catch (e) {
        console.error('Failed to parse saved AI report:', e);
    }
}
</script>

<?php include 'includes/footer.php'; ?>