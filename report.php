<?php
session_start();
require_once 'functions/db.php';
require_once 'functions/auth.php';
require_once 'functions/risk.php';
require_once 'functions/report.php';

requireLogin();

$userId = $_SESSION['user_id'];
$audit_id = intval($_GET['audit_id'] ?? ($_SESSION['active_audit_id'] ?? 0));
$selectedOrgId = intval($_GET['org_id'] ?? 0);
$pageError = '';
$reportData = null;

$stmtOrgList = $pdo->prepare("SELECT id, organization_name FROM organizations WHERE user_id = ? AND is_active = 1 ORDER BY organization_name ASC");
$stmtOrgList->execute([$userId]);
$organizations = $stmtOrgList->fetchAll(PDO::FETCH_ASSOC);

$stmtAuditList = $pdo->prepare("SELECT a.id, a.organization_id, a.session_name, a.audit_date, o.organization_name FROM audit_sessions a JOIN organizations o ON a.organization_id = o.id WHERE o.user_id = ? ORDER BY a.audit_date DESC, a.created_at DESC");
$stmtAuditList->execute([$userId]);
$allAudits = $stmtAuditList->fetchAll(PDO::FETCH_ASSOC);

if ($audit_id > 0) {
    $stmtAccess = $pdo->prepare("SELECT a.id, a.organization_id FROM audit_sessions a JOIN organizations o ON a.organization_id = o.id WHERE a.id = ? AND o.user_id = ?");
    $stmtAccess->execute([$audit_id, $userId]);
    $access = $stmtAccess->fetch(PDO::FETCH_ASSOC);

    if (!$access) {
        $pageError = 'Audit not found or access denied.';
        $audit_id = 0;
        unset($_SESSION['active_audit_id']);
    } else {
        $selectedOrgId = intval($access['organization_id']);
        $_SESSION['active_audit_id'] = $audit_id;
        updateAuditMetrics($pdo, $audit_id);
        $reportData = getReportData($pdo, $audit_id, $userId);
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
            <a class="btn btn-outline-primary" href="api/report_actions.php?action=download_pdf&audit_id=<?= intval($audit_id) ?>">Download PDF</a>
            <button class="btn btn-outline-dark" id="aiSummaryBtn" type="button">Generate AI Summary</button>
        </div>

        <div class="report-card" id="aiSummaryCard">
            <h4>AI Executive Summary</h4>
            <p class="text-muted" id="aiSummaryText">Click the button to generate summary.</p>
        </div>

        <div class="report-card">
            <h4>🔐 Audit Opinion</h4>
            <?php 
                $opinion = calculateAuditOpinion($pdo, $audit_id);
                $opinionClass = $opinion === 'Secure' ? 'badge-srm-success' : ($opinion === 'Acceptable Risk' ? 'badge-srm-warning' : 'badge-srm-danger');
            ?>
            <h3 class="text-center">
                <span class="badge <?= $opinionClass ?>" style="font-size: 1.1em;">
                    <?= htmlspecialchars($opinion) ?>
                </span>
            </h3>
            <p class="text-center text-muted">
                Based on compliance (<?= number_format((float)($reportData['audit']['compliance_percentage'] ?? 0), 2) ?>%), 
                risk level (<?= htmlspecialchars($reportData['audit']['final_risk_level'] ?? 'Low') ?>), 
                and exposure (<?= htmlspecialchars($reportData['audit']['exposure_level'] ?? 'Low') ?>)
            </p>
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

const aiButton = document.getElementById('aiSummaryBtn');
if (aiButton) {
    aiButton.addEventListener('click', () => {
        const summaryText = document.getElementById('aiSummaryText');
        aiButton.disabled = true;
        aiButton.textContent = 'Generating...';
        summaryText.textContent = 'Generating AI report, please wait...';

        const formData = new FormData();
        formData.append('audit_id', '<?= intval($audit_id) ?>');

        fetch('api/ai_actions.php?action=generate_report', {
            method: 'POST',
            body: formData
        })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    summaryText.innerHTML = '<div style="white-space: pre-wrap;">' + data.report_content + '</div>';
                    summaryText.innerHTML += '<p class="text-muted mt-3"><small>Generated by: ' + data.ai_provider + '</small></p>';
                } else {
                    summaryText.textContent = 'Error: ' + (data.message || data.error || 'Failed to generate report.');
                }
                aiButton.disabled = false;
                aiButton.textContent = 'Generate AI Summary';
            })
            .catch((error) => {
                summaryText.textContent = 'Failed to generate report: ' + error.message;
                aiButton.disabled = false;
                aiButton.textContent = 'Generate AI Summary';
            });
    });
}
</script>

<?php include 'includes/footer.php'; ?>