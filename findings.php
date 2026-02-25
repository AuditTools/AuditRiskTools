<?php
session_start();
require_once 'functions/db.php';
require_once 'functions/auth.php';

requireLogin();

$userId   = $_SESSION['user_id'];
$audit_id = intval($_GET['audit_id'] ?? ($_SESSION['active_audit_id'] ?? 0));
$selectedOrgId = intval($_GET['org_id'] ?? 0);
$pageError = '';

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
    }
}

/* ===============================
   Ambil Assets untuk dropdown
================================ */
$assets = [];
if ($audit_id) {
    $stmt = $pdo->prepare("
        SELECT id, asset_name 
        FROM assets 
        WHERE audit_id = ?
    ");
    $stmt->execute([$audit_id]);
    $assets = $stmt->fetchAll(PDO::FETCH_ASSOC);
}

/* ===============================
   Ambil Findings List
================================ */
$findings = [];
if ($audit_id) {
    $stmt2 = $pdo->prepare("
        SELECT f.*, a.asset_name
        FROM findings f
        JOIN assets a ON f.asset_id = a.id
        WHERE f.audit_id = ?
        ORDER BY f.created_at DESC
    ");
    $stmt2->execute([$audit_id]);
    $findings = $stmt2->fetchAll(PDO::FETCH_ASSOC);
}
?>

<?php include 'includes/header.php'; ?>
<?php include 'includes/sidebar.php'; ?>

<div class="container mt-4">

<h2 class="mb-4">Vulnerability & Risk Assessment</h2>

<div class="card shadow-sm mb-4">
<div class="card-body">
<h5 class="mb-3">Pilih Organization & Audit Session</h5>
<form id="findingAuditSwitcher" class="row g-2">
    <div class="col-md-5">
        <select id="orgSelect" class="form-select">
            <option value="">Semua Organization</option>
            <?php foreach ($organizations as $org): ?>
                <option value="<?= intval($org['id']) ?>" <?= $selectedOrgId === intval($org['id']) ? 'selected' : '' ?>>
                    <?= htmlspecialchars($org['organization_name']) ?>
                </option>
            <?php endforeach; ?>
        </select>
    </div>
    <div class="col-md-5">
        <select id="auditSelect" class="form-select">
            <option value="">Pilih Audit Session</option>
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
        <button class="btn btn-primary" type="submit">Buka</button>
    </div>
</form>
</div>
</div>

<?php if (!empty($pageError)): ?>
    <div class="alert alert-danger"><?= htmlspecialchars($pageError) ?></div>
<?php endif; ?>

<?php if (!$audit_id): ?>
    <div class="alert alert-warning">Pilih audit session dulu untuk mengelola findings.</div>
<?php else: ?>

<div class="card shadow-sm mb-4">
<div class="card-body">

<h5 class="mb-3">Add New Finding</h5>

<form id="findingForm">

<input type="hidden" name="audit_id" value="<?= $audit_id ?>">
<?= csrfTokenInput() ?>

<div class="row mb-3">
    <div class="col-md-6">
        <label>Asset</label>
        <select class="form-select" name="asset_id" required>
            <option value="">Select Asset</option>
            <?php foreach ($assets as $asset): ?>
                <option value="<?= $asset['id'] ?>">
                    <?= htmlspecialchars($asset['asset_name']) ?>
                </option>
            <?php endforeach; ?>
        </select>
    </div>

    <div class="col-md-6">
        <label>NIST Function</label>
        <select class="form-select" name="nist_function">
            <option>Identify</option>
            <option>Protect</option>
            <option>Detect</option>
            <option>Respond</option>
            <option>Recover</option>
        </select>
    </div>
</div>

<div class="mb-3">
    <label>Compliance Status</label>
    <select class="form-select" name="audit_status" required>
        <option value="Compliant">Compliant</option>
        <option value="Partially Compliant">Partially Compliant</option>
        <option value="Non-Compliant" selected>Non-Compliant</option>
    </select>
</div>

<div class="mb-3">
    <label>Title</label>
    <input type="text" name="title" class="form-control" required>
</div>

<div class="mb-3">
    <label>Description</label>
    <textarea name="description" class="form-control"></textarea>
</div>

<div class="row mb-3">
    <div class="col-md-6">
        <label>Likelihood (1–5)</label>
        <input type="range"
               min="1"
               max="5"
               value="1"
               class="form-range"
               id="likelihood"
               name="likelihood">
        <div>Value: <span id="likeValue">1</span></div>
    </div>

    <div class="col-md-6">
        <label>Impact (1–5)</label>
        <input type="range"
               min="1"
               max="5"
               value="1"
               class="form-range"
               id="impact"
               name="impact">
        <div>Value: <span id="impactValue">1</span></div>
    </div>
</div>

<div class="alert alert-secondary">
    Risk Score:
    <span id="riskBadge" class="badge bg-success">1</span>
</div>

<button type="submit" class="btn btn-danger">
    Save Finding
</button>

</form>
</div>
</div>

<div class="card shadow-sm">
<div class="card-body">

<h5 class="mb-3">Findings List</h5>

<table class="table table-bordered">
<thead class="table-dark">
<tr>
    <th>Asset</th>
    <th>Title</th>
    <th>Risk Score</th>
    <th>NIST</th>
    <th>Compliance</th>
    <th>Remediation</th>
</tr>
</thead>
<tbody>

<?php if (count($findings) > 0): ?>
    <?php foreach ($findings as $f): ?>
        <tr>
            <td><?= htmlspecialchars($f['asset_name']) ?></td>
            <td><?= htmlspecialchars($f['title']) ?></td>
            <td>
                <span class="badge bg-danger">
                    <?= $f['risk_score'] ?>
                </span>
            </td>
            <td><?= htmlspecialchars($f['nist_function']) ?></td>
            <td><?= htmlspecialchars($f['audit_status'] ?? 'Non-Compliant') ?></td>
            <td style="min-width: 280px;">
                <form class="remediationForm d-flex gap-2 align-items-center" data-finding-id="<?= intval($f['id']) ?>">
                    <input type="hidden" name="finding_id" value="<?= intval($f['id']) ?>">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generateCSRFToken()) ?>">
                    <select name="remediation_status" class="form-select form-select-sm">
                        <?php
                        $remediationStatuses = ['Open', 'In Progress', 'Resolved', 'Accepted Risk'];
                        $currentStatus = $f['remediation_status'] ?? 'Open';
                        foreach ($remediationStatuses as $statusOption):
                        ?>
                            <option value="<?= htmlspecialchars($statusOption) ?>" <?= $currentStatus === $statusOption ? 'selected' : '' ?>>
                                <?= htmlspecialchars($statusOption) ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                    <input type="date" name="remediation_deadline" value="<?= htmlspecialchars($f['remediation_deadline'] ?? '') ?>" class="form-control form-control-sm">
                    <button type="submit" class="btn btn-sm btn-outline-primary">Save</button>
                </form>
            </td>
        </tr>
    <?php endforeach; ?>
<?php else: ?>
    <tr>
        <td colspan="6" class="text-center">No findings yet</td>
    </tr>
<?php endif; ?>

</tbody>
</table>

</div>
</div>

</div>

<?php endif; ?>

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

document.getElementById('findingAuditSwitcher').addEventListener('submit', function(e) {
    e.preventDefault();
    const selectedAuditId = auditSelect.value;
    const selectedOrgId = orgSelect.value;

    if (selectedAuditId) {
        window.location.href = 'findings.php?audit_id=' + encodeURIComponent(selectedAuditId);
        return;
    }

    if (selectedOrgId) {
        window.location.href = 'findings.php?org_id=' + encodeURIComponent(selectedOrgId);
    }
});

<?php if ($audit_id): ?>
const likelihood  = document.getElementById('likelihood');
const impact      = document.getElementById('impact');
const likeValue   = document.getElementById('likeValue');
const impactValue = document.getElementById('impactValue');
const riskBadge   = document.getElementById('riskBadge');

function updateRisk() {
    const risk = likelihood.value * impact.value;
    riskBadge.textContent = risk;

    let color = "bg-success";
    if (risk >= 6)  color = "bg-warning";
    if (risk >= 13) color = "bg-danger";

    riskBadge.className = "badge " + color;
}

likelihood.addEventListener('input', () => {
    likeValue.textContent = likelihood.value;
    updateRisk();
});

impact.addEventListener('input', () => {
    impactValue.textContent = impact.value;
    updateRisk();
});

document.getElementById('findingForm').addEventListener('submit', function(e) {
    e.preventDefault();

    const formData = new FormData(this);

    fetch('api/finding_actions.php', {
        method: 'POST',
        body: formData
    })
    
    .then(res => res.json())
    .then(data => {
        if (data.success) {
            location.reload();
        } else {
            alert(data.message);
        }
    })
    .catch(() => alert("Error saving finding"));
});

document.querySelectorAll('.remediationForm').forEach((form) => {
    form.addEventListener('submit', function(e) {
        e.preventDefault();

        const formData = new FormData(this);

        fetch('api/finding_actions.php?action=update_remediation', {
            method: 'POST',
            body: formData
        })
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                location.reload();
            } else {
                alert(data.message);
            }
        })
        .catch(() => alert('Error updating remediation'));
    });
});
<?php endif; ?>
</script>

<?php 
// Include chatbot widget (only for logged-in users)
if (file_exists('includes/chatbot.html')) {
    readfile('includes/chatbot.html');
}
?>

<?php include 'includes/footer.php'; ?>