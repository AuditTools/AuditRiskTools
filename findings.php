<?php
session_start();
require_once 'functions/db.php';
require_once 'functions/auth.php';
require_once 'functions/risk.php';
require_once 'functions/owasp.php';
require_once 'functions/nist.php';

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

<form id="findingForm" enctype="multipart/form-data">

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
        <select class="form-select" name="nist_function" id="nistFunctionSelect">
            <option>Identify</option>
            <option>Protect</option>
            <option>Detect</option>
            <option>Respond</option>
            <option>Recover</option>
        </select>
    </div>
</div>

<div class="row mb-3">
    <div class="col-md-6">
        <label>OWASP Category</label>
        <select class="form-select" name="owasp_category" id="owaspSelect">
            <option value="">Select OWASP Issue (Optional)</option>
            <?php 
            $owaspLib = getOwaspLibrary();
            foreach ($owaspLib as $owasp): 
            ?>
                <option value="<?= htmlspecialchars($owasp['title']) ?>" 
                        data-cwe="<?= htmlspecialchars($owasp['cwe']) ?>"
                        data-nist="<?= htmlspecialchars($owasp['nist_function']) ?>">
                    <?= htmlspecialchars($owasp['title']) ?> (CWE: <?= htmlspecialchars($owasp['cwe']) ?>)
                </option>
            <?php endforeach; ?>
        </select>
    </div>

    <div class="col-md-6">
        <label>Recommended NIST Controls</label>
        <div id="nistControlsList" class="border p-2 bg-light" style="max-height: 150px; overflow-y: auto;">
            <small class="text-muted">Select NIST Function above to see controls</small>
        </div>
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
    <textarea name="description" class="form-control" rows="2"></textarea>
</div>

<div class="mb-3">
    <label>Recommendation</label>
    <textarea name="recommendation" class="form-control" rows="2" placeholder="Suggested remediation action..."></textarea>
</div>

<div class="mb-3">
    <label>Evidence Files</label>
    <input type="file" name="evidence_file" class="form-control" accept=".jpg,.jpeg,.png,.pdf,.doc,.docx,.xls,.xlsx,.txt" multiple>
    <small class="text-muted d-block mt-1">Upload evidence: images, PDF, Word, Excel, or text files (Max 10MB each)</small>
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

<div class="mb-3">
    <a href="vulnerability_assessment.php?audit_id=<?= $audit_id ?>" class="btn btn-outline-danger btn-sm">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-shield-exclamation me-1" viewBox="0 0 16 16">
            <path d="M5.338 1.59a61 61 0 0 0-2.837.856.48.48 0 0 0-.328.39c-.554 4.157.726 7.19 2.253 9.188a10.7 10.7 0 0 0 2.287 2.233c.346.244.652.42.893.533q.18.085.293.118a1 1 0 0 0 .101.025 1 1 0 0 0 .1-.025q.114-.034.294-.118c.24-.113.547-.29.893-.533a10.7 10.7 0 0 0 2.287-2.233c1.527-1.997 2.807-5.031 2.253-9.188a.48.48 0 0 0-.328-.39c-.651-.213-1.75-.56-2.837-.855C9.552 1.29 8.531 1.067 8 1.067s-1.552.223-2.662.524zM5.072.56C6.157.265 7.31 0 8 0s1.843.265 2.928.56c1.11.3 2.229.655 2.887.87a1.54 1.54 0 0 1 1.044 1.262c.596 4.477-.787 7.795-2.465 9.99a11.8 11.8 0 0 1-2.517 2.453 7 7 0 0 1-1.048.625c-.28.132-.581.24-.829.24s-.548-.108-.829-.24a7 7 0 0 1-1.048-.625 11.8 11.8 0 0 1-2.517-2.453C1.928 10.487.545 7.169 1.141 2.692A1.54 1.54 0 0 1 2.185 1.43 63 63 0 0 1 5.072.56"/>
            <path d="M7.001 11a1 1 0 1 1 2 0 1 1 0 0 1-2 0M7.1 4.995a.905.905 0 1 1 1.8 0l-.35 3.507a.553.553 0 0 1-1.1 0z"/>
        </svg>
        OWASP Vulnerability Assessment
    </a>
</div>

<table class="table table-bordered">
<thead class="table-dark">
<tr>
    <th>Asset</th>
    <th>Title</th>
    <th>OWASP</th>
    <th>Risk Score</th>
    <th>NIST</th>
    <th>Compliance</th>
    <th>Recommendation</th>
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
                <?php if (!empty($f['owasp_category'])): ?>
                    <span class="badge bg-info"><?= htmlspecialchars($f['owasp_category']) ?></span>
                <?php else: ?>
                    <span class="text-muted">—</span>
                <?php endif; ?>
            </td>
            <td>
                <span class="badge bg-danger">
                    <?= $f['risk_score'] ?>
                </span>
            </td>
            <td><?= htmlspecialchars($f['nist_function']) ?></td>
            <td><?= htmlspecialchars($f['audit_status'] ?? 'Non-Compliant') ?></td>
            <td style="max-width:200px; font-size:0.85rem;">
                <?= !empty($f['recommendation']) ? htmlspecialchars(mb_strimwidth($f['recommendation'], 0, 120, '...')) : '<span class="text-muted">—</span>' ?>
            </td>
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
        <tr>
            <td colspan="8">
                <details>
                    <summary class="cursor-pointer" style="cursor: pointer;">
                        <strong>Evidence Files</strong> 
                        <?php 
                        // Retrieve evidence count
                        $stmtEv = $pdo->prepare("SELECT COUNT(*) as count FROM audit_evidence WHERE finding_id = ?");
                        $stmtEv->execute([$f['id']]);
                        $eviCount = $stmtEv->fetch(PDO::FETCH_ASSOC)['count'];
                        echo '(' . $eviCount . ')';
                        ?>
                    </summary>
                    <div class="p-3 bg-light mt-2">
                        <?php
                        // Fetch evidence for this finding
                        $stmtEvi = $pdo->prepare("SELECT id, original_filename, stored_filename, file_path, evidence_type, created_at FROM audit_evidence WHERE finding_id = ? ORDER BY created_at DESC");
                        $stmtEvi->execute([$f['id']]);
                        $evidence = $stmtEvi->fetchAll(PDO::FETCH_ASSOC);
                        
                        if (count($evidence) > 0):
                        ?>
                            <table class="table table-sm">
                                <thead><tr><th>File</th><th>Type</th><th>Uploaded</th><th>Action</th></tr></thead>
                                <tbody>
                                    <?php foreach ($evidence as $evi): ?>
                                    <tr>
                                        <td><?= htmlspecialchars($evi['original_filename']) ?></td>
                                        <td><small><?= htmlspecialchars($evi['evidence_type']) ?></small></td>
                                        <td><small><?= date('M d, Y', strtotime($evi['created_at'])) ?></small></td>
                                        <td>
                                            <a href="<?= htmlspecialchars($evi['file_path']) ?>" class="btn btn-sm btn-outline-info" target="_blank">
                                                View
                                            </a>
                                            <button class="btn btn-sm btn-outline-danger deleteEviBtn" data-evi-id="<?= intval($evi['id']) ?>">
                                                Delete
                                            </button>
                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        <?php else: ?>
                            <p class="text-muted">No evidence files uploaded yet.</p>
                        <?php endif; ?>
                        
                        <hr>
                        <form class="evidenceUploadForm" enctype="multipart/form-data" data-finding-id="<?= intval($f['id']) ?>">
                            <input type="hidden" name="finding_id" value="<?= intval($f['id']) ?>">
                            <input type="hidden" name="audit_id" value="<?= intval($audit_id) ?>">
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generateCSRFToken()) ?>">
                            <input type="file" name="evidence_file" class="form-control form-control-sm mb-2" accept=".jpg,.jpeg,.png,.pdf,.doc,.docx,.xls,.xlsx,.txt" multiple>
                            <button type="submit" class="btn btn-sm btn-primary">Upload Evidence</button>
                        </form>
                    </div>
                </details>
            </td>
        </tr>
    <?php endforeach; ?>
<?php else: ?>
    <tr>
        <td colspan="8" class="text-center">No findings yet</td>
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

// NIST Controls mapping
const nistControlsData = <?php echo json_encode(getNistControlsChecklist()); ?>;

function updateNistControls() {
    const nistFunction = document.getElementById('nistFunctionSelect').value;
    const nistControlsList = document.getElementById('nistControlsList');
    
    if (nistFunction && nistControlsData[nistFunction]) {
        const controls = nistControlsData[nistFunction];
        nistControlsList.innerHTML = controls.map(ctrl => 
            `<div class="form-check">
                <input class="form-check-input" type="checkbox" id="control_${ctrl.id}" value="${ctrl.id}" name="nist_controls">
                <label class="form-check-label" for="control_${ctrl.id}">
                    <small><strong>${ctrl.control_id}:</strong> ${ctrl.description}</small>
                </label>
            </div>`
        ).join('');
    } else {
        nistControlsList.innerHTML = '<small class="text-muted">Select NIST Function above to see controls</small>';
    }
}

document.getElementById('nistFunctionSelect').addEventListener('change', updateNistControls);
updateNistControls();

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

// Evidence upload handlers
document.querySelectorAll('.evidenceUploadForm').forEach((form) => {
    form.addEventListener('submit', function(e) {
        e.preventDefault();

        const formData = new FormData(this);

        fetch('api/evidence_actions.php', {
            method: 'POST',
            body: formData
        })
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                location.reload();
            } else {
                alert(data.message || 'Error uploading evidence');
            }
        })
        .catch(() => alert('Error uploading evidence'));
    });
});

// Evidence delete handlers
document.querySelectorAll('.deleteEviBtn').forEach((btn) => {
    btn.addEventListener('click', function(e) {
        e.preventDefault();
        
        if (!confirm('Delete this evidence file?')) return;
        
        const eviId = this.dataset.eviId;
        
        fetch('api/evidence_actions.php?action=delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: eviId, csrf_token: '<?= htmlspecialchars(generateCSRFToken()) ?>' })
        })
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                location.reload();
            } else {
                alert(data.message || 'Error deleting evidence');
            }
        })
        .catch(() => alert('Error deleting evidence'));
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