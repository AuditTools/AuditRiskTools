<?php
session_start();
require_once 'functions/db.php';
require_once 'functions/auth.php';

requireLogin();

$userId = $_SESSION['user_id'];
$userRole = $_SESSION['user_role'] ?? 'auditor';
$audit_id = intval($_GET['audit_id'] ?? ($_SESSION['active_audit_id'] ?? 0));
$selectedOrgId = intval($_GET['org_id'] ?? 0);
$assets = [];
$pageError = '';

// Role-based data loading
if ($userRole === 'auditee') {
    // Auditee: only see assigned audits
    $assignedAudits = getAuditeeAssignedAudits($pdo, $userId);
    $organizations = [];
    
    if (count($assignedAudits) > 0) {
        $placeholders = implode(',', array_fill(0, count($assignedAudits), '?'));
        $stmtAuditList = $pdo->prepare("SELECT a.id, a.organization_id, a.session_name, a.audit_date, o.organization_name 
            FROM audit_sessions a JOIN organizations o ON a.organization_id = o.id 
            WHERE a.id IN ($placeholders) ORDER BY a.audit_date DESC");
        $stmtAuditList->execute($assignedAudits);
        $allAudits = $stmtAuditList->fetchAll(PDO::FETCH_ASSOC);
    } else {
        $allAudits = [];
    }

    if ($audit_id > 0 && !in_array($audit_id, $assignedAudits)) {
        $pageError = 'You are not assigned to this audit.';
        $audit_id = 0;
    }
} else {
    // Admin/Auditor
    if ($userRole === 'auditor') {
        // Auditor owns orgs
    } else {
        // Admin: can view but not manage
    }
    
    $stmtOrgList = $pdo->prepare("SELECT id, organization_name FROM organizations WHERE user_id = ? AND is_active = 1 ORDER BY organization_name ASC");
    $stmtOrgList->execute([$userId]);
    $organizations = $stmtOrgList->fetchAll(PDO::FETCH_ASSOC);

    $stmtAuditList = $pdo->prepare("SELECT a.id, a.organization_id, a.session_name, a.audit_date, o.organization_name FROM audit_sessions a JOIN organizations o ON a.organization_id = o.id WHERE o.user_id = ? ORDER BY a.audit_date DESC, a.created_at DESC");
    $stmtAuditList->execute([$userId]);
    $allAudits = $stmtAuditList->fetchAll(PDO::FETCH_ASSOC);
}

if ($audit_id > 0 && empty($pageError)) {
    if ($userRole === 'auditee') {
        $_SESSION['active_audit_id'] = $audit_id;
        $stmt = $pdo->prepare("SELECT * FROM assets WHERE audit_id = ?");
        $stmt->execute([$audit_id]);
        $assets = $stmt->fetchAll(PDO::FETCH_ASSOC);
        $selectedOrgId = 0;
    } else {
        $stmt = $pdo->prepare("SELECT a.id, a.organization_id FROM audit_sessions a JOIN organizations o ON a.organization_id = o.id WHERE a.id = ? AND o.user_id = ?");
        $stmt->execute([$audit_id, $userId]);
        $auditAccess = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$auditAccess) {
            $pageError = 'Audit not found or access denied.';
            $audit_id = 0;
            unset($_SESSION['active_audit_id']);
        } else {
            $selectedOrgId = intval($auditAccess['organization_id']);
            $_SESSION['active_audit_id'] = $audit_id;

            $stmt = $pdo->prepare("SELECT * FROM assets WHERE audit_id = ?");
            $stmt->execute([$audit_id]);
            $assets = $stmt->fetchAll(PDO::FETCH_ASSOC);
        }
    }
}
?>

<?php include 'includes/header.php'; ?>
<?php include 'includes/sidebar.php'; ?>

<div class="container mt-4">

    <h2 class="mb-4">
        <?= $userRole === 'auditee' ? 'Asset Registration' : 'Asset Management' ?>
    </h2>

    <div class="card shadow-sm mb-4">
        <div class="card-body">
            <h5 class="mb-3">Choose Organization & Audit Session</h5>
            <form id="assetAuditSwitcher" class="row g-2">
                <?php if ($userRole !== 'auditee'): ?>
                <div class="col-md-5">
                    <select id="orgSelect" class="form-select">
                        <option value="">All Organizations</option>
                        <?php foreach ($organizations as $org): ?>
                            <option value="<?= intval($org['id']) ?>" <?= $selectedOrgId === intval($org['id']) ? 'selected' : '' ?>>
                                <?= htmlspecialchars($org['organization_name']) ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="col-md-5">
                <?php else: ?>
                <div class="col-md-10">
                <?php endif; ?>
                    <select id="auditSelect" class="form-select">
                        <option value="">Choose Audit Session</option>
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
        <div class="alert alert-warning">Choose an audit session first to manage assets.</div>
    <?php else: ?>

    <!-- Add Asset Form (Auditee only — GRC Segregation of Duties) -->
    <?php if ($userRole === 'auditee'): ?>
    <div class="card shadow-sm mb-4">
        <div class="card-header bg-info text-white">
            <h5 class="mb-0">Register New Asset</h5>
            <small>Register assets for auditor review. CIA ratings will be set by the auditor.</small>
        </div>
        <div class="card-body">

            <form id="assetForm">

                <input type="hidden" name="audit_id" value="<?= $audit_id ?>">
                <?= csrfTokenInput(); ?>

                <div class="row mb-3">
                    <div class="col-md-4">
                        <label>Asset Name *</label>
                        <input type="text" name="asset_name" class="form-control" required>
                    </div>

                    <div class="col-md-4">
                        <label>IP Address / Location</label>
                        <input type="text" name="ip_address" class="form-control" placeholder="e.g. 192.168.1.1 or Room A">
                    </div>

                    <div class="col-md-4">
                        <label>Asset Type *</label>
                        <select name="asset_type" class="form-select" required>
                            <option value="">Select Type</option>
                            <option value="Server">Server</option>
                            <option value="Workstation">Workstation</option>
                            <option value="Network Device">Network Device</option>
                            <option value="Database">Database</option>
                            <option value="Application">Application</option>
                            <option value="Cloud Service">Cloud Service</option>
                            <option value="Mobile Device">Mobile Device</option>
                            <option value="Other">Other</option>
                        </select>
                    </div>
                </div>

                <div class="row mb-3">
                    <div class="col-md-4">
                        <label>Owner</label>
                        <input type="text" name="owner" class="form-control" placeholder="Person responsible">
                    </div>
                    <div class="col-md-4">
                        <label>Department</label>
                        <input type="text" name="department" class="form-control" placeholder="Department / Division">
                    </div>
                    <div class="col-md-4">
                        <label>Description</label>
                        <input type="text" name="description" class="form-control" placeholder="Brief description">
                    </div>
                </div>

                <?php /* Auditee: CIA defaults to 1 (pending auditor review) */ ?>
                <input type="hidden" name="confidentiality" value="1">
                <input type="hidden" name="integrity" value="1">
                <input type="hidden" name="availability" value="1">

                <button type="submit" class="btn btn-primary">
                    Register Asset
                </button>

            </form>

        </div>
    </div>
    <?php endif; ?>

    <!-- Asset Table -->
    <div class="card shadow-sm mb-4">
        <div class="card-header">
            <h5 class="mb-0">Asset Inventory (<?= count($assets) ?>)</h5>
        </div>
        <div class="card-body p-0">
    <table class="table table-bordered mb-0">
        <thead class="table-dark">
            <tr>
                <th>Asset</th>
                <th>Type</th>
                <th>Owner</th>
                <th>IP / Location</th>
                <th>CIA</th>
                <th>Criticality</th>
                <th>Level</th>
                <?php if ($userRole === 'auditor'): ?>
                    <th>Actions</th>
                <?php endif; ?>
            </tr>
        </thead>
        <tbody>
        <?php if (count($assets) > 0): ?>
            <?php foreach ($assets as $asset): ?>
                <tr>
                    <td><?= htmlspecialchars($asset['asset_name']) ?></td>
                    <td><?= htmlspecialchars($asset['asset_type']) ?></td>
                    <td><?= htmlspecialchars($asset['owner'] ?? '—') ?></td>
                    <td><?= htmlspecialchars($asset['ip_address'] ?? '—') ?></td>
                    <td>
                        <?= $asset['confidentiality'] ?>/<?= $asset['integrity'] ?>/<?= $asset['availability'] ?>
                    </td>
                    <td><?= $asset['criticality_score'] ?></td>
                    <td>
                        <?php
                        $criticalityLevel = $asset['criticality_level'] ?? 'Low';
                        $criticalityBadgeClass = 'badge-srm-info';
                        if ($criticalityLevel === 'Critical' || $criticalityLevel === 'High') {
                            $criticalityBadgeClass = 'badge-srm-danger';
                        } elseif ($criticalityLevel === 'Medium') {
                            $criticalityBadgeClass = 'badge-srm-warning';
                        } elseif ($criticalityLevel === 'Low') {
                            $criticalityBadgeClass = 'badge-srm-success';
                        }
                        ?>
                        <span class="badge <?= $criticalityBadgeClass ?>">
                            <?= $asset['criticality_level'] ?>
                        </span>
                    </td>
                    <?php if ($userRole === 'auditor'): ?>
                    <td>
                        <button class="btn btn-sm btn-outline-primary editCiaBtn" 
                                data-asset-id="<?= $asset['id'] ?>"
                                data-asset-name="<?= htmlspecialchars($asset['asset_name']) ?>"
                                data-c="<?= $asset['confidentiality'] ?>"
                                data-i="<?= $asset['integrity'] ?>"
                                data-a="<?= $asset['availability'] ?>">
                            <i class="fas fa-edit"></i> Set CIA
                        </button>
                    </td>
                    <?php endif; ?>
                </tr>
            <?php endforeach; ?>
        <?php else: ?>
            <tr>
                <td colspan="<?= $userRole === 'auditor' ? 8 : 7 ?>" class="text-center">No assets yet</td>
            </tr>
        <?php endif; ?>
        </tbody>
    </table>
        </div>
    </div>

    <?php if ($userRole === 'auditor'): ?>
    <div class="d-flex gap-2">
        <a href="vulnerability_assessment.php?audit_id=<?= $audit_id ?>" class="btn btn-outline-danger">
            Vulnerability Assessment
        </a>
        <a href="findings.php?audit_id=<?= $audit_id ?>" class="btn btn-outline-warning">
            Go to Findings
        </a>
    </div>
    <?php endif; ?>

    <?php endif; ?>

</div>

<script>
const orgSelect = document.getElementById('orgSelect');
const auditSelect = document.getElementById('auditSelect');

function filterAuditsByOrg() {
    if (!orgSelect) return;
    const orgId = orgSelect.value;

    Array.from(auditSelect.options).forEach((opt, index) => {
        if (index === 0) { opt.hidden = false; return; }
        const optionOrgId = opt.dataset.orgId || '';
        opt.hidden = orgId !== '' && optionOrgId !== orgId;
    });

    if (auditSelect.selectedOptions.length && auditSelect.selectedOptions[0].hidden) {
        auditSelect.value = '';
    }
}

if (orgSelect) {
    orgSelect.addEventListener('change', filterAuditsByOrg);
    filterAuditsByOrg();
}

document.getElementById('assetAuditSwitcher').addEventListener('submit', function(e) {
    e.preventDefault();
    const selectedAuditId = auditSelect.value;
    const selectedOrgId = orgSelect ? orgSelect.value : '';

    if (selectedAuditId) {
        window.location.href = 'asset_manage.php?audit_id=' + encodeURIComponent(selectedAuditId);
        return;
    }

    if (selectedOrgId) {
        window.location.href = 'asset_manage.php?org_id=' + encodeURIComponent(selectedOrgId);
    }
});

<?php if ($audit_id): ?>
document.getElementById('assetForm').addEventListener('submit', function(e) {
    e.preventDefault();

    const submitBtn = this.querySelector('button[type="submit"]');
    const originalBtnHtml = submitBtn ? submitBtn.innerHTML : '';
    if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.innerHTML = '⏳ Saving...';
    }

    const formData = new FormData(this);

    <?php if ($userRole === 'auditee'): ?>
    // Auditee uses a dedicated add action that allows auditee role
    fetch('api/asset_actions.php?action=auditee_add', {
        method: 'POST',
        body: formData
    })
    <?php else: ?>
    fetch('api/asset_actions.php?action=add', {
        method: 'POST',
        body: formData
    })
    <?php endif; ?>
    .then(async (res) => {
        const raw = await res.text();
        let data;

        try {
            data = JSON.parse(raw);
        } catch (err) {
            throw new Error(raw || `HTTP ${res.status}`);
        }

        if (!res.ok || !data.success) {
            throw new Error(data.message || `HTTP ${res.status}`);
        }

        return data;
    })
    .then(data => {
        location.reload();
    })
    .catch((error) => alert("Error adding asset: " + error.message))
    .finally(() => {
        if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.innerHTML = originalBtnHtml;
        }
    });
});

<?php if ($userRole === 'auditor'): ?>
// CIA Edit modal for auditor
document.querySelectorAll('.editCiaBtn').forEach(btn => {
    btn.addEventListener('click', function() {
        const assetId = this.dataset.assetId;
        const assetName = this.dataset.assetName;
        const c = this.dataset.c;
        const i = this.dataset.i;
        const a = this.dataset.a;
        
        const html = `
            <div class="modal fade" id="ciaModal" tabindex="-1">
                <div class="modal-dialog">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">Set CIA for: ${assetName}</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body">
                            <div class="mb-3">
                                <label>Confidentiality (1-5)</label>
                                <input type="number" min="1" max="5" id="editC" class="form-control" value="${c}">
                            </div>
                            <div class="mb-3">
                                <label>Integrity (1-5)</label>
                                <input type="number" min="1" max="5" id="editI" class="form-control" value="${i}">
                            </div>
                            <div class="mb-3">
                                <label>Availability (1-5)</label>
                                <input type="number" min="1" max="5" id="editA" class="form-control" value="${a}">
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                            <button type="button" class="btn btn-primary" id="saveCiaBtn">Save CIA Ratings</button>
                        </div>
                    </div>
                </div>
            </div>`;
        
        // Remove existing modal if any
        const existing = document.getElementById('ciaModal');
        if (existing) existing.remove();
        
        document.body.insertAdjacentHTML('beforeend', html);
        const modal = new bootstrap.Modal(document.getElementById('ciaModal'));
        modal.show();
        
        document.getElementById('saveCiaBtn').addEventListener('click', function() {
            const fd = new FormData();
            fd.append('id', assetId);
            fd.append('confidentiality', document.getElementById('editC').value);
            fd.append('integrity', document.getElementById('editI').value);
            fd.append('availability', document.getElementById('editA').value);
            fd.append('csrf_token', '<?= htmlspecialchars(generateCSRFToken()) ?>');
            
            fetch('api/asset_actions.php?action=update_cia', {
                method: 'POST',
                body: fd
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    location.reload();
                } else {
                    alert(data.message);
                }
            });
        });
    });
});
<?php endif; ?>
<?php endif; ?>
</script>

<?php 
// Include chatbot widget (only for logged-in users)
if (file_exists('includes/chatbot.html')) {
    readfile('includes/chatbot.html');
}
?>
<?php include 'includes/footer.php'; ?>