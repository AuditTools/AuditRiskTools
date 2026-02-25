<?php
session_start();
require_once 'functions/db.php';
require_once 'functions/auth.php';

requireLogin();

$userId = $_SESSION['user_id'];
$audit_id = intval($_GET['audit_id'] ?? ($_SESSION['active_audit_id'] ?? 0));
$selectedOrgId = intval($_GET['org_id'] ?? 0);
$assets = [];
$pageError = '';

$stmtOrgList = $pdo->prepare("SELECT id, organization_name FROM organizations WHERE user_id = ? AND is_active = 1 ORDER BY organization_name ASC");
$stmtOrgList->execute([$userId]);
$organizations = $stmtOrgList->fetchAll(PDO::FETCH_ASSOC);

$stmtAuditList = $pdo->prepare("SELECT a.id, a.organization_id, a.session_name, a.audit_date, o.organization_name FROM audit_sessions a JOIN organizations o ON a.organization_id = o.id WHERE o.user_id = ? ORDER BY a.audit_date DESC, a.created_at DESC");
$stmtAuditList->execute([$userId]);
$allAudits = $stmtAuditList->fetchAll(PDO::FETCH_ASSOC);

if ($audit_id > 0) {
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
?>

<?php include 'includes/header.php'; ?>
<?php include 'includes/sidebar.php'; ?>

<div class="container mt-4">

    <h2 class="mb-4">Asset Management</h2>

    <div class="card shadow-sm mb-4">
        <div class="card-body">
            <h5 class="mb-3">Pilih Organization & Audit Session</h5>
            <form id="assetAuditSwitcher" class="row g-2">
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
        <div class="alert alert-warning">Pilih audit session dulu untuk mengelola assets.</div>
    <?php else: ?>

    <!-- Add Asset Form -->
    <div class="card shadow-sm mb-4">
        <div class="card-body">

            <form id="assetForm">

                <input type="hidden" name="audit_id" value="<?= $audit_id ?>">
                <?= csrfTokenInput(); ?>

                <div class="row mb-3">
                    <div class="col-md-4">
                        <label>Asset Name</label>
                        <input type="text" name="asset_name" class="form-control" required>
                    </div>

                    <div class="col-md-4">
                        <label>IP Address</label>
                        <input type="text" name="ip_address" class="form-control">
                    </div>

                    <div class="col-md-4">
                        <label>Asset Type</label>
                        <input type="text" name="asset_type" class="form-control">
                    </div>
                </div>

                <div class="row mb-3">
                    <div class="col-md-4">
                        <label>Confidentiality (1-5)</label>
                        <input type="number" min="1" max="5" name="confidentiality" class="form-control" required>
                    </div>

                    <div class="col-md-4">
                        <label>Integrity (1-5)</label>
                        <input type="number" min="1" max="5" name="integrity" class="form-control" required>
                    </div>

                    <div class="col-md-4">
                        <label>Availability (1-5)</label>
                        <input type="number" min="1" max="5" name="availability" class="form-control" required>
                    </div>
                </div>

                <button type="submit" class="btn btn-primary">
                    Add Asset
                </button>

            </form>

        </div>
    </div>

    <!-- Asset Table -->
    <table class="table table-bordered">
        <thead class="table-dark">
            <tr>
                <th>Asset</th>
                <th>IP</th>
                <th>Type</th>
                <th>CIA</th>
                <th>Criticality Score</th>
                <th>Level</th>
            </tr>
        </thead>
        <tbody>
        <?php if (count($assets) > 0): ?>
            <?php foreach ($assets as $asset): ?>
                <tr>
                    <td><?= htmlspecialchars($asset['asset_name']) ?></td>
                    <td><?= htmlspecialchars($asset['ip_address']) ?></td>
                    <td><?= htmlspecialchars($asset['asset_type']) ?></td>
                    <td>
                        <?= $asset['confidentiality'] ?>/<?= $asset['integrity'] ?>/<?= $asset['availability'] ?>
                    </td>
                    <td><?= $asset['criticality_score'] ?></td>
                    <td>
                        <span class="badge bg-info">
                            <?= $asset['criticality_level'] ?>
                        </span>
                    </td>
                </tr>
            <?php endforeach; ?>
        <?php else: ?>
            <tr>
                <td colspan="6" class="text-center">No assets yet</td>
            </tr>
        <?php endif; ?>
        </tbody>
    </table>

    <a href="findings.php?audit_id=<?= $audit_id ?>" class="btn btn-outline-danger">
        Go to Findings
    </a>

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

document.getElementById('assetAuditSwitcher').addEventListener('submit', function(e) {
    e.preventDefault();
    const selectedAuditId = auditSelect.value;
    const selectedOrgId = orgSelect.value;

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

    const formData = new FormData(this);

    fetch('api/asset_actions.php?action=add', {
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
    .catch(() => alert("Error adding asset"));
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