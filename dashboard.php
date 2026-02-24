<?php
session_start();
require_once 'functions/db.php';
require_once 'functions/auth.php';

requireLogin();

$userId = $_SESSION['user_id'];
$audit_id = intval($_GET['audit_id'] ?? ($_SESSION['active_audit_id'] ?? 0));

$_SESSION['active_audit_id'] = $audit_id > 0 ? $audit_id : ($_SESSION['active_audit_id'] ?? null);

$stmtOrgList = $pdo->prepare("SELECT id, organization_name FROM organizations WHERE user_id = ? AND is_active = 1 ORDER BY organization_name ASC");
$stmtOrgList->execute([$userId]);
$organizations = $stmtOrgList->fetchAll(PDO::FETCH_ASSOC);

$stmtAuditList = $pdo->prepare("SELECT a.id, a.organization_id, a.session_name, a.audit_date, o.organization_name FROM audit_sessions a JOIN organizations o ON a.organization_id = o.id WHERE o.user_id = ? ORDER BY a.audit_date DESC, a.created_at DESC");
$stmtAuditList->execute([$userId]);
$allAudits = $stmtAuditList->fetchAll(PDO::FETCH_ASSOC);

$audit = null;
$topRisks = [];
$assetCount = 0;
$findingCount = 0;
$selectedOrgId = intval($_GET['org_id'] ?? 0);

if ($audit_id) {
    $stmt = $pdo->prepare("SELECT a.*, o.organization_name, o.industry FROM audit_sessions a JOIN organizations o ON a.organization_id = o.id WHERE a.id = ? AND o.user_id = ?");
    $stmt->execute([$audit_id, $userId]);
    $audit = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($audit) {
        $selectedOrgId = intval($audit['organization_id']);
        $_SESSION['active_audit_id'] = $audit_id;
        $stmtCountAssets = $pdo->prepare("SELECT COUNT(*) AS total FROM assets WHERE audit_id = ?");
        $stmtCountAssets->execute([$audit_id]);
        $assetCount = intval($stmtCountAssets->fetch(PDO::FETCH_ASSOC)['total'] ?? 0);

        $stmtCountFindings = $pdo->prepare("SELECT COUNT(*) AS total FROM findings WHERE audit_id = ?");
        $stmtCountFindings->execute([$audit_id]);
        $findingCount = intval($stmtCountFindings->fetch(PDO::FETCH_ASSOC)['total'] ?? 0);

        $stmt2 = $pdo->prepare("SELECT title, risk_score, nist_function FROM findings WHERE audit_id = ? ORDER BY risk_score DESC LIMIT 5");
        $stmt2->execute([$audit_id]);
        $topRisks = $stmt2->fetchAll(PDO::FETCH_ASSOC);
    }
}

include 'includes/header.php';
include 'includes/sidebar.php';
?>

<div class="container mt-4">
    <h2 class="mb-4">Dashboard</h2>

    <div class="card shadow-sm mb-4">
        <div class="card-body">
            <h5 class="mb-3">Pilih Organization & Audit Session</h5>
            <form id="auditSwitcher" class="row g-2">
                <div class="col-md-5">
                    <select id="orgSelect" class="form-select">
                        <option value="">Semua Organization</option>
                        <?php foreach ($organizations as $org): ?>
                            <option value="<?php echo intval($org['id']); ?>" <?php echo $selectedOrgId === intval($org['id']) ? 'selected' : ''; ?>>
                                <?php echo htmlspecialchars($org['organization_name']); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="col-md-5">
                    <select id="auditSelect" class="form-select">
                        <option value="">Pilih Audit Session</option>
                        <?php foreach ($allAudits as $auditItem): ?>
                            <option value="<?php echo intval($auditItem['id']); ?>"
                                    data-org-id="<?php echo intval($auditItem['organization_id']); ?>"
                                    <?php echo $audit_id === intval($auditItem['id']) ? 'selected' : ''; ?>>
                                <?php echo htmlspecialchars($auditItem['organization_name'] . ' - ' . $auditItem['session_name'] . ' (' . $auditItem['audit_date'] . ')'); ?>
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

    <?php if (!$audit_id): ?>
        <div class="alert alert-warning">Pilih audit session dulu untuk mulai manage assets atau findings.</div>
    <?php elseif (!$audit): ?>
        <div class="alert alert-danger">Audit not found or access denied.</div>
    <?php else: ?>
        <div class="card shadow-sm mb-4">
            <div class="card-body">
                <h5 class="mb-3"><?php echo htmlspecialchars($audit['session_name']); ?></h5>
                <div class="row">
                    <div class="col-md-4"><strong>Organization:</strong> <?php echo htmlspecialchars($audit['organization_name']); ?></div>
                    <div class="col-md-4"><strong>Industry:</strong> <?php echo htmlspecialchars($audit['industry']); ?></div>
                    <div class="col-md-4"><strong>Audit Date:</strong> <?php echo htmlspecialchars($audit['audit_date']); ?></div>
                </div>
                <hr>
                <div class="row text-center">
                    <div class="col-md-3"><div class="badge bg-primary p-2">Assets: <?php echo $assetCount; ?></div></div>
                    <div class="col-md-3"><div class="badge bg-danger p-2">Findings: <?php echo $findingCount; ?></div></div>
                    <div class="col-md-3"><div class="badge bg-secondary p-2">Status: <?php echo htmlspecialchars($audit['status'] ?? 'Planning'); ?></div></div>
                    <div class="col-md-3"><div class="badge bg-dark p-2">NIST Maturity: <?php echo htmlspecialchars($audit['nist_maturity_level'] ?? 'Initial'); ?></div></div>
                </div>
            </div>
        </div>

        <div class="row mb-4">
            <div class="col-md-3">
                <div class="card shadow-sm h-100">
                    <div class="card-body text-center">
                        <h6 class="text-muted mb-2">Exposure Level</h6>
                        <div class="fw-bold fs-5"><?php echo htmlspecialchars($audit['exposure_level'] ?? 'Low'); ?></div>
                        <small>Score: <?php echo number_format((float)($audit['exposure_score'] ?? 0), 2); ?>/5</small>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card shadow-sm h-100">
                    <div class="card-body text-center">
                        <h6 class="text-muted mb-2">Avg Asset Criticality</h6>
                        <div class="fw-bold fs-5"><?php echo number_format((float)($audit['avg_asset_criticality'] ?? 0), 2); ?>/5</div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card shadow-sm h-100">
                    <div class="card-body text-center">
                        <h6 class="text-muted mb-2">Final Risk Level</h6>
                        <div class="fw-bold fs-5"><?php echo htmlspecialchars($audit['final_risk_level'] ?? 'Low'); ?></div>
                        <small>Score: <?php echo number_format((float)($audit['final_risk_score'] ?? 0), 2); ?>/25</small>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card shadow-sm h-100">
                    <div class="card-body text-center">
                        <h6 class="text-muted mb-2">Compliance %</h6>
                        <div class="fw-bold fs-5"><?php echo number_format((float)($audit['compliance_percentage'] ?? 0), 2); ?>%</div>
                    </div>
                </div>
            </div>
        </div>

        <div class="card shadow-sm mb-4">
            <div class="card-body">
                <h5 class="mb-3">Top 5 Risks</h5>
                <table class="table table-bordered mb-0">
                    <thead class="table-dark">
                        <tr>
                            <th>Title</th>
                            <th>Risk Score</th>
                            <th>NIST Function</th>
                        </tr>
                    </thead>
                    <tbody>
                    <?php if (count($topRisks) > 0): ?>
                        <?php foreach ($topRisks as $risk): ?>
                            <tr>
                                <td><?php echo htmlspecialchars($risk['title']); ?></td>
                                <td><span class="badge bg-danger"><?php echo htmlspecialchars($risk['risk_score']); ?></span></td>
                                <td><?php echo htmlspecialchars($risk['nist_function']); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <tr>
                            <td colspan="3" class="text-center">No findings yet</td>
                        </tr>
                    <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <div class="d-flex gap-2">
            <a href="asset_manage.php?audit_id=<?php echo intval($audit_id); ?>" class="btn btn-primary">Manage Assets</a>
            <a href="findings.php?audit_id=<?php echo intval($audit_id); ?>" class="btn btn-warning">Manage Findings</a>
        </div>
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

document.getElementById('auditSwitcher').addEventListener('submit', function (event) {
    event.preventDefault();
    const selectedAuditId = auditSelect.value;
    const selectedOrgId = orgSelect.value;

    if (selectedAuditId) {
        window.location.href = 'dashboard.php?audit_id=' + encodeURIComponent(selectedAuditId);
        return;
    }

    if (selectedOrgId) {
        window.location.href = 'dashboard.php?org_id=' + encodeURIComponent(selectedOrgId);
    }
});
</script>

<?php include 'includes/footer.php'; ?>