<?php
session_start();
require_once 'functions/db.php';
require_once 'functions/auth.php';
requireLogin();

$userId = $_SESSION['user_id'];
$userRole = $_SESSION['user_role'] ?? 'auditor';
$audit_id = intval($_GET['audit_id'] ?? ($_SESSION['active_audit_id'] ?? 0));

$_SESSION['active_audit_id'] = $audit_id > 0 ? $audit_id : ($_SESSION['active_audit_id'] ?? null);

$organizations = [];
$allAudits = [];

if ($userRole === 'auditee') {
    // Auditee: only sees assigned audits
    $assignedIds = getAuditeeAssignedAudits($pdo, $userId);
    if (!empty($assignedIds)) {
        $placeholders = implode(',', array_fill(0, count($assignedIds), '?'));
        $stmtAuditList = $pdo->prepare("SELECT a.id, a.organization_id, a.session_name, a.audit_date, o.organization_name FROM audit_sessions a JOIN organizations o ON a.organization_id = o.id WHERE a.id IN ($placeholders) ORDER BY a.audit_date DESC, a.created_at DESC");
        $stmtAuditList->execute($assignedIds);
        $allAudits = $stmtAuditList->fetchAll(PDO::FETCH_ASSOC);
        // Get unique orgs from assigned audits
        $orgIds = array_unique(array_column($allAudits, 'organization_id'));
        if (!empty($orgIds)) {
            $orgPlaceholders = implode(',', array_fill(0, count($orgIds), '?'));
            $stmtOrgList = $pdo->prepare("SELECT id, organization_name FROM organizations WHERE id IN ($orgPlaceholders) ORDER BY organization_name ASC");
            $stmtOrgList->execute(array_values($orgIds));
            $organizations = $stmtOrgList->fetchAll(PDO::FETCH_ASSOC);
        }
    }
} elseif ($userRole === 'admin') {
    // Admin: sees all organizations and audits for oversight
    $stmtOrgList = $pdo->prepare("SELECT id, organization_name FROM organizations WHERE is_active = 1 ORDER BY organization_name ASC");
    $stmtOrgList->execute();
    $organizations = $stmtOrgList->fetchAll(PDO::FETCH_ASSOC);

    $stmtAuditList = $pdo->prepare("SELECT a.id, a.organization_id, a.session_name, a.audit_date, o.organization_name FROM audit_sessions a JOIN organizations o ON a.organization_id = o.id ORDER BY a.audit_date DESC, a.created_at DESC");
    $stmtAuditList->execute();
    $allAudits = $stmtAuditList->fetchAll(PDO::FETCH_ASSOC);
} else {
    // Auditor: sees own organizations
    $stmtOrgList = $pdo->prepare("SELECT id, organization_name FROM organizations WHERE user_id = ? AND is_active = 1 ORDER BY organization_name ASC");
    $stmtOrgList->execute([$userId]);
    $organizations = $stmtOrgList->fetchAll(PDO::FETCH_ASSOC);

    $stmtAuditList = $pdo->prepare("SELECT a.id, a.organization_id, a.session_name, a.audit_date, o.organization_name FROM audit_sessions a JOIN organizations o ON a.organization_id = o.id WHERE o.user_id = ? ORDER BY a.audit_date DESC, a.created_at DESC");
    $stmtAuditList->execute([$userId]);
    $allAudits = $stmtAuditList->fetchAll(PDO::FETCH_ASSOC);
}

// Auditee: auto-activate the most recent assigned audit if none selected yet
if ($userRole === 'auditee' && $audit_id === 0 && !empty($allAudits)) {
    $audit_id = intval($allAudits[0]['id']);
    $_SESSION['active_audit_id'] = $audit_id;
}

$audit = null;
$topRisks = [];
$assetCount = 0;
$findingCount = 0;
$selectedOrgId = intval($_GET['org_id'] ?? 0);

// Notifications count for auditee
$notifCount = 0;
if ($userRole === 'auditee') {
    $notifCount = getUnreadNotificationCount($pdo, $userId);
}

if ($audit_id) {
    // Role-based audit access check
    if ($userRole === 'auditee') {
        $stmt = $pdo->prepare("SELECT a.*, o.organization_name, o.industry FROM audit_sessions a JOIN organizations o ON a.organization_id = o.id JOIN audit_auditees aa ON aa.audit_id = a.id WHERE a.id = ? AND aa.auditee_user_id = ?");
        $stmt->execute([$audit_id, $userId]);
    } elseif ($userRole === 'admin') {
        $stmt = $pdo->prepare("SELECT a.*, o.organization_name, o.industry FROM audit_sessions a JOIN organizations o ON a.organization_id = o.id WHERE a.id = ?");
        $stmt->execute([$audit_id]);
    } else {
        $stmt = $pdo->prepare("SELECT a.*, o.organization_name, o.industry FROM audit_sessions a JOIN organizations o ON a.organization_id = o.id WHERE a.id = ? AND o.user_id = ?");
        $stmt->execute([$audit_id, $userId]);
    }
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
    <h2 class="mb-4">
        Dashboard
        <?php if ($userRole === 'auditee' && $notifCount > 0): ?>
            <span class="badge bg-danger ms-2" title="Unread Notifications"><?php echo $notifCount; ?></span>
        <?php endif; ?>
    </h2>

    <?php if (isset($_GET['error']) && $_GET['error'] === 'access_denied'): ?>
        <div class="alert alert-danger alert-dismissible fade show" role="alert">
            <i class="fas fa-lock me-2"></i>
            <strong>Access Denied.</strong> You don't have permission to view that page.
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    <?php endif; ?>

    <?php if ($userRole === 'auditee'): ?>
        <!-- Auditee: show assigned audits as clickable cards -->
        <?php if (empty($allAudits)): ?>
            <div class="alert alert-warning">
                <i class="fas fa-exclamation-triangle me-2"></i>
                <strong>No audits assigned yet.</strong> Please contact your auditor.
            </div>
        <?php else: ?>
            <div class="card shadow-sm mb-4">
                <div class="card-body">
                    <h5 class="mb-3"><i class="fas fa-list-check me-2 text-primary"></i>Your Assigned Audits</h5>
                    <div class="row g-2">
                        <?php foreach ($allAudits as $auditItem): ?>
                            <?php $isActive = ($audit_id === intval($auditItem['id'])); ?>
                            <div class="col-md-4">
                                <a href="dashboard.php?audit_id=<?= intval($auditItem['id']) ?>" class="text-decoration-none">
                                    <div class="card h-100 <?= $isActive ? 'border-primary bg-primary bg-opacity-10' : 'border' ?>">
                                        <div class="card-body py-2 px-3">
                                            <div class="fw-semibold <?= $isActive ? 'text-primary' : '' ?>">
                                                <?= $isActive ? '<i class="fas fa-circle-check me-1"></i>' : '' ?>
                                                <?= htmlspecialchars($auditItem['session_name']) ?>
                                            </div>
                                            <small class="text-muted"><?= htmlspecialchars($auditItem['organization_name']) ?> &middot; <?= htmlspecialchars($auditItem['audit_date']) ?></small>
                                        </div>
                                    </div>
                                </a>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            </div>
        <?php endif; ?>
    <?php else: ?>
        <!-- Auditor / Admin: full org + audit switcher -->
        <div class="card shadow-sm mb-4">
            <div class="card-body">
                <h5 class="mb-3">Choose Organization & Audit Session</h5>
                <form id="auditSwitcher" class="row g-2">
                    <div class="col-md-5">
                        <select id="orgSelect" class="form-select">
                            <option value="">All Organization</option>
                            <?php foreach ($organizations as $org): ?>
                                <option value="<?php echo intval($org['id']); ?>" <?php echo $selectedOrgId === intval($org['id']) ? 'selected' : ''; ?>>
                                    <?php echo htmlspecialchars($org['organization_name']); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="col-md-5">
                        <select id="auditSelect" class="form-select">
                            <option value="">Choose Audit Session</option>
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
                        <button class="btn btn-primary" type="submit">Open</button>
                    </div>
                </form>
            </div>
        </div>
    <?php endif; ?>

    <?php if (!$audit_id): ?>
        <?php if ($userRole !== 'auditee'): ?>
        <div class="alert alert-warning">Choose an audit session first to start managing assets or findings.</div>
        <?php endif; ?>
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
                    <div class="col-md-3"><div class="badge badge-srm-accent p-2">Assets: <?php echo $assetCount; ?></div></div>
                    <div class="col-md-3"><div class="badge badge-srm-danger p-2">Findings: <?php echo $findingCount; ?></div></div>
                    <div class="col-md-3"><div class="badge badge-srm-muted p-2">Status: <?php echo htmlspecialchars($audit['status'] ?? 'Planning'); ?></div></div>
                    <div class="col-md-3"><div class="badge badge-srm-neutral p-2">NIST Maturity: <?php echo htmlspecialchars($audit['nist_maturity_level'] ?? 'Initial'); ?></div></div>
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
                                <?php
                                $topRiskScore = (int)($risk['risk_score'] ?? 0);
                                $topRiskBadgeClass = 'badge-srm-success';
                                if ($topRiskScore >= 13) {
                                    $topRiskBadgeClass = 'badge-srm-danger';
                                } elseif ($topRiskScore >= 6) {
                                    $topRiskBadgeClass = 'badge-srm-warning';
                                }
                                ?>
                                <td><span class="badge <?= $topRiskBadgeClass ?>"><?php echo htmlspecialchars($risk['risk_score']); ?></span></td>
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
            <?php if ($userRole === 'auditor'): ?>
                <a href="asset_manage.php?audit_id=<?php echo intval($audit_id); ?>" class="btn btn-primary">Manage Assets</a>
                <a href="findings.php?audit_id=<?php echo intval($audit_id); ?>" class="btn btn-warning">Manage Findings</a>
                <a href="control_checklist.php?audit_id=<?php echo intval($audit_id); ?>" class="btn btn-outline-secondary">Control Checklist</a>
            <?php elseif ($userRole === 'auditee'): ?>
                <a href="asset_manage.php?audit_id=<?php echo intval($audit_id); ?>" class="btn btn-primary">Register Assets</a>
                <a href="findings.php?audit_id=<?php echo intval($audit_id); ?>" class="btn btn-warning">View Findings &amp; Respond</a>
            <?php elseif ($userRole === 'admin'): ?>
                <a href="report.php?audit_id=<?php echo intval($audit_id); ?>" class="btn btn-info text-white">View Report</a>
                <a href="audit_sessions.php?org_id=<?php echo intval($selectedOrgId); ?>" class="btn btn-outline-secondary">Manage Sessions</a>
            <?php endif; ?>
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

<?php 
// Include chatbot widget (only for logged-in users)
if (file_exists('includes/chatbot.html')) {
    readfile('includes/chatbot.html');
}
?>

<?php include 'includes/footer.php'; ?>