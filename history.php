<?php
session_start();
require_once 'functions/auth.php';
require_once 'functions/db.php';

requireLogin();

$userId   = $_SESSION['user_id'];
$userRole = $_SESSION['user_role'] ?? 'auditee';

// Redirect non-auditees to dashboard
if ($userRole !== 'auditee') {
    header('Location: dashboard.php');
    exit();
}

// ── Assigned audits ────────────────────────────────────────────────────────
$stmtAudits = $pdo->prepare("
    SELECT a.id, a.session_name, a.status, a.created_at, a.audit_date,
           o.organization_name, o.industry,
           aa.assigned_at
    FROM audit_auditees aa
    JOIN audit_sessions a ON aa.audit_id = a.id
    JOIN organizations o ON a.organization_id = o.id
    WHERE aa.auditee_user_id = ?
    ORDER BY aa.assigned_at DESC
");
$stmtAudits->execute([$userId]);
$assignedAudits = $stmtAudits->fetchAll();

// ── Recent audit log activity ──────────────────────────────────────────────
$stmtLog = $pdo->prepare("
    SELECT action, table_name, record_id, ip_address, created_at
    FROM audit_logs
    WHERE user_id = ?
    ORDER BY created_at DESC
    LIMIT 30
");
$stmtLog->execute([$userId]);
$activityLog = $stmtLog->fetchAll();

// ── Assets I registered ───────────────────────────────────────────────────
$stmtAssets = $pdo->prepare("
    SELECT a.asset_name, a.asset_type, a.criticality_level, a.created_at,
           au.session_name
    FROM assets a
    JOIN audit_sessions au ON a.audit_id = au.id
    WHERE a.registered_by = ?
    ORDER BY a.created_at DESC
    LIMIT 20
");
$stmtAssets->execute([$userId]);
$myAssets = $stmtAssets->fetchAll();

// ── Findings I responded to ───────────────────────────────────────────────
$stmtResp = $pdo->prepare("
    SELECT f.title, f.risk_level, f.remediation_status, f.response_date,
           au.session_name, f.management_response
    FROM findings f
    JOIN audit_sessions au ON f.audit_id = au.id
    WHERE f.responded_by = ?
    ORDER BY f.response_date DESC
    LIMIT 20
");
$stmtResp->execute([$userId]);
$myResponses = $stmtResp->fetchAll();

include 'includes/header.php';
include 'includes/sidebar.php';
?>

<h3 class="mb-1">My Activity History</h3>
<p class="text-muted mb-4">Overview of your assigned audits, registered assets, and submitted responses.</p>

<!-- ── Assigned Audits ────────────────────────────────────────────────── -->
<div class="card shadow-sm mb-4">
    <div class="card-header d-flex align-items-center gap-2">
        <i class="fas fa-folder-open"></i>
        <strong>Assigned Audits</strong>
        <span class="badge bg-secondary ms-1"><?= count($assignedAudits) ?></span>
    </div>
    <div class="card-body p-0">
        <?php if (empty($assignedAudits)): ?>
            <p class="text-muted text-center py-4">You have not been assigned to any audits yet.</p>
        <?php else: ?>
        <table class="table table-hover mb-0">
            <thead class="table-dark">
                <tr>
                    <th>Audit Session</th>
                    <th>Organization</th>
                    <th>Industry</th>
                    <th>Period</th>
                    <th>Status</th>
                    <th>Assigned</th>
                    <th></th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($assignedAudits as $a): 
                $statusClass = match($a['status'] ?? 'Active') {
                    'Completed' => 'bg-success',
                    'Active'    => 'bg-primary',
                    default     => 'bg-secondary'
                };
            ?>
                <tr>
                    <td><strong><?= htmlspecialchars($a['session_name']) ?></strong></td>
                    <td><?= htmlspecialchars($a['organization_name']) ?></td>
                    <td><?= htmlspecialchars($a['industry'] ?? '—') ?></td>
                    <td style="font-size:0.85rem;">
                        <?= $a['audit_date'] ? date('d M Y', strtotime($a['audit_date'])) : '—' ?>
                    </td>
                    <td><span class="badge <?= $statusClass ?>"><?= htmlspecialchars($a['status'] ?? 'Active') ?></span></td>
                    <td style="font-size:0.85rem;"><?= date('d M Y', strtotime($a['assigned_at'])) ?></td>
                    <td>
                        <a href="dashboard.php?switch_audit=<?= intval($a['id']) ?>" class="btn btn-sm btn-outline-primary">View</a>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        <?php endif; ?>
    </div>
</div>

<div class="row g-4">
    <!-- ── Registered Assets ──────────────────────────────────────────── -->
    <div class="col-lg-6">
        <div class="card shadow-sm h-100">
            <div class="card-header d-flex align-items-center gap-2">
                <i class="fas fa-server"></i>
                <strong>Assets I Registered</strong>
                <span class="badge bg-secondary ms-1"><?= count($myAssets) ?></span>
            </div>
            <div class="card-body p-0">
                <?php if (empty($myAssets)): ?>
                    <p class="text-muted text-center py-4">No assets registered yet.</p>
                <?php else: ?>
                <table class="table table-sm table-hover mb-0">
                    <thead class="table-dark">
                        <tr><th>Asset</th><th>Type</th><th>Criticality</th><th>Registered</th></tr>
                    </thead>
                    <tbody>
                    <?php foreach ($myAssets as $ast): 
                        $critClass = match($ast['criticality_level'] ?? 'Low') {
                            'Critical' => 'danger', 'High' => 'warning', 'Medium' => 'info', default => 'secondary'
                        };
                    ?>
                        <tr>
                            <td><?= htmlspecialchars($ast['asset_name']) ?></td>
                            <td><?= htmlspecialchars($ast['asset_type']) ?></td>
                            <td><span class="badge bg-<?= $critClass ?>"><?= htmlspecialchars($ast['criticality_level'] ?? 'Low') ?></span></td>
                            <td style="font-size:0.8rem;"><?= date('d M Y', strtotime($ast['created_at'])) ?></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <!-- ── Submitted Responses ────────────────────────────────────────── -->
    <div class="col-lg-6">
        <div class="card shadow-sm h-100">
            <div class="card-header d-flex align-items-center gap-2">
                <i class="fas fa-reply"></i>
                <strong>My Finding Responses</strong>
                <span class="badge bg-secondary ms-1"><?= count($myResponses) ?></span>
            </div>
            <div class="card-body p-0">
                <?php if (empty($myResponses)): ?>
                    <p class="text-muted text-center py-4">No responses submitted yet.</p>
                <?php else: ?>
                <table class="table table-sm table-hover mb-0">
                    <thead class="table-dark">
                        <tr><th>Finding</th><th>Risk</th><th>Status</th><th>Responded</th></tr>
                    </thead>
                    <tbody>
                    <?php foreach ($myResponses as $r): 
                        $riskClass = match($r['risk_level'] ?? 'Low') {
                            'Critical' => 'danger', 'High' => 'warning', 'Medium' => 'info', default => 'secondary'
                        };
                        $statusClass = match($r['remediation_status'] ?? 'Open') {
                            'Resolved' => 'success', 'In Progress' => 'warning text-dark', default => 'secondary'
                        };
                    ?>
                        <tr>
                            <td style="font-size:0.85rem;"><?= htmlspecialchars(mb_strimwidth($r['title'], 0, 40, '…')) ?></td>
                            <td><span class="badge bg-<?= $riskClass ?>"><?= htmlspecialchars($r['risk_level'] ?? '—') ?></span></td>
                            <td><span class="badge bg-<?= $statusClass ?>"><?= htmlspecialchars($r['remediation_status'] ?? 'Open') ?></span></td>
                            <td style="font-size:0.8rem;"><?= $r['response_date'] ? date('d M Y', strtotime($r['response_date'])) : '—' ?></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
                <?php endif; ?>
            </div>
        </div>
    </div>
</div>

<!-- ── Recent Activity Log ────────────────────────────────────────────── -->
<?php if (!empty($activityLog)): ?>
<div class="card shadow-sm mt-4">
    <div class="card-header d-flex align-items-center gap-2">
        <i class="fas fa-history"></i>
        <strong>Recent Activity</strong>
        <span class="badge bg-secondary ms-1"><?= count($activityLog) ?></span>
    </div>
    <div class="card-body p-0">
        <table class="table table-sm table-hover mb-0">
            <thead class="table-dark">
                <tr><th>Action</th><th>Target</th><th>Date & Time</th></tr>
            </thead>
            <tbody>
            <?php foreach ($activityLog as $log): ?>
                <tr>
                    <td><span class="badge bg-secondary text-white" style="font-size:0.75rem; font-family:monospace;"><?= htmlspecialchars($log['action']) ?></span></td>
                    <td style="font-size:0.85rem;"><?= htmlspecialchars(ucfirst(str_replace('_', ' ', $log['table_name'] ?? ''))) ?> #<?= intval($log['record_id'] ?? 0) ?></td>
                    <td style="font-size:0.82rem; white-space:nowrap;"><?= date('d M Y H:i', strtotime($log['created_at'])) ?></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>
<?php endif; ?>

<?php include 'includes/footer.php'; ?>
