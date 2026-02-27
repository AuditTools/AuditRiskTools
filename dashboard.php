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

// Notifications for all roles
$notifCount = 0;
$notifications = [];
try {
    $notifCount = getUnreadNotificationCount($pdo, $userId);
    $notifications = getNotifications($pdo, $userId, 15);
} catch (Exception $e) {
    // Table may not exist yet — silently ignore
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
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h2 class="mb-0">Dashboard</h2>
        <div class="position-relative">
            <button class="btn btn-outline-secondary position-relative" type="button" id="notifToggleBtn" title="Notifications">
                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="currentColor" viewBox="0 0 16 16"><path d="M8 16a2 2 0 0 0 2-2H6a2 2 0 0 0 2 2M8 1.918l-.797.161A4 4 0 0 0 4 6c0 .628-.134 2.197-.459 3.742-.16.767-.376 1.566-.663 2.258h10.244c-.287-.692-.502-1.49-.663-2.258C12.134 8.197 12 6.628 12 6a4 4 0 0 0-3.203-3.92zM14.22 12c.223.447.481.801.78 1H1c.299-.199.557-.553.78-1C2.68 10.2 3 6.88 3 6c0-2.42 1.72-4.44 4.005-4.901a1 1 0 1 1 1.99 0A5 5 0 0 1 13 6c0 .88.32 4.2 1.22 6"/></svg>
                <?php if ($notifCount > 0): ?>
                    <span class="position-absolute top-0 start-100 translate-middle badge rounded-pill bg-danger" style="font-size:0.65rem;">
                        <?= $notifCount > 99 ? '99+' : $notifCount ?>
                    </span>
                <?php endif; ?>
            </button>

            <!-- Notification dropdown panel -->
            <div id="notifPanel" class="card shadow-lg border position-absolute end-0 mt-1" style="width:380px; max-height:450px; z-index:1060; display:none;">
                <div class="card-header d-flex justify-content-between align-items-center py-2">
                    <strong style="font-size:0.9rem;">Notifications</strong>
                    <?php if ($notifCount > 0): ?>
                        <button class="btn btn-sm btn-link text-decoration-none p-0" id="markAllReadBtn" style="font-size:0.8rem;">Mark all read</button>
                    <?php endif; ?>
                </div>
                <div class="card-body p-0" style="max-height:370px; overflow-y:auto;">
                    <?php if (empty($notifications)): ?>
                        <div class="text-center text-muted py-4" style="font-size:0.85rem;">
                            <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" fill="currentColor" class="mb-2 text-secondary" viewBox="0 0 16 16"><path d="M8 16a2 2 0 0 0 2-2H6a2 2 0 0 0 2 2M8 1.918l-.797.161A4 4 0 0 0 4 6c0 .628-.134 2.197-.459 3.742-.16.767-.376 1.566-.663 2.258h10.244c-.287-.692-.502-1.49-.663-2.258C12.134 8.197 12 6.628 12 6a4 4 0 0 0-3.203-3.92zM14.22 12c.223.447.481.801.78 1H1c.299-.199.557-.553.78-1C2.68 10.2 3 6.88 3 6c0-2.42 1.72-4.44 4.005-4.901a1 1 0 1 1 1.99 0A5 5 0 0 1 13 6c0 .88.32 4.2 1.22 6"/></svg>
                            <div>No notifications yet</div>
                        </div>
                    <?php else: ?>
                        <ul class="list-group list-group-flush">
                            <?php foreach ($notifications as $notif):
                                $isUnread = !$notif['is_read'];
                                $typeIcons = [
                                    'audit_assigned'     => ['icon' => '📋', 'color' => 'primary'],
                                    'finding_created'    => ['icon' => '⚠️', 'color' => 'warning'],
                                    'finding_closed'     => ['icon' => '✅', 'color' => 'success'],
                                    'finding_reopened'   => ['icon' => '🔄', 'color' => 'danger'],
                                    'response_submitted' => ['icon' => '💬', 'color' => 'info'],
                                    'evidence_reviewed'  => ['icon' => '📎', 'color' => 'secondary'],
                                ];
                                $meta = $typeIcons[$notif['type']] ?? ['icon' => '🔔', 'color' => 'secondary'];
                                $timeAgo = '';
                                $created = strtotime($notif['created_at']);
                                $diff = time() - $created;
                                if ($diff < 60) $timeAgo = 'just now';
                                elseif ($diff < 3600) $timeAgo = floor($diff/60) . 'm ago';
                                elseif ($diff < 86400) $timeAgo = floor($diff/3600) . 'h ago';
                                elseif ($diff < 604800) $timeAgo = floor($diff/86400) . 'd ago';
                                else $timeAgo = date('M d', $created);
                            ?>
                                <li class="list-group-item px-3 py-2 notif-item <?= $isUnread ? 'bg-light border-start border-3 border-' . $meta['color'] : '' ?>"
                                    data-notif-id="<?= intval($notif['id']) ?>"
                                    <?php if ($notif['audit_id']): ?>data-audit-id="<?= intval($notif['audit_id']) ?>"<?php endif; ?>
                                    style="cursor:pointer; font-size:0.85rem;">
                                    <div class="d-flex gap-2">
                                        <span style="font-size:1.1rem;"><?= $meta['icon'] ?></span>
                                        <div class="flex-grow-1">
                                            <div class="<?= $isUnread ? 'fw-semibold' : '' ?>"><?= htmlspecialchars($notif['message']) ?></div>
                                            <small class="text-muted"><?= $timeAgo ?></small>
                                        </div>
                                        <?php if ($isUnread): ?>
                                            <span class="bg-<?= $meta['color'] ?> rounded-circle d-inline-block" style="width:8px;height:8px;margin-top:6px;flex-shrink:0;"></span>
                                        <?php endif; ?>
                                    </div>
                                </li>
                            <?php endforeach; ?>
                        </ul>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>

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
// --- Org/Audit switcher (auditor & admin only) ---
(function() {
    const orgSelect = document.getElementById('orgSelect');
    const auditSelect = document.getElementById('auditSelect');
    const auditSwitcher = document.getElementById('auditSwitcher');

    if (orgSelect && auditSelect) {
        function filterAuditsByOrg() {
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
        orgSelect.addEventListener('change', filterAuditsByOrg);
        filterAuditsByOrg();
    }

    if (auditSwitcher) {
        auditSwitcher.addEventListener('submit', function (event) {
            event.preventDefault();
            const selectedAuditId = auditSelect ? auditSelect.value : '';
            const selectedOrgId = orgSelect ? orgSelect.value : '';
            if (selectedAuditId) {
                window.location.href = 'dashboard.php?audit_id=' + encodeURIComponent(selectedAuditId);
                return;
            }
            if (selectedOrgId) {
                window.location.href = 'dashboard.php?org_id=' + encodeURIComponent(selectedOrgId);
            }
        });
    }
})();

// --- Notification panel ---
(function() {
    const toggleBtn = document.getElementById('notifToggleBtn');
    const panel = document.getElementById('notifPanel');
    const markAllBtn = document.getElementById('markAllReadBtn');
    if (!toggleBtn || !panel) return;

    // Toggle panel open/close
    toggleBtn.addEventListener('click', function(e) {
        e.stopPropagation();
        const isOpen = panel.style.display !== 'none';
        panel.style.display = isOpen ? 'none' : 'block';
    });

    // Close panel when clicking outside
    document.addEventListener('click', function(e) {
        if (!panel.contains(e.target) && e.target !== toggleBtn) {
            panel.style.display = 'none';
        }
    });

    // Click a notification → mark as read & navigate to audit
    document.querySelectorAll('.notif-item').forEach(function(item) {
        item.addEventListener('click', function() {
            const notifId = this.dataset.notifId;
            const auditId = this.dataset.auditId;

            // Mark this notification as read
            fetch('api/notification_actions.php?action=mark_read', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ids: [parseInt(notifId)] })
            }).then(function() {
                if (auditId) {
                    window.location.href = 'findings.php?audit_id=' + auditId;
                } else {
                    window.location.reload();
                }
            });
        });
    });

    // Mark all as read
    if (markAllBtn) {
        markAllBtn.addEventListener('click', function(e) {
            e.stopPropagation();
            fetch('api/notification_actions.php?action=mark_all_read', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({})
            })
            .then(function(res) { return res.json(); })
            .then(function(data) {
                if (data.success) {
                    // Remove unread styling
                    document.querySelectorAll('.notif-item').forEach(function(item) {
                        item.classList.remove('bg-light', 'border-start', 'border-3',
                            'border-primary', 'border-warning', 'border-success',
                            'border-danger', 'border-info', 'border-secondary');
                        const dot = item.querySelector('.rounded-circle');
                        if (dot) dot.remove();
                        const fw = item.querySelector('.fw-semibold');
                        if (fw) fw.classList.remove('fw-semibold');
                    });
                    // Remove badge
                    const badge = toggleBtn.querySelector('.badge');
                    if (badge) badge.remove();
                    // Remove "Mark all read" button
                    markAllBtn.remove();
                }
            });
        });
    }
})();
</script>

<?php 
// Include chatbot widget (only for logged-in users)
if (file_exists('includes/chatbot.html')) {
    readfile('includes/chatbot.html');
}
?>

<?php include 'includes/footer.php'; ?>