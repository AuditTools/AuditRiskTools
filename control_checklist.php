<?php
/**
 * SRM-Audit - NIST CSF Control Audit Checklist (Module 6)
 * Auditor reviews each NIST CSF control and marks compliance status.
 * Supports: Compliant / Partially Compliant / Non-Compliant / Not Applicable
 * Results feed into overall compliance percentage and maturity level.
 */
session_start();
require_once 'functions/db.php';
require_once 'functions/auth.php';
require_once 'functions/nist_controls.php';

requireLogin();

$userId = $_SESSION['user_id'];
$audit_id = intval($_GET['audit_id'] ?? ($_SESSION['active_audit_id'] ?? 0));
$selectedOrgId = intval($_GET['org_id'] ?? 0);
$pageError = '';

// Get organizations
$stmtOrgList = $pdo->prepare("SELECT id, organization_name FROM organizations WHERE user_id = ? AND is_active = 1 ORDER BY organization_name ASC");
$stmtOrgList->execute([$userId]);
$organizations = $stmtOrgList->fetchAll(PDO::FETCH_ASSOC);

// Get all audit sessions
$stmtAuditList = $pdo->prepare("
    SELECT a.id, a.organization_id, a.session_name, a.audit_date, o.organization_name 
    FROM audit_sessions a 
    JOIN organizations o ON a.organization_id = o.id 
    WHERE o.user_id = ? 
    ORDER BY a.audit_date DESC, a.created_at DESC
");
$stmtAuditList->execute([$userId]);
$allAudits = $stmtAuditList->fetchAll(PDO::FETCH_ASSOC);

// Verify audit access
if ($audit_id > 0) {
    $stmtAccess = $pdo->prepare("
        SELECT a.id, a.organization_id, a.session_name, o.organization_name
        FROM audit_sessions a 
        JOIN organizations o ON a.organization_id = o.id 
        WHERE a.id = ? AND o.user_id = ?
    ");
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

// Get NIST controls grouped by function
$controlsByFunction = getNistControlsByFunction();
$totalControls = getNistControlTotal();

// Get saved checklist for this audit
$savedChecklist = [];
if ($audit_id) {
    $stmt = $pdo->prepare("SELECT control_id, status, notes FROM control_checklist WHERE audit_id = ?");
    $stmt->execute([$audit_id]);
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    foreach ($rows as $r) {
        $savedChecklist[$r['control_id']] = $r;
    }
}

include 'includes/header.php';
include 'includes/sidebar.php';
?>

<style>
    .nist-function-header {
        padding: 12px 18px;
        margin-bottom: 0;
        font-weight: 700;
        color: #fff;
        border-radius: 6px 6px 0 0;
    }
    .fn-identify { background: #0d6efd; }
    .fn-protect { background: #198754; }
    .fn-detect { background: #fd7e14; }
    .fn-respond { background: #dc3545; }
    .fn-recover { background: #6f42c1; }

    .control-row {
        padding: 12px 18px;
        border-bottom: 1px solid #eee;
        transition: background 0.15s;
    }
    .control-row:hover { background: #f8f9fa; }
    .control-row:last-child { border-bottom: none; }

    .control-id-badge {
        display: inline-block;
        font-family: 'Courier New', monospace;
        font-weight: 600;
        font-size: 0.82rem;
        background: #e9ecef;
        padding: 2px 8px;
        border-radius: 4px;
        min-width: 80px;
        text-align: center;
    }
    .control-title { font-weight: 600; margin-bottom: 2px; }
    .control-desc { font-size: 0.85rem; color: #555; }
    .control-guidance {
        font-size: 0.8rem;
        background: #f0f7ff;
        border-left: 3px solid #0d6efd;
        padding: 6px 12px;
        margin-top: 6px;
        color: #444;
    }

    .status-select {
        min-width: 170px;
        font-size: 0.85rem;
    }
    .status-Compliant { border-color: #198754; background: #d1e7dd; }
    .status-Partially { border-color: #ffc107; background: #fff3cd; }
    .status-Non-Compliant { border-color: #dc3545; background: #f8d7da; }
    .status-Not-Applicable { border-color: #6c757d; background: #e9ecef; }
    .status-Not-Assessed { border-color: #dee2e6; }

    .notes-input {
        font-size: 0.82rem;
        resize: none;
    }

    .summary-card {
        text-align: center;
        padding: 15px;
        border-radius: 8px;
    }
    .summary-card .num {
        font-size: 2rem;
        font-weight: 700;
        line-height: 1.1;
    }
    .summary-card .lbl {
        font-size: 0.8rem;
        color: #666;
    }

    .progress-bar-striped { transition: width 0.5s; }

    .function-section { margin-bottom: 20px; }
    .function-body {
        border: 1px solid #dee2e6;
        border-top: none;
        border-radius: 0 0 6px 6px;
    }

    .save-float {
        position: fixed;
        bottom: 20px;
        right: 30px;
        z-index: 1050;
        box-shadow: 0 4px 20px rgba(0,0,0,0.25);
    }
</style>

<!-- Page Header -->
<div class="d-flex justify-content-between align-items-center mb-3">
    <h3><i class="bi bi-clipboard-check"></i> NIST CSF Control Checklist</h3>
    <?php if (isset($access)): ?>
        <span class="badge bg-primary fs-6"><?= htmlspecialchars($access['session_name']) ?> — <?= htmlspecialchars($access['organization_name']) ?></span>
    <?php endif; ?>
</div>

<!-- Audit Selector -->
<?php if (!$audit_id): ?>
    <div class="card mb-4">
        <div class="card-body">
            <h5>Select Audit Session</h5>
            <?php if ($pageError): ?>
                <div class="alert alert-danger"><?= htmlspecialchars($pageError) ?></div>
            <?php endif; ?>

            <!-- Org filter -->
            <div class="row mb-3">
                <div class="col-md-4">
                    <label class="form-label">Filter by Organization</label>
                    <select id="orgFilter" class="form-select" onchange="filterAudits()">
                        <option value="0">All Organizations</option>
                        <?php foreach ($organizations as $org): ?>
                            <option value="<?= $org['id'] ?>" <?= $selectedOrgId == $org['id'] ? 'selected' : '' ?>><?= htmlspecialchars($org['organization_name']) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="col-md-6">
                    <label class="form-label">Audit Session</label>
                    <select id="auditSelect" class="form-select">
                        <option value="">-- Choose Audit Session --</option>
                        <?php foreach ($allAudits as $a): ?>
                            <option value="<?= $a['id'] ?>" data-org="<?= $a['organization_id'] ?>"><?= htmlspecialchars($a['organization_name'] . ' — ' . $a['session_name'] . ' (' . $a['audit_date'] . ')') ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="col-md-2 d-flex align-items-end">
                    <button class="btn btn-primary w-100" onclick="goToAudit()">Load Checklist</button>
                </div>
            </div>
        </div>
    </div>

    <script>
        function filterAudits() {
            const orgId = document.getElementById('orgFilter').value;
            const sel = document.getElementById('auditSelect');
            Array.from(sel.options).forEach(o => {
                if (!o.value) return;
                o.style.display = (orgId === '0' || o.dataset.org === orgId) ? '' : 'none';
            });
            sel.value = '';
        }
        function goToAudit() {
            const id = document.getElementById('auditSelect').value;
            if (id) window.location = 'control_checklist.php?audit_id=' + id;
        }
        <?php if ($selectedOrgId): ?>filterAudits();<?php endif; ?>
    </script>
<?php else: ?>

    <!-- ============ COMPLIANCE SUMMARY CARDS ============ -->
    <?php
    // Calculate summary from saved data
    $stats = ['Compliant' => 0, 'Partially Compliant' => 0, 'Non-Compliant' => 0, 'Not Applicable' => 0, 'Not Assessed' => 0];
    foreach ($savedChecklist as $sc) {
        if (isset($stats[$sc['status']])) $stats[$sc['status']]++;
    }
    $stats['Not Assessed'] = $totalControls - count($savedChecklist);
    $applicable = $totalControls - $stats['Not Applicable'];
    $compPct = $applicable > 0 ? round((($stats['Compliant'] + $stats['Partially Compliant'] * 0.5) / $applicable) * 100, 1) : 0;
    $assessed = count($savedChecklist);
    ?>

    <div class="row mb-4 g-3">
        <div class="col-md-2">
            <div class="summary-card bg-light border">
                <div class="num text-primary"><?= $totalControls ?></div>
                <div class="lbl">Total Controls</div>
            </div>
        </div>
        <div class="col-md-2">
            <div class="summary-card border" style="background:#d1e7dd">
                <div class="num text-success" id="sumCompliant"><?= $stats['Compliant'] ?></div>
                <div class="lbl">Compliant</div>
            </div>
        </div>
        <div class="col-md-2">
            <div class="summary-card border" style="background:#fff3cd">
                <div class="num text-warning" id="sumPartial"><?= $stats['Partially Compliant'] ?></div>
                <div class="lbl">Partial</div>
            </div>
        </div>
        <div class="col-md-2">
            <div class="summary-card border" style="background:#f8d7da">
                <div class="num text-danger" id="sumNonComp"><?= $stats['Non-Compliant'] ?></div>
                <div class="lbl">Non-Compliant</div>
            </div>
        </div>
        <div class="col-md-2">
            <div class="summary-card bg-light border">
                <div class="num text-secondary" id="sumNA"><?= $stats['Not Applicable'] ?></div>
                <div class="lbl">N/A</div>
            </div>
        </div>
        <div class="col-md-2">
            <div class="summary-card border" style="background:#e0cffc">
                <div class="num" id="sumNotAssessed"><?= $stats['Not Assessed'] ?></div>
                <div class="lbl">Not Assessed</div>
            </div>
        </div>
    </div>

    <!-- Overall progress bar -->
    <div class="card mb-4">
        <div class="card-body">
            <div class="d-flex justify-content-between mb-1">
                <strong>Overall Compliance Score</strong>
                <strong id="compPct"><?= $compPct ?>%</strong>
            </div>
            <div class="progress" style="height: 24px;">
                <div id="compBar" class="progress-bar progress-bar-striped <?= $compPct >= 80 ? 'bg-success' : ($compPct >= 50 ? 'bg-warning' : 'bg-danger') ?>"
                    role="progressbar" style="width: <?= $compPct ?>%">
                    <?= $compPct ?>%
                </div>
            </div>
            <div class="d-flex justify-content-between mt-1">
                <small class="text-muted">Assessed: <span id="assessedCount"><?= $assessed ?></span> / <?= $totalControls ?></small>
                <small class="text-muted">
                    Maturity:
                    <strong id="maturityBadge" class="<?= $compPct > 90 ? 'text-success' : ($compPct > 70 ? 'text-primary' : ($compPct > 40 ? 'text-warning' : 'text-danger')) ?>">
                        <?php
                        if ($compPct <= 40) echo 'Initial';
                        elseif ($compPct <= 70) echo 'Developing';
                        elseif ($compPct <= 90) echo 'Managed';
                        else echo 'Optimized';
                        ?>
                    </strong>
                </small>
            </div>
        </div>
    </div>

    <!-- Filter / Expand controls -->
    <div class="d-flex justify-content-between align-items-center mb-3">
        <div>
            <button class="btn btn-sm btn-outline-secondary" onclick="toggleAllSections(true)">Expand All</button>
            <button class="btn btn-sm btn-outline-secondary" onclick="toggleAllSections(false)">Collapse All</button>
            <select id="statusFilter" class="form-select form-select-sm d-inline-block ms-2" style="width:auto" onchange="filterByStatus()">
                <option value="all">Show All</option>
                <option value="Not Assessed">Not Assessed Only</option>
                <option value="Non-Compliant">Non-Compliant Only</option>
                <option value="Partially Compliant">Partially Compliant Only</option>
                <option value="Compliant">Compliant Only</option>
            </select>
        </div>
        <div>
            <button class="btn btn-outline-info btn-sm me-2" onclick="toggleGuidance()">
                <i class="bi bi-info-circle"></i> Toggle Guidance
            </button>
        </div>
    </div>

    <!-- ============ NIST FUNCTION SECTIONS ============ -->
    <?php
    $fnClasses = [
        'Identify' => 'fn-identify',
        'Protect' => 'fn-protect',
        'Detect' => 'fn-detect',
        'Respond' => 'fn-respond',
        'Recover' => 'fn-recover'
    ];
    $fnIcons = [
        'Identify' => '🔍',
        'Protect' => '🛡️',
        'Detect' => '📡',
        'Respond' => '🚨',
        'Recover' => '🔄'
    ];
    ?>

    <?php foreach ($controlsByFunction as $func => $controls): ?>
        <?php
        $fnCount = count($controls);
        $fnCompliant = 0;
        foreach ($controls as $c) {
            $saved = $savedChecklist[$c['control_id']] ?? null;
            if ($saved && $saved['status'] === 'Compliant') $fnCompliant++;
        }
        ?>
        <div class="function-section" data-function="<?= $func ?>">
            <div class="nist-function-header <?= $fnClasses[$func] ?> d-flex justify-content-between align-items-center"
                 style="cursor:pointer" onclick="toggleSection('<?= $func ?>')">
                <span><?= $fnIcons[$func] ?> <?= strtoupper($func) ?> (<?= $fnCount ?> controls)</span>
                <span>
                    <span class="badge bg-light text-dark"><?= $fnCompliant ?>/<?= $fnCount ?> compliant</span>
                    <i class="bi bi-chevron-down ms-2" id="icon-<?= $func ?>"></i>
                </span>
            </div>
            <div class="function-body" id="body-<?= $func ?>">
                <?php foreach ($controls as $ctrl): ?>
                    <?php
                    $cid = $ctrl['control_id'];
                    $saved = $savedChecklist[$cid] ?? null;
                    $currentStatus = $saved['status'] ?? 'Not Assessed';
                    $currentNotes = $saved['notes'] ?? '';
                    $statusClass = '';
                    if ($currentStatus === 'Compliant') $statusClass = 'status-Compliant';
                    elseif ($currentStatus === 'Partially Compliant') $statusClass = 'status-Partially';
                    elseif ($currentStatus === 'Non-Compliant') $statusClass = 'status-Non-Compliant';
                    elseif ($currentStatus === 'Not Applicable') $statusClass = 'status-Not-Applicable';
                    ?>
                    <div class="control-row" data-control="<?= $cid ?>" data-status="<?= $currentStatus ?>">
                        <div class="row align-items-start">
                            <div class="col-md-6">
                                <span class="control-id-badge"><?= $cid ?></span>
                                <span class="control-title ms-2"><?= htmlspecialchars($ctrl['title']) ?></span>
                                <div class="control-desc ms-1 mt-1"><?= htmlspecialchars($ctrl['description']) ?></div>
                                <div class="control-guidance mt-1" style="display:none">
                                    <strong>Audit Guidance:</strong> <?= htmlspecialchars($ctrl['guidance']) ?>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <select class="form-select form-select-sm status-select <?= $statusClass ?>"
                                        data-control="<?= $cid ?>"
                                        onchange="onStatusChange(this)">
                                    <option value="Not Assessed" <?= $currentStatus === 'Not Assessed' ? 'selected' : '' ?>>Not Assessed</option>
                                    <option value="Compliant" <?= $currentStatus === 'Compliant' ? 'selected' : '' ?>>✅ Compliant</option>
                                    <option value="Partially Compliant" <?= $currentStatus === 'Partially Compliant' ? 'selected' : '' ?>>⚠️ Partially Compliant</option>
                                    <option value="Non-Compliant" <?= $currentStatus === 'Non-Compliant' ? 'selected' : '' ?>>❌ Non-Compliant</option>
                                    <option value="Not Applicable" <?= $currentStatus === 'Not Applicable' ? 'selected' : '' ?>>➖ Not Applicable</option>
                                </select>
                            </div>
                            <div class="col-md-3">
                                <textarea class="form-control form-control-sm notes-input"
                                          data-control="<?= $cid ?>"
                                          rows="2"
                                          placeholder="Auditor notes / evidence..."><?= htmlspecialchars($currentNotes) ?></textarea>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>
    <?php endforeach; ?>

    <!-- Floating Save Button -->
    <button class="btn btn-lg btn-success save-float" id="btnSaveAll" onclick="saveAll()">
        💾 Save All Changes
    </button>

    <!-- Status toast -->
    <div class="position-fixed bottom-0 start-50 translate-middle-x p-3" style="z-index:1060">
        <div id="saveToast" class="toast align-items-center text-bg-success border-0" role="alert">
            <div class="d-flex">
                <div class="toast-body" id="toastMsg">Saved!</div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        </div>
    </div>

    <input type="hidden" id="csrf_token" value="<?= $_SESSION['csrf_token'] ?? '' ?>">
    <input type="hidden" id="audit_id" value="<?= $audit_id ?>">

    <script>
        const TOTAL = <?= $totalControls ?>;
        let guidanceVisible = false;
        let hasUnsavedChanges = false;

        // Track changes
        document.querySelectorAll('.status-select, .notes-input').forEach(el => {
            el.addEventListener('change', () => { hasUnsavedChanges = true; });
            el.addEventListener('input', () => { hasUnsavedChanges = true; });
        });

        // Warn before leaving with unsaved changes
        window.addEventListener('beforeunload', e => {
            if (hasUnsavedChanges) {
                e.preventDefault();
                e.returnValue = '';
            }
        });

        // ---- Status change visual feedback ----
        function onStatusChange(sel) {
            // Update visual class
            sel.className = 'form-select form-select-sm status-select';
            const val = sel.value;
            if (val === 'Compliant') sel.classList.add('status-Compliant');
            else if (val === 'Partially Compliant') sel.classList.add('status-Partially');
            else if (val === 'Non-Compliant') sel.classList.add('status-Non-Compliant');
            else if (val === 'Not Applicable') sel.classList.add('status-Not-Applicable');

            // Update the data-status on parent row
            sel.closest('.control-row').dataset.status = val;

            // Recalculate summary
            recalcSummary();
        }

        // ---- Recalculate summary from DOM ----
        function recalcSummary() {
            let stats = { 'Compliant': 0, 'Partially Compliant': 0, 'Non-Compliant': 0, 'Not Applicable': 0, 'Not Assessed': 0 };
            document.querySelectorAll('.status-select').forEach(sel => {
                stats[sel.value] = (stats[sel.value] || 0) + 1;
            });
            document.getElementById('sumCompliant').textContent = stats['Compliant'];
            document.getElementById('sumPartial').textContent = stats['Partially Compliant'];
            document.getElementById('sumNonComp').textContent = stats['Non-Compliant'];
            document.getElementById('sumNA').textContent = stats['Not Applicable'];
            document.getElementById('sumNotAssessed').textContent = stats['Not Assessed'];

            const assessed = TOTAL - stats['Not Assessed'];
            document.getElementById('assessedCount').textContent = assessed;

            const applicable = TOTAL - stats['Not Applicable'];
            const pct = applicable > 0 ? Math.round(((stats['Compliant'] + stats['Partially Compliant'] * 0.5) / applicable) * 1000) / 10 : 0;
            document.getElementById('compPct').textContent = pct + '%';
            const bar = document.getElementById('compBar');
            bar.style.width = pct + '%';
            bar.textContent = pct + '%';
            bar.className = 'progress-bar progress-bar-striped ' + (pct >= 80 ? 'bg-success' : (pct >= 50 ? 'bg-warning' : 'bg-danger'));

            // Maturity
            let maturity = 'Initial';
            if (pct > 90) maturity = 'Optimized';
            else if (pct > 70) maturity = 'Managed';
            else if (pct > 40) maturity = 'Developing';
            const mb = document.getElementById('maturityBadge');
            mb.textContent = maturity;
            mb.className = pct > 90 ? 'text-success' : (pct > 70 ? 'text-primary' : (pct > 40 ? 'text-warning' : 'text-danger'));
        }

        // ---- Save All ----
        async function saveAll() {
            const btn = document.getElementById('btnSaveAll');
            btn.disabled = true;
            btn.innerHTML = '⏳ Saving...';

            const items = [];
            document.querySelectorAll('.control-row').forEach(row => {
                const cid = row.dataset.control;
                const status = row.querySelector('.status-select').value;
                const notes = row.querySelector('.notes-input').value.trim();
                items.push({ control_id: cid, status: status, notes: notes });
            });

            try {
                const res = await fetch('api/checklist_actions.php?action=save_bulk', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        audit_id: document.getElementById('audit_id').value,
                        csrf_token: document.getElementById('csrf_token').value,
                        items: items
                    })
                });
                const data = await res.json();
                if (data.success) {
                    showToast('✅ ' + data.message, 'success');
                    hasUnsavedChanges = false;
                } else {
                    showToast('❌ ' + data.message, 'danger');
                }
            } catch (err) {
                showToast('❌ Network error: ' + err.message, 'danger');
            }

            btn.disabled = false;
            btn.innerHTML = '💾 Save All Changes';
        }

        // ---- Toggle Sections ----
        function toggleSection(func) {
            const body = document.getElementById('body-' + func);
            const icon = document.getElementById('icon-' + func);
            if (body.style.display === 'none') {
                body.style.display = '';
                icon.classList.replace('bi-chevron-right', 'bi-chevron-down');
            } else {
                body.style.display = 'none';
                icon.classList.replace('bi-chevron-down', 'bi-chevron-right');
            }
        }

        function toggleAllSections(show) {
            document.querySelectorAll('.function-body').forEach(b => b.style.display = show ? '' : 'none');
            document.querySelectorAll('[id^="icon-"]').forEach(i => {
                i.classList.remove('bi-chevron-down', 'bi-chevron-right');
                i.classList.add(show ? 'bi-chevron-down' : 'bi-chevron-right');
            });
        }

        // ---- Toggle Guidance ----
        function toggleGuidance() {
            guidanceVisible = !guidanceVisible;
            document.querySelectorAll('.control-guidance').forEach(g => {
                g.style.display = guidanceVisible ? 'block' : 'none';
            });
        }

        // ---- Filter by Status ----
        function filterByStatus() {
            const filter = document.getElementById('statusFilter').value;
            document.querySelectorAll('.control-row').forEach(row => {
                if (filter === 'all') {
                    row.style.display = '';
                } else {
                    row.style.display = row.dataset.status === filter ? '' : 'none';
                }
            });
        }

        // ---- Toast Helper ----
        function showToast(msg, type) {
            const t = document.getElementById('saveToast');
            t.className = 'toast align-items-center text-bg-' + type + ' border-0';
            document.getElementById('toastMsg').textContent = msg;
            new bootstrap.Toast(t, { delay: 3000 }).show();
        }
    </script>

<?php endif; ?>

<?php include 'includes/footer.php'; ?>
