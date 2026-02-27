<?php
session_start();
require_once 'functions/db.php';
require_once 'functions/auth.php';
require_once 'functions/risk.php';
require_once 'functions/owasp.php';

requireLogin();

$userId   = $_SESSION['user_id'];
$userRole = $_SESSION['user_role'] ?? 'auditor';
$audit_id = intval($_GET['audit_id'] ?? ($_SESSION['active_audit_id'] ?? 0));
$selectedOrgId = intval($_GET['org_id'] ?? 0);
$pageError = '';

if ($userRole === 'auditee') {
    // Auditee: only see assigned audits
    $organizations = [];
    $assignedAudits = getAuditeeAssignedAudits($pdo, $userId);
    
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
    } elseif ($audit_id > 0) {
        $_SESSION['active_audit_id'] = $audit_id;
    }
} else {
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

$hasEvidenceTable = false;
try {
    $stmtEvidenceTable = $pdo->query("SHOW TABLES LIKE 'audit_evidence'");
    $hasEvidenceTable = $stmtEvidenceTable && $stmtEvidenceTable->fetch() ? true : false;
} catch (Exception $e) {
    $hasEvidenceTable = false;
}
?>

<?php include 'includes/header.php'; ?>
<?php include 'includes/sidebar.php'; ?>

<div class="container mt-4">

<h2 class="mb-4"><?= $userRole === 'auditee' ? 'Findings & Management Response' : 'Vulnerability & Risk Assessment' ?></h2>

<div class="card shadow-sm mb-4">
<div class="card-body">
<h5 class="mb-3">Select Organization & Audit Session</h5>
<form id="findingAuditSwitcher" class="row g-2">
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
            <option value="">Select Audit Session</option>
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
    <div class="alert alert-warning">Please select an audit session to view findings.</div>
<?php else: ?>

<?php if ($userRole === 'auditor'): ?>
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
    <span id="riskBadge" class="badge badge-srm-success">1</span>
</div>

<button type="submit" class="btn btn-danger">
    Save Finding
</button>

</form>
</div>
</div>
<?php endif; /* auditor only - add finding form */ ?>

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
    <th>Status</th>
    <?php if ($userRole === 'auditor'): ?>
        <th>Actions</th>
    <?php endif; ?>
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
                    <span class="badge badge-srm-info"><?= htmlspecialchars($f['owasp_category']) ?></span>
                <?php else: ?>
                    <span class="text-muted">—</span>
                <?php
                endif;
                $riskScore = (int)($f['risk_score'] ?? 0);
                $riskScoreBadgeClass = 'badge-srm-success';
                if ($riskScore >= 13) {
                    $riskScoreBadgeClass = 'badge-srm-danger';
                } elseif ($riskScore >= 6) {
                    $riskScoreBadgeClass = 'badge-srm-warning';
                }
                ?>
            </td>
            <td>
                <span class="badge <?= $riskScoreBadgeClass ?>">
                    <?= $f['risk_score'] ?>
                </span>
            </td>
            <td><?= htmlspecialchars($f['nist_function']) ?></td>
            <td><?= htmlspecialchars($f['audit_status'] ?? 'Non-Compliant') ?></td>
            <td style="max-width:200px; font-size:0.85rem;">
                <?= !empty($f['recommendation']) ? htmlspecialchars(mb_strimwidth($f['recommendation'], 0, 120, '...')) : '<span class="text-muted">—</span>' ?>
            </td>
            <td>
                <?php 
                $currentStatus = $f['remediation_status'] ?? 'Open';
                $statusClass = 'bg-danger';
                if ($currentStatus === 'Resolved') $statusClass = 'bg-success';
                elseif ($currentStatus === 'In Progress') $statusClass = 'bg-warning text-dark';
                elseif ($currentStatus === 'Accepted Risk') $statusClass = 'bg-info';
                ?>
                <span class="badge <?= $statusClass ?>"><?= htmlspecialchars($currentStatus) ?></span>
            </td>
            <?php if ($userRole === 'auditor'): ?>
            <td style="min-width: 220px;">
                <?php if ($currentStatus === 'In Progress' || $currentStatus === 'Open'): ?>
                    <form class="closeFindingForm d-flex flex-wrap gap-1 align-items-center" data-finding-id="<?= intval($f['id']) ?>">
                        <input type="hidden" name="finding_id" value="<?= intval($f['id']) ?>">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generateCSRFToken()) ?>">
                        <input type="date" name="remediation_deadline"
                               value="<?= htmlspecialchars($f['remediation_deadline'] ?? '') ?>"
                               class="form-control form-control-sm close-date-input"
                               style="width:130px" title="Enter resolved date first">
                        <button type="submit" class="btn btn-sm btn-success close-btn"
                                title="Mark as resolved"
                                <?= empty($f['remediation_deadline']) ? 'disabled' : '' ?>>
                            <i class="fas fa-check"></i> Close
                        </button>
                    </form>
                    <small class="text-muted" style="font-size:0.75rem;">Date required to close</small>
                <?php endif; ?>
                <?php if ($currentStatus === 'Resolved'): ?>
                    <form class="reopenFindingForm d-inline" data-finding-id="<?= intval($f['id']) ?>">
                        <input type="hidden" name="finding_id" value="<?= intval($f['id']) ?>">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generateCSRFToken()) ?>">
                        <button type="submit" class="btn btn-sm btn-outline-warning" title="Reopen Finding">
                            <i class="fas fa-redo"></i> Reopen
                        </button>
                    </form>
                    <?php if (!empty($f['remediation_deadline'])): ?>
                        <small class="text-muted d-block mt-1"><?= date('d M Y', strtotime($f['remediation_deadline'])) ?></small>
                    <?php endif; ?>
                <?php endif; ?>
            </td>
            <?php endif; ?>
        </tr>
        <tr>
            <td colspan="<?= $userRole === 'auditor' ? 9 : 8 ?>">
                <details <?= $userRole === 'auditee' ? 'open' : '' ?>>
                    <summary class="cursor-pointer" style="cursor: pointer;">
                        <strong>Details & Evidence</strong>
                        <?php if (!empty($f['management_response'])): ?>
                            <span class="badge bg-info ms-2">Has Response</span>
                        <?php endif; ?>
                        <?php if ($hasEvidenceTable): ?>
                            <?php 
                            $stmtEv = $pdo->prepare("SELECT COUNT(*) as count FROM audit_evidence WHERE finding_id = ?");
                            $stmtEv->execute([$f['id']]);
                            $eviCount = $stmtEv->fetch(PDO::FETCH_ASSOC)['count'];
                            echo ' (' . $eviCount . ' files)';
                            ?>
                        <?php endif; ?>
                    </summary>
                    <div class="p-3 bg-light mt-2">
                        
                        <!-- Management Response Section -->
                        <div class="mb-3">
                            <h6><i class="fas fa-reply"></i> Management Response</h6>
                            <?php if (!empty($f['management_response'])): ?>
                                <div class="border rounded p-2 bg-white mb-2">
                                    <p class="mb-1"><?= nl2br(htmlspecialchars($f['management_response'])) ?></p>
                                    <small class="text-muted">
                                        Responded: <?= $f['response_date'] ? date('M d, Y H:i', strtotime($f['response_date'])) : '—' ?>
                                    </small>
                                </div>
                            <?php else: ?>
                                <p class="text-muted mb-2">No management response yet.</p>
                            <?php endif; ?>

                            <?php if ($userRole === 'auditee' && ($f['remediation_status'] ?? 'Open') !== 'Resolved'): ?>
                                <form class="mgmtResponseForm" data-finding-id="<?= intval($f['id']) ?>">
                                    <input type="hidden" name="finding_id" value="<?= intval($f['id']) ?>">
                                    <input type="hidden" name="audit_id" value="<?= intval($audit_id) ?>">
                                    <textarea name="management_response" class="form-control form-control-sm mb-2" rows="3" 
                                              placeholder="Enter your response: action plan, timeline, remediation steps..."><?= htmlspecialchars($f['management_response'] ?? '') ?></textarea>
                                    <button type="submit" class="btn btn-sm btn-primary">
                                        <i class="fas fa-paper-plane"></i> Submit Response
                                    </button>
                                </form>
                            <?php endif; ?>
                        </div>

                        <hr>

                        <!-- Evidence Section -->
                        <?php if (!$hasEvidenceTable): ?>
                            <div class="alert alert-warning mb-2">
                                Evidence feature not active (table missing).
                            </div>
                        <?php else: ?>
                            <?php
                            // Fetch evidence for this finding with uploader info
                            $stmtEvi = $pdo->prepare("SELECT ae.id, ae.original_filename, ae.stored_filename, ae.file_path, ae.evidence_type, ae.created_at, ae.uploaded_by, ae.evidence_status, ae.review_notes,
                                    COALESCE(u.name, 'Unknown') AS uploader_name, COALESCE(u.role, '') AS uploader_role
                                FROM audit_evidence ae
                                LEFT JOIN users u ON ae.uploaded_by = u.id
                                WHERE ae.finding_id = ? ORDER BY ae.created_at DESC");
                            $stmtEvi->execute([$f['id']]);
                            $evidence = $stmtEvi->fetchAll(PDO::FETCH_ASSOC);
                            ?>

                            <?php if ($userRole === 'auditee'): ?>
                                <h6 class="text-primary"><i class="fas fa-upload"></i> Upload Evidence</h6>
                                <p class="text-muted" style="font-size:0.85rem;">Upload documents, screenshots, or files that prove this control has been implemented or remediated.</p>
                                <form class="evidenceUploadForm mb-3" enctype="multipart/form-data" data-finding-id="<?= intval($f['id']) ?>">
                                    <input type="hidden" name="finding_id" value="<?= intval($f['id']) ?>">
                                    <input type="hidden" name="audit_id" value="<?= intval($audit_id) ?>">
                                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generateCSRFToken()) ?>">
                                    <div class="row g-2 align-items-end">
                                        <div class="col-md-8">
                                            <input type="file" name="evidence_file" class="form-control form-control-sm" accept=".jpg,.jpeg,.png,.pdf,.doc,.docx,.xls,.xlsx,.txt" multiple>
                                        </div>
                                        <div class="col-md-4 d-grid">
                                            <button type="submit" class="btn btn-sm btn-primary"><i class="fas fa-cloud-upload-alt"></i> Upload Evidence</button>
                                        </div>
                                    </div>
                                    <small class="text-muted d-block mt-1">Accepted: images, PDF, Word, Excel, text (max 10MB each)</small>
                                </form>
                            <?php endif; ?>

                            <?php if (count($evidence) > 0): ?>
                            <h6><?= $userRole === 'auditor' ? '<i class="fas fa-clipboard-check"></i> Evidence Review' : '<i class="fas fa-folder-open"></i> Uploaded Evidence' ?></h6>
                            <table class="table table-sm table-bordered">
                                <thead class="table-light">
                                    <tr>
                                        <th>File</th>
                                        <th>Type</th>
                                        <th>Uploaded By</th>
                                        <th>Date</th>
                                        <th>Status</th>
                                        <th>Action</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($evidence as $evi): 
                                        $eviStatus = $evi['evidence_status'] ?? 'Pending Review';
                                        $statusBadge = 'bg-secondary';
                                        if ($eviStatus === 'Accepted') $statusBadge = 'bg-success';
                                        elseif ($eviStatus === 'Rejected') $statusBadge = 'bg-danger';
                                        elseif ($eviStatus === 'Needs Revision') $statusBadge = 'bg-warning text-dark';
                                    ?>
                                    <tr>
                                        <td><?= htmlspecialchars($evi['original_filename']) ?></td>
                                        <td><small><?= htmlspecialchars($evi['evidence_type']) ?></small></td>
                                        <td>
                                            <small>
                                                <?= htmlspecialchars($evi['uploader_name']) ?>
                                                <span class="badge <?= ($evi['uploader_role'] === 'auditee') ? 'bg-success' : 'bg-primary' ?>" style="font-size:0.65rem;">
                                                    <?= htmlspecialchars(ucfirst($evi['uploader_role'])) ?>
                                                </span>
                                            </small>
                                        </td>
                                        <td><small><?= date('M d, Y', strtotime($evi['created_at'])) ?></small></td>
                                        <td><span class="badge <?= $statusBadge ?>"><?= htmlspecialchars($eviStatus) ?></span></td>
                                        <td style="white-space:nowrap;">
                                            <a href="<?= htmlspecialchars($evi['file_path']) ?>" class="btn btn-sm btn-outline-info" target="_blank">View</a>
                                            <?php if ($userRole === 'auditor'): ?>
                                                <div class="btn-group btn-group-sm mt-1">
                                                    <button class="btn btn-outline-success reviewEviBtn" data-evi-id="<?= intval($evi['id']) ?>" data-status="Accepted" title="Accept evidence">✓</button>
                                                    <button class="btn btn-outline-warning reviewEviBtn" data-evi-id="<?= intval($evi['id']) ?>" data-status="Needs Revision" title="Needs revision">↻</button>
                                                    <button class="btn btn-outline-danger reviewEviBtn" data-evi-id="<?= intval($evi['id']) ?>" data-status="Rejected" title="Reject evidence">✕</button>
                                                </div>
                                            <?php endif; ?>
                                            <?php if ($userRole === 'auditor' || (isset($evi['uploaded_by']) && $evi['uploaded_by'] == $userId)): ?>
                                                <button class="btn btn-sm btn-outline-danger deleteEviBtn mt-1" data-evi-id="<?= intval($evi['id']) ?>">Delete</button>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                    <?php if (!empty($evi['review_notes'])): ?>
                                    <tr>
                                        <td colspan="6" class="bg-light">
                                            <small class="text-muted"><strong>Auditor note:</strong> <?= htmlspecialchars($evi['review_notes']) ?></small>
                                        </td>
                                    </tr>
                                    <?php endif; ?>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                            <?php else: ?>
                                <p class="text-muted"><?= $userRole === 'auditor' ? 'No evidence uploaded by auditee yet.' : 'No evidence files uploaded yet.' ?></p>
                            <?php endif; ?>
                            
                            <?php if ($userRole === 'auditor'): ?>
                            <hr>
                            <small class="text-muted d-block mb-2"><i class="fas fa-info-circle"></i> Auditors can upload supplementary documentation if needed.</small>
                            <form class="evidenceUploadForm" enctype="multipart/form-data" data-finding-id="<?= intval($f['id']) ?>">
                                <input type="hidden" name="finding_id" value="<?= intval($f['id']) ?>">
                                <input type="hidden" name="audit_id" value="<?= intval($audit_id) ?>">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generateCSRFToken()) ?>">
                                <input type="file" name="evidence_file" class="form-control form-control-sm mb-2" accept=".jpg,.jpeg,.png,.pdf,.doc,.docx,.xls,.xlsx,.txt" multiple>
                                <button type="submit" class="btn btn-sm btn-outline-secondary">Upload Documentation</button>
                            </form>
                            <?php endif; ?>
                        <?php endif; ?>
                    </div>
                </details>
            </td>
        </tr>
    <?php endforeach; ?>
<?php else: ?>
    <tr>
        <td colspan="<?= $userRole === 'auditor' ? 9 : 8 ?>" class="text-center">No findings yet</td>
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

document.getElementById('findingAuditSwitcher').addEventListener('submit', function(e) {
    e.preventDefault();
    const selectedAuditId = auditSelect.value;
    const selectedOrgId = orgSelect ? orgSelect.value : '';

    if (selectedAuditId) {
        window.location.href = 'findings.php?audit_id=' + encodeURIComponent(selectedAuditId);
        return;
    }

    if (selectedOrgId) {
        window.location.href = 'findings.php?org_id=' + encodeURIComponent(selectedOrgId);
    }
});

<?php if ($audit_id): ?>

// --- Auditor-only: Risk sliders & Add Finding form ---
(function() {
    const likelihood  = document.getElementById('likelihood');
    const impact      = document.getElementById('impact');
    const likeValue   = document.getElementById('likeValue');
    const impactValue = document.getElementById('impactValue');
    const riskBadge   = document.getElementById('riskBadge');
    const findingForm = document.getElementById('findingForm');

    if (likelihood && impact && likeValue && impactValue && riskBadge) {
        function updateRisk() {
            const risk = likelihood.value * impact.value;
            riskBadge.textContent = risk;
            let color = "badge-srm-success";
            if (risk >= 6)  color = "badge-srm-warning";
            if (risk >= 13) color = "badge-srm-danger";
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
    }

    if (findingForm) {
        findingForm.addEventListener('submit', function(e) {
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
    }
})();

// Enable Close button when date is entered
document.querySelectorAll('.close-date-input').forEach(input => {
    input.addEventListener('change', function() {
        const btn = this.closest('form').querySelector('.close-btn');
        if (btn) btn.disabled = !this.value;
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

// Evidence review handlers (auditor: Accept / Needs Revision / Reject)
document.querySelectorAll('.reviewEviBtn').forEach((btn) => {
    btn.addEventListener('click', function(e) {
        e.preventDefault();
        const eviId = this.dataset.eviId;
        const newStatus = this.dataset.status;
        let reviewNotes = '';

        if (newStatus === 'Rejected' || newStatus === 'Needs Revision') {
            reviewNotes = prompt('Provide a note for the auditee (reason / what to fix):');
            if (reviewNotes === null) return; // cancelled
        }

        fetch('api/evidence_actions.php?action=review', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                evidence_id: eviId,
                evidence_status: newStatus,
                review_notes: reviewNotes,
                csrf_token: '<?= htmlspecialchars(generateCSRFToken()) ?>'
            })
        })
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                location.reload();
            } else {
                alert(data.message || 'Error reviewing evidence');
            }
        })
        .catch(() => alert('Error reviewing evidence'));
    });
});

// Close finding handlers (auditor)
document.querySelectorAll('.closeFindingForm').forEach((form) => {
    form.addEventListener('submit', function(e) {
        e.preventDefault();
        if (!confirm('Close this finding? This marks it as Resolved.')) return;
        
        const formData = new FormData(this);
        fetch('api/finding_actions.php?action=close_finding', {
            method: 'POST',
            body: formData
        })
        .then(res => res.json())
        .then(data => {
            if (data.success) location.reload();
            else alert(data.message);
        })
        .catch(() => alert('Error closing finding'));
    });
});

// Reopen finding handlers (auditor)
document.querySelectorAll('.reopenFindingForm').forEach((form) => {
    form.addEventListener('submit', function(e) {
        e.preventDefault();
        if (!confirm('Reopen this finding?')) return;
        
        const formData = new FormData(this);
        fetch('api/finding_actions.php?action=reopen_finding', {
            method: 'POST',
            body: formData
        })
        .then(res => res.json())
        .then(data => {
            if (data.success) location.reload();
            else alert(data.message);
        })
        .catch(() => alert('Error reopening finding'));
    });
});

// Management response handlers (auditee)
document.querySelectorAll('.mgmtResponseForm').forEach((form) => {
    form.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const formData = new FormData(this);
        fetch('api/finding_actions.php?action=management_response', {
            method: 'POST',
            body: formData
        })
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                alert('Response submitted successfully!');
                location.reload();
            } else {
                alert(data.message || 'Error submitting response');
            }
        })
        .catch(() => alert('Error submitting response'));
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