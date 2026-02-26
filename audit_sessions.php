<?php
session_start();
require_once 'functions/db.php';
require_once 'functions/auth.php';

requireLogin();
requireAuditor(); // Only admin/auditor can manage audit sessions

$userId = $_SESSION['user_id'];

// Ambil org_id dari URL
$orgId = intval($_GET['org_id'] ?? 0);

if ($orgId <= 0) {
    die("Invalid organization.");
}

// Verifikasi organization milik user
$stmt = $pdo->prepare("SELECT id, organization_name FROM organizations WHERE id = ? AND user_id = ?");
$stmt->execute([$orgId, $userId]);
$organization = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$organization) {
    die("Organization not found or access denied.");
}
?>

<?php include 'includes/header.php'; ?>
<?php include 'includes/sidebar.php'; ?>

<div class="container mt-4">
    <h2 class="mb-4">Create Audit Session</h2>

    <div class="card shadow-sm mb-4">
        <div class="card-body">

            <form id="auditForm">
                <?= csrfTokenInput(); ?>

                <!-- Kirim organization_id sebagai hidden -->
                <input type="hidden" name="organization_id" value="<?= $organization['id'] ?>">

                <div class="mb-3">
                    <label class="form-label">Organization</label>
                    <input type="text" class="form-control"
                           value="<?= htmlspecialchars($organization['organization_name']) ?>"
                           disabled>
                </div>

                <div class="mb-3">
                    <label class="form-label">Session Name</label>
                    <input type="text" name="session_name" class="form-control" required>
                </div>

                <div class="mb-3">
                    <label class="form-label">Digital Scale</label>
                    <select name="digital_scale" class="form-select" required>
                        <option value="Low">Low</option>
                        <option value="Medium">Medium</option>
                        <option value="High">High</option>
                    </select>
                </div>

                <div class="mb-3">
                    <label class="form-label">Audit Date</label>
                    <input type="date" name="audit_date" class="form-control" required>
                </div>

                <div class="mb-3">
                    <label class="form-label">Notes (Optional)</label>
                    <textarea name="notes" class="form-control"></textarea>
                </div>

                <button type="submit" class="btn btn-primary">
                    Create Audit
                </button>

            </form>

        </div>
    </div>

    <!-- Existing Audit Sessions for this Org -->
    <?php
    $stmtExisting = $pdo->prepare("SELECT * FROM audit_sessions WHERE organization_id = ? ORDER BY audit_date DESC");
    $stmtExisting->execute([$orgId]);
    $existingAudits = $stmtExisting->fetchAll(PDO::FETCH_ASSOC);
    ?>
    <?php if (count($existingAudits) > 0): ?>
    <div class="card shadow-sm mb-4">
        <div class="card-header bg-dark text-white">
            <h6 class="mb-0">Existing Audit Sessions</h6>
        </div>
        <div class="card-body p-0">
            <table class="table table-hover mb-0">
                <thead class="table-light">
                    <tr>
                        <th>Session Name</th>
                        <th>Date</th>
                        <th>Status</th>
                        <th>Assigned Auditees</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($existingAudits as $ea): ?>
                        <?php
                        $stmtAA = $pdo->prepare("SELECT u.name FROM audit_auditees aa JOIN users u ON aa.auditee_user_id = u.id WHERE aa.audit_id = ?");
                        $stmtAA->execute([$ea['id']]);
                        $assignedNames = $stmtAA->fetchAll(PDO::FETCH_COLUMN);
                        ?>
                        <tr>
                            <td><?= htmlspecialchars($ea['session_name']) ?></td>
                            <td><?= htmlspecialchars($ea['audit_date']) ?></td>
                            <td><span class="badge bg-secondary"><?= htmlspecialchars($ea['status']) ?></span></td>
                            <td>
                                <?php if (count($assignedNames) > 0): ?>
                                    <?php foreach ($assignedNames as $aName): ?>
                                        <span class="badge bg-info"><?= htmlspecialchars($aName) ?></span>
                                    <?php endforeach; ?>
                                <?php else: ?>
                                    <span class="text-muted">None</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <button class="btn btn-sm btn-outline-primary assignAuditeeBtn" 
                                        data-audit-id="<?= $ea['id'] ?>"
                                        data-audit-name="<?= htmlspecialchars($ea['session_name']) ?>">
                                    <i class="fas fa-user-plus"></i> Assign Auditee
                                </button>
                                <a href="dashboard.php?audit_id=<?= $ea['id'] ?>" class="btn btn-sm btn-outline-dark">
                                    <i class="fas fa-eye"></i> Open
                                </a>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
    <?php endif; ?>
</div>

<!-- Assign Auditee Modal -->
<div class="modal fade" id="assignAuditeeModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Assign Auditee to <span id="assignAuditName"></span></h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <div id="assignAlertBox"></div>
                <input type="hidden" id="assignAuditId">
                
                <div class="mb-3">
                    <label class="form-label">Select Auditee</label>
                    <select id="auditeeSelect" class="form-select">
                        <option value="">Loading...</option>
                    </select>
                </div>

                <h6>Currently Assigned:</h6>
                <div id="currentAuditees" class="mb-3">
                    <span class="text-muted">Loading...</span>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                <button type="button" class="btn btn-primary" id="confirmAssignBtn">Assign</button>
            </div>
        </div>
    </div>
</div>

<script>
document.getElementById('auditForm').addEventListener('submit', function(e) {
    e.preventDefault();

    const formData = new FormData(this);

    fetch('api/audit_actions.php?action=create', {
        method: 'POST',
        body: formData
    })
    .then(res => {
        const contentType = res.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
            return res.text().then(text => {
                console.error('Non-JSON response:', text);
                throw new Error('Server returned non-JSON response. Check browser console.');
            });
        }
        return res.json();
    })
    .then(data => {
        if (data.success) {
            window.location.reload();
        } else {
            alert(data.message || 'Error creating audit session');
        }
    })
    .catch(err => {
        console.error('Error:', err);
        alert(err.message || "Error creating audit session");
    });
});

// Assign Auditee Modal logic
const assignModal = new bootstrap.Modal(document.getElementById('assignAuditeeModal'));

document.querySelectorAll('.assignAuditeeBtn').forEach(btn => {
    btn.addEventListener('click', function() {
        const auditId = this.dataset.auditId;
        const auditName = this.dataset.auditName;
        document.getElementById('assignAuditId').value = auditId;
        document.getElementById('assignAuditName').textContent = auditName;
        
        // Load available auditees
        fetch('api/audit_actions.php?action=available_auditees')
            .then(r => r.json())
            .then(data => {
                const sel = document.getElementById('auditeeSelect');
                sel.innerHTML = '<option value="">Select Auditee...</option>';
                if (data.success) {
                    data.data.forEach(u => {
                        sel.innerHTML += `<option value="${u.id}">${u.name} (${u.email})</option>`;
                    });
                }
            });
        
        // Load currently assigned
        loadAssigned(auditId);
        assignModal.show();
    });
});

function loadAssigned(auditId) {
    fetch('api/audit_actions.php?action=list_auditees&audit_id=' + auditId)
        .then(r => r.json())
        .then(data => {
            const div = document.getElementById('currentAuditees');
            if (data.success && data.data.length > 0) {
                div.innerHTML = data.data.map(a => 
                    `<span class="badge bg-info me-1">${a.name} 
                        <button type="button" class="btn-close btn-close-white ms-1" style="font-size:0.6em" 
                                onclick="removeAuditee(${auditId}, ${a.id})"></button>
                    </span>`
                ).join('');
            } else {
                div.innerHTML = '<span class="text-muted">No auditees assigned yet</span>';
            }
        });
}

document.getElementById('confirmAssignBtn').addEventListener('click', function() {
    const auditId = document.getElementById('assignAuditId').value;
    const auditeeId = document.getElementById('auditeeSelect').value;
    const alertBox = document.getElementById('assignAlertBox');
    
    if (!auditeeId) {
        alertBox.innerHTML = '<div class="alert alert-warning">Please select an auditee</div>';
        return;
    }

    const fd = new FormData();
    fd.append('audit_id', auditId);
    fd.append('auditee_user_id', auditeeId);

    fetch('api/audit_actions.php?action=assign_auditee', {
        method: 'POST',
        body: fd
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            alertBox.innerHTML = '<div class="alert alert-success">' + data.message + '</div>';
            loadAssigned(auditId);
        } else {
            alertBox.innerHTML = '<div class="alert alert-danger">' + data.message + '</div>';
        }
    });
});

function removeAuditee(auditId, auditeeId) {
    if (!confirm('Remove this auditee from the audit?')) return;
    
    const fd = new FormData();
    fd.append('audit_id', auditId);
    fd.append('auditee_user_id', auditeeId);

    fetch('api/audit_actions.php?action=remove_auditee', {
        method: 'POST',
        body: fd
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            loadAssigned(auditId);
        } else {
            alert(data.message);
        }
    });
}
</script>

<?php include 'includes/footer.php'; ?>