<?php
session_start();
require_once 'functions/db.php';
require_once 'functions/auth.php';

requireLogin();
requireAuditor(); // Only admin/auditor can manage audit sessions

$userId = $_SESSION['user_id'];
$userRole = $_SESSION['user_role'] ?? 'auditor';

// Ambil org_id dari URL
$orgId = intval($_GET['org_id'] ?? 0);

if ($orgId <= 0) {
    header('Location: organizations.php');
    exit();
}

// Verifikasi organization — auditor must own it
$stmt = $pdo->prepare("SELECT id, organization_name FROM organizations WHERE id = ? AND user_id = ?");
$stmt->execute([$orgId, $userId]);
$organization = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$organization) {
    die("Organization not found or access denied.");
}
?>

<?php include 'includes/header.php'; ?>
<?php include 'includes/sidebar.php'; ?>

<!-- Flatpickr Date Picker -->
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/flatpickr/dist/flatpickr.min.css">
<script src="https://cdn.jsdelivr.net/npm/flatpickr"></script>
<style>
.flatpickr-day.selected, .flatpickr-day.selected:hover,
.flatpickr-day.selected.prevMonthDay, .flatpickr-day.selected.nextMonthDay {
    background: #4e89d4; border-color: #4e89d4;
}
.flatpickr-months .flatpickr-month { background: #4e89d4; }
.flatpickr-current-month .flatpickr-monthDropdown-months { background: #4e89d4; }
.flatpickr-weekdays { background: #4e89d4; }
span.flatpickr-weekday { background: #4e89d4; color: #fff; }
.flatpickr-calendar { box-shadow: 0 4px 20px rgba(0,0,0,.12); border-radius: 10px; }
#auditDatePicker { cursor: pointer; background: #fff; }
</style>

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
                    <div class="input-group">
                        <span class="input-group-text text-secondary"><i class="fas fa-calendar-alt"></i></span>
                        <input type="text" id="auditDatePicker" name="audit_date"
                               class="form-control" placeholder="Select a date…" autocomplete="off" readonly required>
                    </div>
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
                    <label class="form-label d-flex justify-content-between align-items-center">
                        <span>Select Auditee</span>
                        <button type="button" class="btn btn-sm btn-outline-success py-0" id="openCreateAuditeeBtn">
                            <i class="fas fa-user-plus me-1"></i>New Auditee
                        </button>
                    </label>
                    <select id="auditeeSelect" class="form-select">
                        <option value="">Select Auditee...</option>
                    </select>
                    <div class="form-text text-muted">Don't see anyone? Click <strong>New Auditee</strong> to create an account.</div>
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

<!-- Create Auditee Modal -->
<div class="modal fade" id="createAuditeeModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title"><i class="fas fa-user-plus me-2"></i>Create Auditee Account</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <div id="createAuditeeAlert"></div>
                <p class="text-muted small mb-3">Create a new user account with the <strong>Auditee</strong> role. Share the credentials with them so they can log in.</p>
                <div class="mb-3">
                    <label class="form-label">Full Name</label>
                    <input type="text" id="newAuditeeName" class="form-control" placeholder="e.g. John Doe">
                </div>
                <div class="mb-3">
                    <label class="form-label">Email Address</label>
                    <input type="email" id="newAuditeeEmail" class="form-control" placeholder="e.g. john@company.com">
                </div>
                <div class="mb-3">
                    <label class="form-label">Temporary Password</label>
                    <input type="text" id="newAuditeePassword" class="form-control mb-2" placeholder="Min. 6 characters">
                    <button class="btn btn-warning w-100" type="button" id="genPasswordBtn">
                        <i class="fas fa-dice me-2"></i>Generate Random Password
                    </button>
                    <div class="form-text mt-1">Give this password to the auditee. They can change it later.</div>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" id="backToAssignBtn">Back</button>
                <button type="button" class="btn btn-success" id="confirmCreateAuditeeBtn">
                    <i class="fas fa-check me-1"></i>Create Account
                </button>
            </div>
        </div>
    </div>
</div>

<script>
document.addEventListener('DOMContentLoaded', function() {

    // Flatpickr date picker
    flatpickr('#auditDatePicker', {
        dateFormat: 'Y-m-d',
        allowInput: false,
        disableMobile: true,
        minDate: 'today',
    });

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

    // Assign Auditee Modal logic — created lazily after Bootstrap JS is loaded
    var assignModal = null;
    function getAssignModal() {
        if (!assignModal) {
            assignModal = new bootstrap.Modal(document.getElementById('assignAuditeeModal'));
        }
        return assignModal;
    }

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
            getAssignModal().show();
        });
    });

    window.loadAssigned = function(auditId) {
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
    };

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

    // ---- Create Auditee Modal ----
    var createAuditeeModal = null;
    function getCreateAuditeeModal() {
        if (!createAuditeeModal) {
            createAuditeeModal = new bootstrap.Modal(document.getElementById('createAuditeeModal'));
        }
        return createAuditeeModal;
    }

    document.getElementById('openCreateAuditeeBtn').addEventListener('click', function() {
        getAssignModal().hide();
        document.getElementById('createAuditeeAlert').innerHTML = '';
        document.getElementById('newAuditeeName').value = '';
        document.getElementById('newAuditeeEmail').value = '';
        document.getElementById('newAuditeePassword').value = '';
        getCreateAuditeeModal().show();
    });

    document.getElementById('backToAssignBtn').addEventListener('click', function() {
        getCreateAuditeeModal().hide();
        getAssignModal().show();
    });

    document.getElementById('genPasswordBtn').addEventListener('click', function() {
        const chars = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789@#!';
        let pwd = '';
        for (let i = 0; i < 10; i++) pwd += chars[Math.floor(Math.random() * chars.length)];
        document.getElementById('newAuditeePassword').value = pwd;
    });

    document.getElementById('confirmCreateAuditeeBtn').addEventListener('click', function() {
        const name = document.getElementById('newAuditeeName').value.trim();
        const email = document.getElementById('newAuditeeEmail').value.trim();
        const password = document.getElementById('newAuditeePassword').value.trim();
        const alertBox = document.getElementById('createAuditeeAlert');

        if (!name || !email || !password) {
            alertBox.innerHTML = '<div class="alert alert-warning">Please fill in all fields.</div>';
            return;
        }

        const fd = new FormData();
        fd.append('name', name);
        fd.append('email', email);
        fd.append('password', password);

        fetch('api/audit_actions.php?action=create_auditee', { method: 'POST', body: fd })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    alertBox.innerHTML = `<div class="alert alert-success"><strong>Account created!</strong><br>${data.message}<br><small class="text-muted">Email: <strong>${email}</strong> &nbsp;|&nbsp; Password: <strong>${password}</strong></small></div>`;
                    document.getElementById('newAuditeeName').value = '';
                    document.getElementById('newAuditeeEmail').value = '';
                    document.getElementById('newAuditeePassword').value = '';
                    // Refresh the auditee dropdown
                    const auditId = document.getElementById('assignAuditId').value;
                    fetch('api/audit_actions.php?action=available_auditees')
                        .then(r => r.json())
                        .then(res => {
                            if (res.success) {
                                const sel = document.getElementById('auditeeSelect');
                                sel.innerHTML = '<option value="">Select Auditee...</option>';
                                res.data.forEach(u => {
                                    sel.innerHTML += `<option value="${u.id}">${u.name} (${u.email})</option>`;
                                });
                                // Pre-select the newly created user
                                const opt = [...sel.options].find(o => o.text.includes(email));
                                if (opt) opt.selected = true;
                            }
                        });
                } else {
                    alertBox.innerHTML = `<div class="alert alert-danger">${data.message}</div>`;
                }
            })
            .catch(() => {
                alertBox.innerHTML = '<div class="alert alert-danger">Network error. Please try again.</div>';
            });
    });

    window.removeAuditee = function(auditId, auditeeId) {
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
    };

}); // end DOMContentLoaded
</script>

<?php include 'includes/footer.php'; ?>