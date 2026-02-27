<?php
session_start();
require_once 'functions/db.php';
require_once 'functions/auth.php';
requireLogin();
requireAuditor(); // Only admin/auditor can manage organizations

$userId = $_SESSION['user_id'];
$userRole = $_SESSION['user_role'] ?? 'auditor';

if ($userRole === 'admin') {
    // Admin: see ALL organizations (oversight)
    $stmt = $pdo->prepare("SELECT o.*, u.name as auditor_name, u.email as auditor_email,
                          (SELECT COUNT(*) FROM audit_sessions WHERE organization_id = o.id) as audit_count
                          FROM organizations o
                          JOIN users u ON o.user_id = u.id
                          ORDER BY o.is_active DESC, o.created_at DESC");
    $stmt->execute();
} else {
    // Auditor: see own organizations only
    $stmt = $pdo->prepare("SELECT o.*, 
                          (SELECT COUNT(*) FROM audit_sessions WHERE organization_id = o.id) as audit_count
                          FROM organizations o 
                          WHERE o.user_id = ? AND o.is_active = 1
                          ORDER BY o.created_at DESC");
    $stmt->execute([$userId]);
}
$organizations = $stmt->fetchAll();

include 'includes/header.php';
include 'includes/sidebar.php';
?>

<style>
    .audit-count-badge {
        background: #495057;
        color: #f8f9fa;
        border: 1px solid rgba(255, 255, 255, 0.18);
        font-weight: 600;
        min-width: 28px;
    }
    .status-active { color: #198754; font-weight: 600; }
    .status-inactive { color: #dc3545; font-weight: 600; }
    .org-detail-label { font-weight: 600; color: #6c757d; font-size: 0.82rem; text-transform: uppercase; letter-spacing: 0.3px; }
</style>

<h2 class="mb-4">Organizations</h2>

<?php if ($userRole === 'admin'): ?>
<!-- ============ ADMIN VIEW: Oversight — View All, Activate/Deactivate ============ -->
<div id="alertBox"></div>

<?php if (count($organizations) > 0): ?>
<div class="row g-3">
    <?php foreach ($organizations as $org): ?>
    <div class="col-md-6 col-lg-4">
        <div class="card shadow-sm h-100 <?= $org['is_active'] ? '' : 'border-danger bg-danger bg-opacity-10' ?>">
            <div class="card-body pb-2">
                <div class="d-flex justify-content-between align-items-start mb-2">
                    <div>
                        <h6 class="mb-0 fw-bold"><?= htmlspecialchars($org['organization_name']) ?></h6>
                        <small class="text-muted"><?= htmlspecialchars($org['industry']) ?></small>
                    </div>
                    <span class="badge <?= $org['is_active'] ? 'bg-success' : 'bg-danger' ?>">
                        <?= $org['is_active'] ? 'Active' : 'Inactive' ?>
                    </span>
                </div>

                <div class="row g-2 mb-2" style="font-size:0.85rem;">
                    <div class="col-6">
                        <span class="org-detail-label">Auditor</span><br>
                        <?= htmlspecialchars($org['auditor_name']) ?>
                    </div>
                    <div class="col-6">
                        <span class="org-detail-label">Employees</span><br>
                        <?= !empty($org['number_of_employees']) ? number_format(intval($org['number_of_employees'])) : '—' ?>
                    </div>
                    <div class="col-6">
                        <span class="org-detail-label">System Type</span><br>
                        <?= !empty($org['system_type']) ? htmlspecialchars($org['system_type']) : '—' ?>
                    </div>
                    <div class="col-6">
                        <span class="org-detail-label">Contact Person</span><br>
                        <?= !empty($org['contact_person']) ? htmlspecialchars($org['contact_person']) : '—' ?>
                    </div>
                    <div class="col-6">
                        <span class="org-detail-label">Contact Email</span><br>
                        <?= !empty($org['contact_email']) ? htmlspecialchars($org['contact_email']) : '—' ?>
                    </div>
                    <div class="col-6">
                        <span class="org-detail-label">Contact Phone</span><br>
                        <?= !empty($org['contact_phone']) ? htmlspecialchars($org['contact_phone']) : '—' ?>
                    </div>
                    <div class="col-12">
                        <span class="org-detail-label">Address</span><br>
                        <?= !empty($org['address']) ? htmlspecialchars($org['address']) : '—' ?>
                    </div>
                    <div class="col-6">
                        <span class="org-detail-label">Audit Sessions</span><br>
                        <span class="badge audit-count-badge"><?= intval($org['audit_count']) ?></span>
                    </div>
                    <div class="col-6">
                        <span class="org-detail-label">Created</span><br>
                        <?= date('d M Y', strtotime($org['created_at'])) ?>
                    </div>
                </div>
            </div>
            <div class="card-footer bg-transparent border-top d-flex gap-2">
                <?php if ($org['is_active']): ?>
                    <button class="btn btn-sm btn-outline-danger flex-fill toggleStatusBtn" 
                            data-org-id="<?= intval($org['id']) ?>" data-action="deactivate">
                        <i class="fas fa-ban me-1"></i>Deactivate
                    </button>
                <?php else: ?>
                    <button class="btn btn-sm btn-outline-success flex-fill toggleStatusBtn" 
                            data-org-id="<?= intval($org['id']) ?>" data-action="activate">
                        <i class="fas fa-check-circle me-1"></i>Activate
                    </button>
                <?php endif; ?>
            </div>
        </div>
    </div>
    <?php endforeach; ?>
</div>
<?php else: ?>
    <div class="alert alert-info"><i class="fas fa-info-circle me-2"></i>No organizations have been created yet.</div>
<?php endif; ?>

<script>
document.querySelectorAll('.toggleStatusBtn').forEach(btn => {
    btn.addEventListener('click', function() {
        const orgId = this.dataset.orgId;
        const action = this.dataset.action;
        const label = action === 'activate' ? 'activate' : 'deactivate';
        if (!confirm('Are you sure you want to ' + label + ' this organization?')) return;

        fetch('api/organization_actions.php?action=toggle_status', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: orgId, activate: action === 'activate' })
        })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                location.reload();
            } else {
                document.getElementById('alertBox').innerHTML = '<div class="alert alert-danger">' + data.message + '</div>';
            }
        })
        .catch(() => {
            document.getElementById('alertBox').innerHTML = '<div class="alert alert-danger">Server error</div>';
        });
    });
});
</script>

<?php else: ?>
<!-- ============ AUDITOR VIEW: Create + Manage Own Orgs ============ -->

<div class="card mb-4 shadow-sm">
    <div class="card-body">
        <h5>Create Organization</h5>

        <div id="alertBox"></div>

        <form id="orgForm">
            <?= csrfTokenInput(); ?>
            <div class="row mb-2">
                <div class="col-md-6">
                    <input name="organization_name" class="form-control" placeholder="Organization Name" required>
                </div>
                <div class="col-md-3">
                    <select name="industry" class="form-select" required>
                        <option value="">Select Industry</option>
                        <option>Finance</option>
                        <option>Healthcare</option>
                        <option>Education</option>
                        <option>Retail</option>
                        <option>Technology</option>
                        <option>Government</option>
                        <option>Manufacturing</option>
                        <option>Other</option>
                    </select>
                </div>
                <div class="col-md-3">
                    <input name="number_of_employees" type="number" class="form-control" placeholder="No. of Employees" min="1">
                </div>
            </div>
            <div class="row mb-2">
                <div class="col-md-6">
                    <select name="system_type" class="form-select">
                        <option value="">Select System Type</option>
                        <option value="Web Application">Web Application</option>
                        <option value="Mobile Application">Mobile Application</option>
                        <option value="Internal Network">Internal Network</option>
                        <option value="Cloud Infrastructure">Cloud Infrastructure</option>
                        <option value="Hybrid">Hybrid</option>
                    </select>
                </div>
                <div class="col-md-4">
                    <input name="contact_person" class="form-control" placeholder="Contact Person (optional)">
                </div>
                <div class="col-md-2">
                    <button type="submit" class="btn btn-primary w-100">Create</button>
                </div>
            </div>
        </form>
    </div>
</div>

<div class="table-responsive">
<table class="table table-bordered table-hover">
    <thead class="table-dark">
        <tr>
            <th>Name</th>
            <th>Industry</th>
            <th>System Type</th>
            <th>Employees</th>
            <th>Contact Person</th>
            <th>Contact Email</th>
            <th>Contact Phone</th>
            <th>Address</th>
            <th>Audits</th>
            <th>Action</th>
        </tr>
    </thead>
    <tbody>
        <?php if (count($organizations) > 0): ?>
            <?php foreach ($organizations as $org): ?>
                <tr>
                    <td><a href="audit_sessions.php?org_id=<?= intval($org['id']) ?>" class="text-decoration-none fw-semibold"><?= htmlspecialchars($org['organization_name']) ?></a></td>
                    <td><?= htmlspecialchars($org['industry']) ?></td>
                    <td><?= !empty($org['system_type']) ? htmlspecialchars($org['system_type']) : '<span class="text-muted">—</span>' ?></td>
                    <td><?= !empty($org['number_of_employees']) ? number_format(intval($org['number_of_employees'])) : '<span class="text-muted">—</span>' ?></td>
                    <td><?= !empty($org['contact_person']) ? htmlspecialchars($org['contact_person']) : '<span class="text-muted">—</span>' ?></td>
                    <td><?= !empty($org['contact_email']) ? htmlspecialchars($org['contact_email']) : '<span class="text-muted">—</span>' ?></td>
                    <td><?= !empty($org['contact_phone']) ? htmlspecialchars($org['contact_phone']) : '<span class="text-muted">—</span>' ?></td>
                    <td><?= !empty($org['address']) ? htmlspecialchars($org['address']) : '<span class="text-muted">—</span>' ?></td>
                    <td><span class="badge audit-count-badge"><?= intval($org['audit_count']) ?></span></td>
                    <td>
                        <button class="btn btn-sm btn-outline-secondary editOrgBtn" 
                                data-id="<?= intval($org['id']) ?>"
                                data-name="<?= htmlspecialchars($org['organization_name'], ENT_QUOTES) ?>"
                                data-industry="<?= htmlspecialchars($org['industry'], ENT_QUOTES) ?>"
                                data-employees="<?= intval($org['number_of_employees'] ?? 0) ?>"
                                data-system="<?= htmlspecialchars($org['system_type'] ?? '', ENT_QUOTES) ?>"
                                data-contact="<?= htmlspecialchars($org['contact_person'] ?? '', ENT_QUOTES) ?>"
                                data-email="<?= htmlspecialchars($org['contact_email'] ?? '', ENT_QUOTES) ?>"
                                data-phone="<?= htmlspecialchars($org['contact_phone'] ?? '', ENT_QUOTES) ?>"
                                data-address="<?= htmlspecialchars($org['address'] ?? '', ENT_QUOTES) ?>"
                                title="Edit Organization">
                            Edit
                        </button>
                        <a href="audit_sessions.php?org_id=<?= intval($org['id']) ?>" class="btn btn-sm btn-dark">
                            Audit Sessions
                        </a>
                    </td>
                </tr>
            <?php endforeach; ?>
        <?php else: ?>
            <tr>
                <td colspan="10" class="text-center text-muted">
                    No organizations yet.
                </td>
            </tr>
        <?php endif; ?>
    </tbody>
</table>
</div>

<script>
document.getElementById('orgForm').addEventListener('submit', function(e){
    e.preventDefault();

    const formData = new FormData(this);

    fetch('api/organization_actions.php?action=add', {
        method: 'POST',
        body: formData
    })
    .then(res => res.json())
    .then(data => {
        if(data.success){
            showAlert('success', data.message);
            setTimeout(() => location.reload(), 800);
        } else {
            showAlert('danger', data.message);
        }
    })
    .catch(() => showAlert('danger', 'Server error'));
});

function showAlert(type, message){
    document.getElementById('alertBox').innerHTML =
        `<div class="alert alert-${type}">${message}</div>`;
}
</script>

<!-- Edit Organization Modal -->
<div class="modal fade" id="editOrgModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title"><i class="fas fa-pen me-2"></i>Edit Organization</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <form id="editOrgForm">
                <div class="modal-body">
                    <div id="editOrgAlert"></div>
                    <input type="hidden" id="editOrgId" name="id">
                    <div class="mb-3">
                        <label class="form-label">Organization Name</label>
                        <input type="text" id="editOrgName" name="organization_name" class="form-control" required>
                    </div>
                    <div class="row mb-3">
                        <div class="col-md-6">
                            <label class="form-label">Industry</label>
                            <select id="editOrgIndustry" name="industry" class="form-select" required>
                                <option value="">Select Industry</option>
                                <option>Finance</option>
                                <option>Healthcare</option>
                                <option>Education</option>
                                <option>Retail</option>
                                <option>Technology</option>
                                <option>Government</option>
                                <option>Manufacturing</option>
                                <option>Other</option>
                            </select>
                        </div>
                        <div class="col-md-6">
                            <label class="form-label">System Type</label>
                            <select id="editOrgSystem" name="system_type" class="form-select">
                                <option value="">Select System Type</option>
                                <option value="Web Application">Web Application</option>
                                <option value="Mobile Application">Mobile Application</option>
                                <option value="Internal Network">Internal Network</option>
                                <option value="Cloud Infrastructure">Cloud Infrastructure</option>
                                <option value="Hybrid">Hybrid</option>
                            </select>
                        </div>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">No. of Employees</label>
                        <input type="number" id="editOrgEmployees" name="number_of_employees" class="form-control" min="1">
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Contact Person</label>
                        <input type="text" id="editOrgContact" name="contact_person" class="form-control">
                    </div>
                    <div class="row mb-3">
                        <div class="col-md-6">
                            <label class="form-label">Contact Email</label>
                            <input type="email" id="editOrgEmail" name="contact_email" class="form-control" placeholder="email@example.com">
                        </div>
                        <div class="col-md-6">
                            <label class="form-label">Contact Phone</label>
                            <input type="text" id="editOrgPhone" name="contact_phone" class="form-control" placeholder="+62...">
                        </div>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Address</label>
                        <textarea id="editOrgAddress" name="address" class="form-control" rows="2"></textarea>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-primary">Save Changes</button>
                </div>
            </form>
        </div>
    </div>
</div>

<script>
// Edit Organization Modal
var editModal = null;
function getEditModal() {
    if (!editModal) editModal = new bootstrap.Modal(document.getElementById('editOrgModal'));
    return editModal;
}

document.querySelectorAll('.editOrgBtn').forEach(btn => {
    btn.addEventListener('click', function() {
        document.getElementById('editOrgId').value = this.dataset.id;
        document.getElementById('editOrgName').value = this.dataset.name;
        document.getElementById('editOrgIndustry').value = this.dataset.industry;
        document.getElementById('editOrgEmployees').value = this.dataset.employees > 0 ? this.dataset.employees : '';
        document.getElementById('editOrgSystem').value = this.dataset.system;
        document.getElementById('editOrgContact').value = this.dataset.contact;
        document.getElementById('editOrgEmail').value = this.dataset.email;
        document.getElementById('editOrgPhone').value = this.dataset.phone;
        document.getElementById('editOrgAddress').value = this.dataset.address;
        document.getElementById('editOrgAlert').innerHTML = '';
        getEditModal().show();
    });
});

document.getElementById('editOrgForm').addEventListener('submit', function(e) {
    e.preventDefault();
    const formData = new FormData(this);

    fetch('api/organization_actions.php?action=update', {
        method: 'POST',
        body: formData
    })
    .then(res => {
        const ct = res.headers.get('content-type');
        if (!ct || !ct.includes('application/json')) {
            return res.text().then(txt => { console.error('Non-JSON:', txt); throw new Error('Server returned non-JSON response'); });
        }
        return res.json();
    })
    .then(data => {
        if (data.success) {
            document.getElementById('editOrgAlert').innerHTML = '<div class="alert alert-success py-2">' + data.message + '</div>';
            setTimeout(() => window.location.href = 'organizations.php', 800);
        } else {
            document.getElementById('editOrgAlert').innerHTML = '<div class="alert alert-danger py-2">' + data.message + '</div>';
        }
    })
    .catch(err => {
        document.getElementById('editOrgAlert').innerHTML = '<div class="alert alert-danger py-2">' + err.message + '</div>';
    });
});
</script>

<?php endif; ?>

<?php 
// Include chatbot widget (only for logged-in users)
if (file_exists('includes/chatbot.html')) {
    readfile('includes/chatbot.html');
}
?>


<?php include 'includes/footer.php'; ?>