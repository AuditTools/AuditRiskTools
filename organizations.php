<?php
session_start();
require_once 'functions/db.php';
require_once 'functions/auth.php';
requireLogin();

$userId = $_SESSION['user_id'];

$stmt = $pdo->prepare("SELECT o.*, 
                      (SELECT COUNT(*) FROM audit_sessions WHERE organization_id = o.id) as audit_count
                      FROM organizations o 
                      WHERE o.user_id = ? AND o.is_active = 1
                      ORDER BY o.created_at DESC");
$stmt->execute([$userId]);
$organizations = $stmt->fetchAll();

include 'includes/header.php';
include 'includes/sidebar.php';
?>

<h2 class="mb-4">Organizations</h2>

<div class="card mb-4 shadow-sm">
    <div class="card-body">
        <h5>Create Organization</h5>

        <div id="alertBox"></div>

        <form id="orgForm">
            <?= csrfTokenInput(); ?>
            <div class="row">
                <div class="col-md-6">
                    <input name="organization_name" class="form-control" placeholder="Organization Name" required>
                </div>
                <div class="col-md-4">
                    <select name="industry" class="form-select" required>
                        <option value="">Select Industry</option>
                        <option>Finance</option>
                        <option>Healthcare</option>
                        <option>Education</option>
                        <option>Retail</option>
                        <option>Technology</option>
                        <option>Other</option>
                    </select>
                </div>
                <div class="col-md-2">
                    <button type="submit" class="btn btn-primary w-100">Create</button>
                </div>
            </div>
        </form>
    </div>
</div>

<table class="table table-bordered">
    <thead class="table-dark">
        <tr>
            <th>Name</th>
            <th>Industry</th>
            <th>Audits</th>
            <th>Action</th>
        </tr>
    </thead>
    <tbody>
        <?php if (count($organizations) > 0): ?>
            <?php foreach ($organizations as $org): ?>
                <tr>
                    <td><?= htmlspecialchars($org['organization_name']) ?></td>
                    <td><?= htmlspecialchars($org['industry']) ?></td>
                    <td><span class="badge bg-info"><?= intval($org['audit_count']) ?></span></td>
                    <td>
                        <a href="audit_sessions.php?org_id=<?= intval($org['id']) ?>" class="btn btn-sm btn-dark">
                            Open
                        </a>
                    </td>
                </tr>
            <?php endforeach; ?>
        <?php else: ?>
            <tr>
                <td colspan="4" class="text-center text-muted">
                    No organizations yet.
                </td>
            </tr>
        <?php endif; ?>
    </tbody>
</table>

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

<?php include 'includes/footer.php'; ?>