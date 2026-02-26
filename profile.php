<?php
session_start();
require_once 'functions/db.php';
require_once 'functions/auth.php';
requireLogin();

$userId   = $_SESSION['user_id'];
$userRole = $_SESSION['user_role'] ?? 'auditor';

// Fetch fresh user data from DB
$stmt = $pdo->prepare("SELECT id, name, email, role, is_active, created_at, last_login FROM users WHERE id = ?");
$stmt->execute([$userId]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$user) {
    session_destroy();
    header('Location: login.php');
    exit;
}

$roleColors = ['admin' => '#e76f7a', 'auditor' => '#5f95ff', 'auditee' => '#67b389'];
$roleColor  = $roleColors[$user['role']] ?? '#7f8ea8';
$roleLabel  = ['admin' => 'Administrator', 'auditor' => 'Auditor', 'auditee' => 'Auditee'];
$roleDesc   = [
    'admin'   => 'Full access: manage users, all organizations, and audit sessions.',
    'auditor' => 'Create and manage organizations, audit sessions, assets, findings, and reports.',
    'auditee' => 'View and contribute to audits you are assigned to. Can register assets and respond to findings.',
];

include 'includes/header.php';
include 'includes/sidebar.php';
?>

<div class="container mt-4" style="max-width:680px;">
    <h2 class="mb-4">My Profile</h2>

    <!-- Profile Card -->
    <div class="card shadow-sm mb-4">
        <div class="card-body d-flex align-items-center gap-4 py-4">
            <!-- Avatar -->
            <div style="width:72px;height:72px;border-radius:50%;background:<?= $roleColor ?>;flex-shrink:0;
                        display:flex;align-items:center;justify-content:center;
                        font-size:2rem;font-weight:700;color:#fff;
                        box-shadow:0 4px 16px <?= $roleColor ?>55;">
                <?= strtoupper(mb_substr($user['name'], 0, 1)) ?>
            </div>
            <div>
                <h4 class="mb-1 fw-bold"><?= htmlspecialchars($user['name']) ?></h4>
                <div class="mb-1 text-muted"><?= htmlspecialchars($user['email']) ?></div>
                <span class="badge rounded-pill px-3 py-1 fw-semibold"
                      style="background:<?= $roleColor ?>22;color:<?= $roleColor ?>;border:1px solid <?= $roleColor ?>55;font-size:0.8rem;">
                    <?= htmlspecialchars($roleLabel[$user['role']] ?? ucfirst($user['role'])) ?>
                </span>
            </div>
        </div>
    </div>

    <!-- Role Info Card -->
    <div class="card shadow-sm mb-4" style="border-left:4px solid <?= $roleColor ?>;">
        <div class="card-body">
            <h6 class="fw-semibold mb-1" style="color:<?= $roleColor ?>;">
                <i class="fas fa-shield-halved me-2"></i>Role: <?= htmlspecialchars($roleLabel[$user['role']] ?? ucfirst($user['role'])) ?>
            </h6>
            <p class="mb-0 text-muted" style="font-size:0.9rem;"><?= $roleDesc[$user['role']] ?? '' ?></p>
        </div>
    </div>

    <!-- Account Details -->
    <div class="card shadow-sm mb-4">
        <div class="card-header bg-light fw-semibold">Account Details</div>
        <div class="card-body">
            <table class="table table-borderless mb-0" style="font-size:0.9rem;">
                <tr>
                    <td class="text-muted" style="width:160px;">Full Name</td>
                    <td><?= htmlspecialchars($user['name']) ?></td>
                </tr>
                <tr>
                    <td class="text-muted">Email</td>
                    <td><?= htmlspecialchars($user['email']) ?></td>
                </tr>
                <tr>
                    <td class="text-muted">Role</td>
                    <td><?= htmlspecialchars($roleLabel[$user['role']] ?? ucfirst($user['role'])) ?></td>
                </tr>
                <tr>
                    <td class="text-muted">Account Status</td>
                    <td>
                        <?php if ($user['is_active']): ?>
                            <span class="badge bg-success">Active</span>
                        <?php else: ?>
                            <span class="badge bg-secondary">Inactive</span>
                        <?php endif; ?>
                    </td>
                </tr>
                <tr>
                    <td class="text-muted">Member Since</td>
                    <td><?= $user['created_at'] ? date('d M Y', strtotime($user['created_at'])) : '-' ?></td>
                </tr>
                <tr>
                    <td class="text-muted">Last Login</td>
                    <td><?= $user['last_login'] ? date('d M Y, H:i', strtotime($user['last_login'])) : 'N/A' ?></td>
                </tr>
            </table>
        </div>
    </div>

    <!-- Change Password -->
    <div class="card shadow-sm mb-4">
        <div class="card-header bg-light fw-semibold">Change Password</div>
        <div class="card-body">
            <div id="pwAlert"></div>
            <form id="changePasswordForm">
                <?= csrfTokenInput() ?>
                <div class="mb-3">
                    <label class="form-label">Current Password</label>
                    <input type="password" name="current_password" id="currentPw" class="form-control" required autocomplete="current-password">
                </div>
                <div class="mb-3">
                    <label class="form-label">New Password</label>
                    <input type="password" name="new_password" id="newPw" class="form-control" required autocomplete="new-password" minlength="8">
                    <div class="form-text">Minimum 8 characters.</div>
                </div>
                <div class="mb-3">
                    <label class="form-label">Confirm New Password</label>
                    <input type="password" name="confirm_password" id="confirmPw" class="form-control" required autocomplete="new-password">
                </div>
                <button type="submit" class="btn btn-primary">
                    <i class="fas fa-key me-2"></i>Update Password
                </button>
            </form>
        </div>
    </div>

    <div class="mb-5">
        <a href="logout.php" class="btn btn-outline-danger">
            <i class="fas fa-right-from-bracket me-2"></i>Logout
        </a>
    </div>
</div>

<script>
document.getElementById('changePasswordForm').addEventListener('submit', function(e) {
    e.preventDefault();
    const alertBox = document.getElementById('pwAlert');
    const newPw    = document.getElementById('newPw').value;
    const confirmPw = document.getElementById('confirmPw').value;

    if (newPw !== confirmPw) {
        alertBox.innerHTML = '<div class="alert alert-warning">New passwords do not match.</div>';
        return;
    }

    const fd = new FormData(this);
    fetch('api/auth_actions.php?action=change_password', { method: 'POST', body: fd })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                alertBox.innerHTML = '<div class="alert alert-success"><i class="fas fa-check-circle me-2"></i>' + data.message + '</div>';
                this.reset();
            } else {
                alertBox.innerHTML = '<div class="alert alert-danger">' + (data.message || 'Error updating password.') + '</div>';
            }
        })
        .catch(() => {
            alertBox.innerHTML = '<div class="alert alert-danger">Network error. Please try again.</div>';
        });
});
</script>

<?php include 'includes/footer.php'; ?>
