<?php
/**
 * SRM-Audit - User Management (Admin Only)
 * View all users, change roles, activate/deactivate accounts.
 */
session_start();
require_once 'functions/db.php';
require_once 'functions/auth.php';

requireLogin();

// Only admin can access this page
$userRole = $_SESSION['user_role'] ?? 'auditor';
if ($userRole !== 'admin') {
    header('Location: dashboard.php');
    exit();
}

$userId = $_SESSION['user_id'];
$message = '';
$messageType = '';

// Handle POST actions (role change, activate/deactivate, create user)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && verifyCSRFToken($_POST['csrf_token'] ?? '')) {
    $postAction = $_POST['post_action'] ?? '';

    try {
        switch ($postAction) {
            case 'change_role':
                $targetId = intval($_POST['target_id'] ?? 0);
                $newRole = $_POST['new_role'] ?? '';
                if (!in_array($newRole, ['admin', 'auditor', 'auditee'], true)) {
                    throw new Exception('Invalid role');
                }
                if ($targetId === $userId) {
                    throw new Exception('Cannot change your own role');
                }
                $stmt = $pdo->prepare("UPDATE users SET role = ? WHERE id = ?");
                $stmt->execute([$newRole, $targetId]);
                $message = "User #$targetId role changed to $newRole";
                $messageType = 'success';
                break;

            case 'toggle_active':
                $targetId = intval($_POST['target_id'] ?? 0);
                if ($targetId === $userId) {
                    throw new Exception('Cannot deactivate your own account');
                }
                $stmt = $pdo->prepare("UPDATE users SET is_active = IF(is_active=1, 0, 1) WHERE id = ?");
                $stmt->execute([$targetId]);
                $message = "User #$targetId status toggled";
                $messageType = 'success';
                break;

            case 'create_user':
                $name = trim($_POST['new_name'] ?? '');
                $email = filter_var(trim($_POST['new_email'] ?? ''), FILTER_VALIDATE_EMAIL);
                $password = $_POST['new_password'] ?? '';
                $role = $_POST['new_role_create'] ?? 'auditor';

                if (!$name || !$email || strlen($password) < 8) {
                    throw new Exception('Name, valid email, and password (min 8 chars) required');
                }
                if (!in_array($role, ['admin', 'auditor', 'auditee'], true)) {
                    $role = 'auditor';
                }
                // Check duplicate
                $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
                $stmt->execute([$email]);
                if ($stmt->fetch()) {
                    throw new Exception('Email already exists');
                }
                $hash = password_hash($password, PASSWORD_DEFAULT);
                $stmt = $pdo->prepare("INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)");
                $stmt->execute([$name, $email, $hash, $role]);
                $message = "User '$name' ($role) created successfully";
                $messageType = 'success';
                break;

            case 'reset_password':
                $targetId = intval($_POST['target_id'] ?? 0);
                $newPw = $_POST['reset_password'] ?? '';
                if (strlen($newPw) < 8) {
                    throw new Exception('Password must be at least 8 characters');
                }
                $hash = password_hash($newPw, PASSWORD_DEFAULT);
                $stmt = $pdo->prepare("UPDATE users SET password_hash = ?, failed_login_attempts = 0 WHERE id = ?");
                $stmt->execute([$hash, $targetId]);
                $message = "Password reset for user #$targetId";
                $messageType = 'success';
                break;
        }
    } catch (Exception $e) {
        $message = $e->getMessage();
        $messageType = 'danger';
    }
}

// Fetch all users
$stmtUsers = $pdo->query("SELECT id, name, email, role, is_active, failed_login_attempts, last_login, created_at FROM users ORDER BY id ASC");
$users = $stmtUsers->fetchAll(PDO::FETCH_ASSOC);

include 'includes/header.php';
include 'includes/sidebar.php';
?>

<div class="container mt-4">
    <h2 class="mb-4"><i class="fas fa-users-cog"></i> User Management</h2>

    <?php if ($message): ?>
        <div class="alert alert-<?= $messageType ?> alert-dismissible fade show">
            <?= htmlspecialchars($message) ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    <?php endif; ?>

    <!-- Create New User -->
    <div class="card shadow-sm mb-4">
        <div class="card-header bg-primary text-white">
            <h6 class="mb-0"><i class="fas fa-user-plus"></i> Create New User</h6>
        </div>
        <div class="card-body">
            <form method="POST" class="row g-2">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generateCSRFToken()) ?>">
                <input type="hidden" name="post_action" value="create_user">
                <div class="col-md-3">
                    <input type="text" name="new_name" class="form-control" placeholder="Full Name" required>
                </div>
                <div class="col-md-3">
                    <input type="email" name="new_email" class="form-control" placeholder="Email" required>
                </div>
                <div class="col-md-2">
                    <input type="password" name="new_password" class="form-control" placeholder="Password (min 8)" minlength="8" required>
                </div>
                <div class="col-md-2">
                    <select name="new_role_create" class="form-select">
                        <option value="auditor">Auditor</option>
                        <option value="auditee">Auditee</option>
                        <option value="admin">Admin</option>
                    </select>
                </div>
                <div class="col-md-2 d-grid">
                    <button type="submit" class="btn btn-success"><i class="fas fa-plus"></i> Create</button>
                </div>
            </form>
        </div>
    </div>

    <!-- User List -->
    <div class="card shadow-sm">
        <div class="card-header">
            <h6 class="mb-0">All Users (<?= count($users) ?>)</h6>
        </div>
        <div class="card-body p-0">
            <div class="table-responsive">
                <table class="table table-hover mb-0">
                    <thead class="table-dark">
                        <tr>
                            <th>ID</th>
                            <th>Name</th>
                            <th>Email</th>
                            <th>Role</th>
                            <th>Status</th>
                            <th>Last Login</th>
                            <th>Created</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($users as $u): ?>
                            <tr class="<?= !$u['is_active'] ? 'table-secondary' : '' ?>">
                                <td><?= $u['id'] ?></td>
                                <td>
                                    <?= htmlspecialchars($u['name']) ?>
                                    <?= $u['id'] === $userId ? '<span class="badge bg-info">You</span>' : '' ?>
                                </td>
                                <td><?= htmlspecialchars($u['email']) ?></td>
                                <td>
                                    <?php if ($u['id'] !== $userId): ?>
                                        <form method="POST" class="d-inline">
                                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generateCSRFToken()) ?>">
                                            <input type="hidden" name="post_action" value="change_role">
                                            <input type="hidden" name="target_id" value="<?= $u['id'] ?>">
                                            <select name="new_role" class="form-select form-select-sm d-inline-block" style="width:auto" onchange="this.form.submit()">
                                                <option value="admin" <?= $u['role'] === 'admin' ? 'selected' : '' ?>>Admin</option>
                                                <option value="auditor" <?= $u['role'] === 'auditor' ? 'selected' : '' ?>>Auditor</option>
                                                <option value="auditee" <?= $u['role'] === 'auditee' ? 'selected' : '' ?>>Auditee</option>
                                            </select>
                                        </form>
                                    <?php else: ?>
                                        <span class="badge bg-primary"><?= ucfirst($u['role']) ?></span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <?php if ($u['is_active']): ?>
                                        <span class="badge bg-success">Active</span>
                                    <?php else: ?>
                                        <span class="badge bg-secondary">Disabled</span>
                                    <?php endif; ?>
                                    <?php if ($u['failed_login_attempts'] >= 5): ?>
                                        <span class="badge bg-danger">Locked</span>
                                    <?php endif; ?>
                                </td>
                                <td><small><?= $u['last_login'] ? date('d M Y H:i', strtotime($u['last_login'])) : 'Never' ?></small></td>
                                <td><small><?= date('d M Y', strtotime($u['created_at'])) ?></small></td>
                                <td>
                                    <?php if ($u['id'] !== $userId): ?>
                                        <!-- Toggle Active -->
                                        <form method="POST" class="d-inline">
                                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generateCSRFToken()) ?>">
                                            <input type="hidden" name="post_action" value="toggle_active">
                                            <input type="hidden" name="target_id" value="<?= $u['id'] ?>">
                                            <button type="submit" class="btn btn-sm <?= $u['is_active'] ? 'btn-outline-warning' : 'btn-outline-success' ?>" 
                                                    title="<?= $u['is_active'] ? 'Deactivate' : 'Activate' ?>"
                                                    onclick="return confirm('<?= $u['is_active'] ? 'Deactivate' : 'Activate' ?> this user?')">
                                                <?= $u['is_active'] ? '<i class="fas fa-ban"></i>' : '<i class="fas fa-check"></i>' ?>
                                            </button>
                                        </form>
                                        <!-- Reset Password -->
                                        <button class="btn btn-sm btn-outline-secondary" title="Reset Password"
                                                onclick="resetPassword(<?= $u['id'] ?>, '<?= htmlspecialchars($u['name'], ENT_QUOTES) ?>')">
                                            <i class="fas fa-key"></i>
                                        </button>
                                    <?php else: ?>
                                        <span class="text-muted">—</span>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<!-- Reset Password Modal -->
<div class="modal fade" id="resetPwModal" tabindex="-1">
    <div class="modal-dialog">
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generateCSRFToken()) ?>">
            <input type="hidden" name="post_action" value="reset_password">
            <input type="hidden" name="target_id" id="resetTargetId">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Reset Password for <span id="resetUserName"></span></h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <label class="form-label">New Password</label>
                    <input type="password" name="reset_password" class="form-control" minlength="8" placeholder="Min 8 characters" required>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-primary">Reset Password</button>
                </div>
            </div>
        </form>
    </div>
</div>

<script>
function resetPassword(userId, userName) {
    document.getElementById('resetTargetId').value = userId;
    document.getElementById('resetUserName').textContent = userName;
    new bootstrap.Modal(document.getElementById('resetPwModal')).show();
}
</script>

<?php include 'includes/footer.php'; ?>
