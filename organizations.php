<?php
/**
 * SRM-Audit - Organizations Management
 * Manage organizations under audit
 */
session_start();
require_once 'functions/db.php';
require_once 'functions/auth.php';

// Check authentication
requireLogin();

$userId = $_SESSION['user_id'];

// Get organizations for this user
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
        <form>
            <div class="row">
                <div class="col-md-6">
                    <input class="form-control" placeholder="Organization Name">
                </div>
                <div class="col-md-4">
                    <select class="form-select">
                        <option>Select Industry</option>
                        <option>Finance</option>
                        <option>Healthcare</option>
                        <option>Education</option>
                        <option>Retail</option>
                        <option>Technology</option>
                        <option>Other</option>
                    </select>
                </div>
                <div class="col-md-2">
                    <button class="btn btn-primary w-100">Create</button>
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
                    <td><?php echo htmlspecialchars($org['organization_name']); ?></td>
                    <td><?php echo htmlspecialchars($org['industry']); ?></td>
                    <td><span class="badge bg-info"><?php echo intval($org['audit_count']); ?></span></td>
                    <td>
                        <a href="audit_sessions.php?org_id=<?php echo intval($org['id']); ?>" class="btn btn-sm btn-dark">
                            <i class="fas fa-folder-open"></i> Open
                        </a>
                        <button onclick="editOrg(<?php echo intval($org['id']); ?>)" class="btn btn-sm btn-primary">
                            <i class="fas fa-edit"></i>
                        </button>
                        <button onclick="deleteOrg(<?php echo intval($org['id']); ?>)" class="btn btn-sm btn-danger">
                            <i class="fas fa-trash"></i>
                        </button>
                    </td>
                </tr>
            <?php endforeach; ?>
        <?php else: ?>
            <tr>
                <td colspan="4" class="text-center text-muted">
                    <i class="fas fa-info-circle"></i> No organizations yet. Create one to get started.
                </td>
            </tr>
        <?php endif; ?>
    </tbody>
</table>

<?php include 'includes/footer.php'; ?>