<?php
/**
 * SRM-Audit - Asset Management
 * Manage assets for selected audit session
 */
session_start();
require_once 'functions/db.php';
require_once 'functions/auth.php';

// Check authentication
requireLogin();

$userId = $_SESSION['user_id'];
$auditId = isset($_GET['audit_id']) ? intval($_GET['audit_id']) : 0;

// Verify audit belongs to user's organization
if ($auditId > 0) {
    $stmt = $pdo->prepare("SELECT a.*, o.organization_name 
                          FROM audit_sessions a 
                          JOIN organizations o ON a.organization_id = o.id 
                          WHERE a.id = ? AND o.user_id = ?");
    $stmt->execute([$auditId, $userId]);
    $audit = $stmt->fetch();
    
    if (!$audit) {
        header('Location: audit_sessions.php?error=invalid_audit');
        exit();
    }
} else {
    header('Location: audit_sessions.php?error=no_audit_selected');
    exit();
}

// Get assets for this audit
$stmt = $pdo->prepare("SELECT * FROM assets WHERE audit_id = ? ORDER BY criticality_score DESC, created_at DESC");
$stmt->execute([$auditId]);
$assets = $stmt->fetchAll();

// Calculate average criticality
$avgCriticality = 0;
if (count($assets) > 0) {
    $totalCriticality = array_sum(array_column($assets, 'criticality_score'));
    $avgCriticality = $totalCriticality / count($assets);
}

include 'includes/header.php';
?>

<div class="container-fluid">
    <div class="row">
        <?php include 'includes/sidebar.php'; ?>
        
        <main class="col-md-9 ms-sm-auto col-lg-10 px-md-4">
            <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                <div>
                    <h1 class="h2"><i class="fas fa-server"></i> Asset Management</h1>
                    <p class="text-muted">
                        <i class="fas fa-building"></i> <?php echo htmlspecialchars($audit['organization_name']); ?> 
                        | <i class="fas fa-calendar"></i> <?php echo htmlspecialchars($audit['session_name'] ?? 'Audit Session'); ?>
                    </p>
                </div>
                <div class="btn-toolbar mb-2 mb-md-0">
                    <button type="button" class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addAssetModal">
                        <i class="fas fa-plus"></i> Add Asset
                    </button>
                    <a href="audit_sessions.php" class="btn btn-outline-secondary ms-2">
                        <i class="fas fa-arrow-left"></i> Back
                    </a>
                </div>
            </div>

            <!-- Statistics Cards -->
            <div class="row mb-4">
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-body">
                            <h6 class="text-muted">Total Assets</h6>
                            <h3><i class="fas fa-server text-primary"></i> <?php echo count($assets); ?></h3>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-body">
                            <h6 class="text-muted">Average Criticality</h6>
                            <h3>
                                <i class="fas fa-shield-alt text-warning"></i> 
                                <?php echo number_format($avgCriticality, 2); ?>/5
                            </h3>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-body">
                            <h6 class="text-muted">Critical Assets</h6>
                            <h3>
                                <i class="fas fa-exclamation-triangle text-danger"></i> 
                                <?php 
                                $criticalCount = count(array_filter($assets, function($a) { 
                                    return $a['criticality_level'] == 'Critical'; 
                                }));
                                echo $criticalCount;
                                ?>
                            </h3>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Assets Table -->
            <div class="card">
                <div class="card-header">
                    <h5 class="mb-0"><i class="fas fa-list"></i> Asset Inventory</h5>
                </div>
                <div class="card-body">
                    <?php if (count($assets) > 0): ?>
                        <div class="table-responsive">
                            <table class="table table-striped table-hover">
                                <thead>
                                    <tr>
                                        <th>Asset Name</th>
                                        <th>Type</th>
                                        <th>IP/URL</th>
                                        <th>C</th>
                                        <th>I</th>
                                        <th>A</th>
                                        <th>Criticality</th>
                                        <th>Level</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($assets as $asset): ?>
                                        <tr>
                                            <td>
                                                <strong><?php echo htmlspecialchars($asset['asset_name']); ?></strong>
                                                <?php if ($asset['description']): ?>
                                                    <br><small class="text-muted"><?php echo htmlspecialchars(substr($asset['description'], 0, 50)); ?></small>
                                                <?php endif; ?>
                                            </td>
                                            <td><?php echo htmlspecialchars($asset['asset_type']); ?></td>
                                            <td><code><?php echo htmlspecialchars($asset['ip_address']); ?></code></td>
                                            <td>
                                                <span class="badge bg-info"><?php echo $asset['confidentiality']; ?></span>
                                            </td>
                                            <td>
                                                <span class="badge bg-info"><?php echo $asset['integrity']; ?></span>
                                            </td>
                                            <td>
                                                <span class="badge bg-info"><?php echo $asset['availability']; ?></span>
                                            </td>
                                            <td><?php echo number_format($asset['criticality_score'], 2); ?></td>
                                            <td>
                                                <?php
                                                $levelClass = 'secondary';
                                                switch($asset['criticality_level']) {
                                                    case 'Critical': $levelClass = 'danger'; break;
                                                    case 'High': $levelClass = 'warning'; break;
                                                    case 'Medium': $levelClass = 'info'; break;
                                                    case 'Low': $levelClass = 'success'; break;
                                                }
                                                ?>
                                                <span class="badge bg-<?php echo $levelClass; ?>">
                                                    <?php echo htmlspecialchars($asset['criticality_level']); ?>
                                                </span>
                                            </td>
                                            <td>
                                                <button class="btn btn-sm btn-info" onclick="viewAsset(<?php echo $asset['id']; ?>)">
                                                    <i class="fas fa-eye"></i>
                                                </button>
                                                <button class="btn btn-sm btn-danger" onclick="deleteAsset(<?php echo $asset['id']; ?>)">
                                                    <i class="fas fa-trash"></i>
                                                </button>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    <?php else: ?>
                        <div class="alert alert-info">
                            <i class="fas fa-info-circle"></i> No assets registered yet. Click "Add Asset" to begin.
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </main>
    </div>
</div>

<!-- Add Asset Modal -->
<div class="modal fade" id="addAssetModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title"><i class="fas fa-plus"></i> Add New Asset</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <form id="addAssetForm">
                <div class="modal-body">
                    <input type="hidden" name="audit_id" value="<?php echo $auditId; ?>">
                    
                    <div class="row">
                        <div class="col-md-6 mb-3">
                            <label class="form-label">Asset Name *</label>
                            <input type="text" name="asset_name" class="form-control" required>
                        </div>
                        <div class="col-md-6 mb-3">
                            <label class="form-label">Asset Type *</label>
                            <select name="asset_type" class="form-select" required>
                                <option value="">Select Type</option>
                                <option value="Server">Server</option>
                                <option value="Workstation">Workstation</option>
                                <option value="Database">Database</option>
                                <option value="Web Application">Web Application</option>
                                <option value="Mobile Application">Mobile Application</option>
                                <option value="Network Device">Network Device</option>
                                <option value="IoT Device">IoT Device</option>
                                <option value="Cloud Service">Cloud Service</option>
                                <option value="Other">Other</option>
                            </select>
                        </div>
                    </div>

                    <div class="mb-3">
                        <label class="form-label">IP Address / URL</label>
                        <input type="text" name="ip_address" class="form-control" placeholder="e.g., 192.168.1.100 or https://example.com">
                    </div>

                    <div class="mb-3">
                        <label class="form-label">Description</label>
                        <textarea name="description" class="form-control" rows="2"></textarea>
                    </div>

                    <div class="row">
                        <div class="col-md-6 mb-3">
                            <label class="form-label">Owner / Responsible Person</label>
                            <input type="text" name="owner" class="form-control">
                        </div>
                        <div class="col-md-6 mb-3">
                            <label class="form-label">Department</label>
                            <input type="text" name="department" class="form-control">
                        </div>
                    </div>

                    <hr>
                    <h6 class="mb-3"><i class="fas fa-shield-alt"></i> CIA Triad Rating (1-5)</h6>
                    
                    <div class="row">
                        <div class="col-md-4 mb-3">
                            <label class="form-label">Confidentiality *</label>
                            <input type="number" name="confidentiality" class="form-control" min="1" max="5" required>
                            <small class="text-muted">1=Low, 5=Critical</small>
                        </div>
                        <div class="col-md-4 mb-3">
                            <label class="form-label">Integrity *</label>
                            <input type="number" name="integrity" class="form-control" min="1" max="5" required>
                            <small class="text-muted">1=Low, 5=Critical</small>
                        </div>
                        <div class="col-md-4 mb-3">
                            <label class="form-label">Availability *</label>
                            <input type="number" name="availability" class="form-control" min="1" max="5" required>
                            <small class="text-muted">1=Low, 5=Critical</small>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-save"></i> Add Asset
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>

<script>
// Handle form submission
document.getElementById('addAssetForm').addEventListener('submit', function(e) {
    e.preventDefault();
    
    const formData = new FormData(this);
    
    fetch('api/asset_actions.php?action=add', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            location.reload();
        } else {
            alert('Error: ' + data.message);
        }
    })
    .catch(error => {
        alert('Error: ' + error);
    });
});

function deleteAsset(id) {
    if (confirm('Are you sure you want to delete this asset?')) {
        fetch('api/asset_actions.php?action=delete', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({id: id})
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                location.reload();
            } else {
                alert('Error: ' + data.message);
            }
        });
    }
}

function viewAsset(id) {
    // Implement view functionality
    alert('View asset details (to be implemented)');
}
</script>

<?php include 'includes/footer.php'; ?>
