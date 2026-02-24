<?php
session_start();
require_once 'functions/db.php';
require_once 'functions/auth.php';

requireLogin();

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

    <div class="card shadow-sm">
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
</div>

<script>
document.getElementById('auditForm').addEventListener('submit', function(e) {
    e.preventDefault();

    const formData = new FormData(this);

    fetch('api/audit_actions.php?action=create', {
        method: 'POST',
        body: formData
    })
    .then(res => res.json())
    .then(data => {
        if (data.success) {
            window.location.href = "dashboard.php?audit_id=" + data.audit_id;
        } else {
            alert(data.message);
        }
    })
    .catch(err => {
        console.error(err);
        alert("Error creating audit session");
    });
});
</script>

<?php include 'includes/footer.php'; ?>