<?php
/**
 * SRM-Audit - Dashboard
 * Main dashboard with audit overview
 */
session_start();
require_once 'functions/db.php';
require_once 'functions/auth.php';

// Check authentication
requireLogin();

$userId = $_SESSION['user_id'];
$auditId = isset($_GET['audit_id']) ? intval($_GET['audit_id']) : 0;

// If audit_id provided, verify ownership and load data
$audit = null;
if ($auditId > 0) {
    $stmt = $pdo->prepare("SELECT a.*, o.organization_name, o.industry 
                          FROM audit_sessions a 
                          JOIN organizations o ON a.organization_id = o.id 
                          WHERE a.id = ? AND o.user_id = ?");
    $stmt->execute([$auditId, $userId]);
    $audit = $stmt->fetch();
    
    if (!$audit) {
        $auditId = 0; // Invalid audit
    }
}

include 'includes/header.php';
include 'includes/sidebar.php';
?>

<h2 class="mb-4">Audit Dashboard</h2>

<div class="row mb-4">

    <div class="col-md-3">
        <div class="card shadow-sm">
            <div class="card-body">
                <h6>Exposure Level</h6>
                <span class="badge bg-danger">High</span>
            </div>
        </div>
    </div>

    <div class="col-md-3">
        <div class="card shadow-sm">
            <div class="card-body">
                <h6>Avg Asset Criticality</h6>
                <h4>4.3</h4>
            </div>
        </div>
    </div>

    <div class="col-md-3">
        <div class="card shadow-sm">
            <div class="card-body">
                <h6>Final Risk Level</h6>
                <span class="badge bg-warning text-dark">Medium</span>
            </div>
        </div>
    </div>

    <div class="col-md-3">
        <div class="card shadow-sm">
            <div class="card-body">
                <h6>Compliance</h6>
                <div class="progress">
                    <div class="progress-bar bg-success" style="width:75%">
                        75%
                    </div>
                </div>
            </div>
        </div>
    </div>

</div>

<h4 class="mb-3">Top 5 Risks</h4>

<table class="table table-bordered">
    <thead class="table-dark">
        <tr>
            <th>Vulnerability</th>
            <th>Risk Score</th>
            <th>NIST</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>SQL Injection</td>
            <td><span class="badge bg-danger">25</span></td>
            <td>Protect</td>
        </tr>
        <tr>
            <td>Weak Password Policy</td>
            <td><span class="badge bg-warning">15</span></td>
            <td>Identify</td>
        </tr>
    </tbody>
</table>

<button class="btn btn-primary" onclick="generateReport()">Generate AI Report</button>

<div id="loading" style="display:none;" class="mt-3">
    <div class="spinner-border text-primary"></div>
    Generating report...
</div>

<script>
function generateReport() {
    document.getElementById("loading").style.display = "block";
}
</script>

<?php include 'includes/footer.php'; ?>