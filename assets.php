<?php include 'includes/header.php'; ?>
<?php include 'includes/sidebar.php'; ?>

<h2 class="mb-4">Asset Management</h2>

<div class="card shadow-sm mb-4">
    <div class="card-body">
        <h5>Add Asset</h5>

        <form method="POST">
            <div class="row mb-3">
                <div class="col-md-4">
                    <input type="text" class="form-control" name="asset_name" placeholder="Asset Name" required>
                </div>
                <div class="col-md-4">
                    <input type="text" class="form-control" name="ip_address" placeholder="IP Address / URL">
                </div>
                <div class="col-md-4">
                    <input type="text" class="form-control" name="asset_type" placeholder="Asset Type">
                </div>
            </div>

            <div class="row mb-3">
                <div class="col-md-4">
                    <label>Confidentiality (1–5)</label>
                    <input type="number" min="1" max="5" class="form-control" name="confidentiality" required>
                </div>
                <div class="col-md-4">
                    <label>Integrity (1–5)</label>
                    <input type="number" min="1" max="5" class="form-control" name="integrity" required>
                </div>
                <div class="col-md-4">
                    <label>Availability (1–5)</label>
                    <input type="number" min="1" max="5" class="form-control" name="availability" required>
                </div>
            </div>

            <button class="btn btn-primary">Calculate Criticality</button>
        </form>
    </div>
</div>

<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {

    $c = (int) $_POST['confidentiality'];
    $i = (int) $_POST['integrity'];
    $a = (int) $_POST['availability'];

    $criticality = ($c + $i + $a) / 3;

    echo "
    <div class='alert alert-info mt-3'>
        <strong>Calculated Asset Criticality:</strong> 
        " . round($criticality, 2) . "
    </div>";
}
?>

<?php include 'includes/footer.php'; ?>