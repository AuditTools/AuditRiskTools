<?php include 'includes/header.php'; ?>
<?php include 'includes/sidebar.php'; ?>

<h2 class="mb-4">Findings & Risk Assessment</h2>

<div class="card shadow-sm mb-4">
    <div class="card-body">
        <h5>Add Finding</h5>

        <form method="POST">
            <div class="mb-3">
                <input type="text" class="form-control" name="title" placeholder="Vulnerability Title" required>
            </div>

            <div class="row mb-3">
                <div class="col-md-6">
                    <label>Likelihood (1–5)</label>
                    <input type="number" min="1" max="5" class="form-control" name="likelihood" required>
                </div>

                <div class="col-md-6">
                    <label>Impact (1–5)</label>
                    <input type="number" min="1" max="5" class="form-control" name="impact" required>
                </div>
            </div>

            <button class="btn btn-danger">Calculate Risk</button>
        </form>
    </div>
</div>

<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {

    $likelihood = (int) $_POST['likelihood'];
    $impact = (int) $_POST['impact'];

    $risk = $likelihood * $impact;

    // Better risk classification
    if ($risk <= 5) {
        $badge = "bg-success";
    } elseif ($risk <= 14) {
        $badge = "bg-warning";
    } elseif ($risk <= 24) {
        $badge = "bg-danger";
    } else {
        $badge = "bg-dark";
    }

    echo "
    <div class='alert alert-secondary mt-3'>
        <strong>Risk Score:</strong> 
        <span class='badge $badge'>$risk</span>
    </div>";
}
?>

<?php include 'includes/footer.php'; ?>