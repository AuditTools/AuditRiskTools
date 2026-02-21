<?php include 'includes/header.php'; ?>
<?php include 'includes/sidebar.php'; ?>

<h2 class="mb-4">Audit Sessions</h2>

<div class="card mb-4 shadow-sm">
    <div class="card-body">
        <h5>Create Audit Session</h5>
        <form>
            <div class="row">
                <div class="col-md-4">
                    <select class="form-select">
                        <option>Digital Scale</option>
                        <option>Low</option>
                        <option>Medium</option>
                        <option>High</option>
                    </select>
                </div>

                <div class="col-md-4">
                    <input type="date" class="form-control">
                </div>

                <div class="col-md-4">
                    <button class="btn btn-primary w-100">Create Audit</button>
                </div>
            </div>
        </form>
    </div>
</div>

<table class="table table-bordered">
    <thead class="table-dark">
        <tr>
            <th>Audit Date</th>
            <th>Exposure</th>
            <th>Final Risk</th>
            <th>Action</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>2026-02-20</td>
            <td><span class="badge bg-warning">Medium</span></td>
            <td><span class="badge bg-danger">High</span></td>
            <td>
                <a href="dashboard.php?audit_id=1" class="btn btn-sm btn-dark">View</a>
            </td>
        </tr>
    </tbody>
</table>

<?php include 'includes/footer.php'; ?>