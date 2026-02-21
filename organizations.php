<?php include 'includes/header.php'; ?>
<?php include 'includes/sidebar.php'; ?>

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
            <th>Action</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>PT Example</td>
            <td>Finance</td>
            <td>
                <a href="audit_sessions.php" class="btn btn-sm btn-dark">Open</a>
            </td>
        </tr>
    </tbody>
</table>

<?php include 'includes/footer.php'; ?>