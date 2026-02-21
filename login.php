<?php include 'includes/header.php'; ?>

<div class="container d-flex justify-content-center align-items-center" style="height:100vh;">
    <div class="card shadow-sm" style="width:400px;">
        <div class="card-body">
            <h4 class="text-center mb-4">SRM-Audit Login</h4>

            <form>
                <div class="mb-3">
                    <label>Email</label>
                    <input type="email" class="form-control" placeholder="Enter email">
                </div>

                <div class="mb-3">
                    <label>Password</label>
                    <input type="password" class="form-control" placeholder="Enter password">
                </div>

                <a href="organizations.php" class="btn btn-dark w-100">Login</a>
            </form>
        </div>
    </div>
</div>

<?php include 'includes/footer.php'; ?>