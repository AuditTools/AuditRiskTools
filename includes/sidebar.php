<?php
$currentPage = basename(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH));

$navClass = function ($pages) use ($currentPage) {
    $isActive = in_array($currentPage, $pages, true);
    return 'nav-link srm-nav-link text-white' . ($isActive ? ' active' : '');
};
?>

<style>
    .srm-nav-link {
        border-radius: 10px;
        margin-bottom: 4px;
        transition: all 0.2s ease;
    }

    .srm-nav-link:hover {
        background-color: rgba(255, 255, 255, 0.12);
        transform: translateX(4px);
    }

    .srm-nav-link.active {
        background-color: rgba(13, 110, 253, 0.95);
        font-weight: 600;
        box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.15);
    }
</style>

<div class="d-flex">
    <div class="bg-dark text-white p-3" style="width:250px; min-height:100vh;">
        <h4>SRM-Audit</h4>
        <hr>
        <ul class="nav flex-column">
            <li class="nav-item"><a href="dashboard.php" class="<?= $navClass(['dashboard.php']) ?>">Dashboard</a></li>
            <li class="nav-item"><a href="organizations.php" class="<?= $navClass(['organizations.php', 'audit_sessions.php']) ?>">Organizations</a></li>
            <?php if (!empty($_SESSION['active_audit_id'])): ?>
                <li class="nav-item"><a href="asset_manage.php?audit_id=<?= intval($_SESSION['active_audit_id']) ?>" class="<?= $navClass(['asset_manage.php']) ?>">Asset Management</a></li>
                <li class="nav-item"><a href="findings.php?audit_id=<?= intval($_SESSION['active_audit_id']) ?>" class="<?= $navClass(['findings.php']) ?>">Findings</a></li>
                <li class="nav-item"><a href="report.php?audit_id=<?= intval($_SESSION['active_audit_id']) ?>" class="<?= $navClass(['report.php']) ?>">Report</a></li>
            <?php endif; ?>
            <li class="nav-item"><a href="logout.php" class="<?= $navClass(['logout.php']) ?>">Logout</a></li>
        </ul>
    </div>

    <div class="p-4 w-100">