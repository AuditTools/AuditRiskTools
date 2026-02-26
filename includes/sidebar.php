<?php
$currentPage = basename(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH));

$navClass = function ($pages) use ($currentPage) {
    $isActive = in_array($currentPage, $pages, true);
    return 'nav-link srm-nav-link text-white' . ($isActive ? ' active' : '');
};
?>

<style>
    .srm-layout {
        display: flex;
        min-height: 100vh;
        position: relative;
    }

    .srm-sidebar {
        width: 250px;
        min-height: 100vh;
        transition: width 0.2s ease, transform 0.25s ease;
        position: relative;
        z-index: 1040;
    }

    .srm-content {
        flex: 1;
        min-width: 0;
    }

    .srm-sidebar-head {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 8px;
    }

    .srm-sidebar-toggle {
        width: 34px;
        height: 34px;
        border: 1px solid rgba(255, 255, 255, 0.3);
        border-radius: 8px;
        background: rgba(255, 255, 255, 0.08);
        color: #fff;
        font-size: 15px;
        line-height: 1;
        display: flex;
        align-items: center;
        justify-content: center;
        transition: background-color 0.2s ease, transform 0.2s ease;
    }

    .srm-sidebar-toggle:hover {
        background: rgba(255, 255, 255, 0.16);
        transform: translateY(-1px);
    }

    .srm-mobile-toggle {
        display: none;
        position: fixed;
        top: 14px;
        left: 14px;
        width: 40px;
        height: 40px;
        border: 1px solid rgba(255, 255, 255, 0.3);
        border-radius: 10px;
        background: #2b3035;
        color: #fff;
        font-size: 18px;
        line-height: 1;
        align-items: center;
        justify-content: center;
        z-index: 1051;
    }

    .srm-sidebar-backdrop {
        display: none;
        position: fixed;
        inset: 0;
        background: rgba(0, 0, 0, 0.45);
        z-index: 1039;
    }

    .srm-nav-list .nav-item {
        display: block;
        transition: opacity 0.18s ease;
    }

    .srm-layout.compact .srm-nav-list .nav-item {
        display: none;
    }

    .srm-layout.compact .srm-nav-list .nav-item.is-active-item {
        display: block;
    }

    .srm-layout.compact .srm-sidebar {
        width: 84px;
    }

    .srm-layout.compact .srm-sidebar-head h4 {
        display: none;
    }

    .srm-layout.compact .srm-sidebar-head {
        justify-content: center;
    }

    .srm-layout.compact .srm-sidebar-toggle {
        margin: 0;
    }

    .srm-nav-text {
        vertical-align: middle;
    }

    .srm-nav-link {
        border-radius: 10px;
        margin-bottom: 4px;
        transition: all 0.2s ease;
    }

    .srm-nav-link:hover {
        background-color: rgba(255, 255, 255, 0.16);
        transform: translateX(4px);
        color: #ffffff !important;
    }

    .srm-nav-link.active {
        background: linear-gradient(135deg, rgba(108, 117, 125, 0.72), rgba(73, 80, 87, 0.92));
        color: #ffffff !important;
        font-weight: 600;
        text-shadow: 0 1px 1px rgba(0, 0, 0, 0.35);
        box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.2), 0 2px 8px rgba(0, 0, 0, 0.18);
    }

    .srm-layout.compact .srm-nav-link {
        position: relative;
        text-align: center;
        padding: 10px 8px;
    }

    .srm-layout.compact .srm-nav-link .srm-nav-text {
        display: none;
    }

    .srm-layout.compact .srm-nav-link::before {
        content: attr(data-short);
        display: inline-flex;
        width: 28px;
        height: 28px;
        border-radius: 999px;
        align-items: center;
        justify-content: center;
        background: rgba(255, 255, 255, 0.18);
        font-size: 12px;
        font-weight: 700;
        letter-spacing: 0.3px;
    }

    @media (max-width: 991.98px) {
        .srm-sidebar {
            position: fixed;
            top: 0;
            left: 0;
            transform: translateX(-100%);
            width: 250px;
        }

        .srm-layout.mobile-open .srm-sidebar {
            transform: translateX(0);
        }

        .srm-content {
            width: 100%;
        }

        .srm-mobile-toggle {
            display: inline-flex;
        }

        .srm-layout.mobile-open .srm-sidebar-backdrop {
            display: block;
        }
    }
</style>

<div id="srmLayout" class="srm-layout">
    <button id="srmMobileToggle" class="srm-mobile-toggle" type="button" aria-label="Open navigation" title="Open navigation">☰</button>
    <div id="srmSidebarBackdrop" class="srm-sidebar-backdrop"></div>
    <div id="srmSidebar" class="bg-dark text-white p-3 srm-sidebar">
        <div class="srm-sidebar-head">
            <h4 class="mb-0">SRM-Audit</h4>
            <button id="srmSidebarToggle" class="srm-sidebar-toggle" type="button" aria-label="Toggle navigation" title="Toggle navigation">☰</button>
        </div>
        <hr>
        <ul class="nav flex-column srm-nav-list">
            <li class="nav-item"><a href="dashboard.php" data-short="DB" class="<?= $navClass(['dashboard.php']) ?>"><span class="srm-nav-text">Dashboard</span></a></li>

            <?php $role = $_SESSION['user_role'] ?? 'auditor'; ?>

            <?php if ($role === 'admin'): ?>
                <!-- Admin: Management only -->
                <li class="nav-item"><a href="user_management.php" data-short="UM" class="<?= $navClass(['user_management.php']) ?>"><span class="srm-nav-text">User Management</span></a></li>
                <li class="nav-item"><a href="organizations.php" data-short="OR" class="<?= $navClass(['organizations.php', 'audit_sessions.php']) ?>"><span class="srm-nav-text">Organizations</span></a></li>
                <?php if (!empty($_SESSION['active_audit_id'])): ?>
                    <li class="nav-item"><a href="report.php?audit_id=<?= intval($_SESSION['active_audit_id']) ?>" data-short="RP" class="<?= $navClass(['report.php']) ?>"><span class="srm-nav-text">Report (View)</span></a></li>
                <?php endif; ?>
            <?php endif; ?>

            <?php if ($role === 'auditor'): ?>
                <!-- Auditor: Full audit workflow -->
                <li class="nav-item"><a href="organizations.php" data-short="OR" class="<?= $navClass(['organizations.php', 'audit_sessions.php']) ?>"><span class="srm-nav-text">Organizations</span></a></li>
                <?php if (!empty($_SESSION['active_audit_id'])): ?>
                    <li class="nav-item"><a href="asset_manage.php?audit_id=<?= intval($_SESSION['active_audit_id']) ?>" data-short="AM" class="<?= $navClass(['asset_manage.php']) ?>"><span class="srm-nav-text">Asset Management</span></a></li>
                    <li class="nav-item"><a href="vulnerability_assessment.php?audit_id=<?= intval($_SESSION['active_audit_id']) ?>" data-short="VA" class="<?= $navClass(['vulnerability_assessment.php']) ?>"><span class="srm-nav-text">Vuln Assessment</span></a></li>
                    <li class="nav-item"><a href="control_checklist.php?audit_id=<?= intval($_SESSION['active_audit_id']) ?>" data-short="CC" class="<?= $navClass(['control_checklist.php']) ?>"><span class="srm-nav-text">Control Checklist</span></a></li>
                    <li class="nav-item"><a href="findings.php?audit_id=<?= intval($_SESSION['active_audit_id']) ?>" data-short="FD" class="<?= $navClass(['findings.php']) ?>"><span class="srm-nav-text">Findings</span></a></li>
                    <li class="nav-item"><a href="report.php?audit_id=<?= intval($_SESSION['active_audit_id']) ?>" data-short="RP" class="<?= $navClass(['report.php']) ?>"><span class="srm-nav-text">Report</span></a></li>
                <?php endif; ?>
            <?php endif; ?>

            <?php if ($role === 'auditee'): ?>
                <!-- Auditee: Assigned audits only -->
                <?php if (!empty($_SESSION['active_audit_id'])): ?>
                    <li class="nav-item"><a href="asset_manage.php?audit_id=<?= intval($_SESSION['active_audit_id']) ?>" data-short="AM" class="<?= $navClass(['asset_manage.php']) ?>"><span class="srm-nav-text">Asset Registration</span></a></li>
                    <li class="nav-item"><a href="findings.php?audit_id=<?= intval($_SESSION['active_audit_id']) ?>" data-short="FD" class="<?= $navClass(['findings.php']) ?>"><span class="srm-nav-text">Findings & Response</span></a></li>
                    <li class="nav-item"><a href="control_checklist.php?audit_id=<?= intval($_SESSION['active_audit_id']) ?>" data-short="CC" class="<?= $navClass(['control_checklist.php']) ?>"><span class="srm-nav-text">Control Checklist</span></a></li>
                    <li class="nav-item"><a href="report.php?audit_id=<?= intval($_SESSION['active_audit_id']) ?>" data-short="RP" class="<?= $navClass(['report.php']) ?>"><span class="srm-nav-text">Report (View)</span></a></li>
                <?php endif; ?>
            <?php endif; ?>

            <li class="nav-item mt-2"><small class="text-muted px-3">Role: <?= ucfirst($role) ?></small></li>
            <li class="nav-item"><a href="logout.php" data-short="LO" class="<?= $navClass(['logout.php']) ?>"><span class="srm-nav-text">Logout</span></a></li>
        </ul>
    </div>

    <div class="p-4 w-100 srm-content">
        <script>
            (function () {
                const layout = document.getElementById('srmLayout');
                const toggle = document.getElementById('srmSidebarToggle');
                const mobileToggle = document.getElementById('srmMobileToggle');
                const backdrop = document.getElementById('srmSidebarBackdrop');
                const navLinks = document.querySelectorAll('.srm-sidebar .srm-nav-link');
                const navItems = document.querySelectorAll('.srm-nav-list .nav-item');
                const storageKey = 'srm_nav_compact';
                const mobileMedia = window.matchMedia('(max-width: 991.98px)');

                if (!layout || !toggle) {
                    return;
                }

                function markActiveItem() {
                    navItems.forEach(function (item) {
                        item.classList.remove('is-active-item');
                    });

                    let activeLink = document.querySelector('.srm-nav-list .srm-nav-link.active');
                    if (!activeLink) {
                        activeLink = document.querySelector('.srm-nav-list .srm-nav-link');
                    }

                    if (activeLink && activeLink.closest('.nav-item')) {
                        activeLink.closest('.nav-item').classList.add('is-active-item');
                    }
                }

                function setCompact(compact) {
                    layout.classList.toggle('compact', compact);
                    toggle.textContent = compact ? '→' : '←';
                    localStorage.setItem(storageKey, compact ? '1' : '0');
                }

                function setMobileOpen(open) {
                    layout.classList.toggle('mobile-open', open);
                    if (mobileToggle) {
                        mobileToggle.textContent = open ? '✕' : '☰';
                    }
                }

                function applyMode() {
                    if (mobileMedia.matches) {
                        layout.classList.remove('compact');
                        setMobileOpen(false);
                        toggle.textContent = '☰';
                        return;
                    }

                    setMobileOpen(false);
                    const saved = localStorage.getItem(storageKey);
                    setCompact(saved === null ? true : saved === '1');
                }

                markActiveItem();
                applyMode();

                toggle.addEventListener('click', function () {
                    if (mobileMedia.matches) {
                        setMobileOpen(!layout.classList.contains('mobile-open'));
                        return;
                    }

                    setCompact(!layout.classList.contains('compact'));
                });

                if (mobileToggle) {
                    mobileToggle.addEventListener('click', function () {
                        setMobileOpen(!layout.classList.contains('mobile-open'));
                    });
                }

                if (backdrop) {
                    backdrop.addEventListener('click', function () {
                        setMobileOpen(false);
                    });
                }

                navLinks.forEach(function (link) {
                    link.addEventListener('click', function () {
                        if (mobileMedia.matches) {
                            setMobileOpen(false);
                        }
                    });
                });

                if (typeof mobileMedia.addEventListener === 'function') {
                    mobileMedia.addEventListener('change', applyMode);
                } else if (typeof mobileMedia.addListener === 'function') {
                    mobileMedia.addListener(applyMode);
                }
            })();
        </script>