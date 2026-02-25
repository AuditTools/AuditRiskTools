<!DOCTYPE html>
<html>
<head>
    <title>SRM-Audit</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .badge-srm-neutral {
            background: #7f8ea8;
            color: #f9fafb;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }

        .badge-srm-muted {
            background: #929eb2;
            color: #ffffff;
            border: 1px solid rgba(255, 255, 255, 0.18);
        }

        .badge-srm-accent {
            background: #5f95ff;
            color: #ffffff;
            border: 1px solid rgba(255, 255, 255, 0.22);
        }

        .badge-srm-danger {
            background: #e76f7a;
            color: #fff;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }

        .badge-srm-info {
            background: #65aecd;
            color: #fff;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }

        .badge-srm-success {
            background: #67b389;
            color: #fff;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }

        .badge-srm-warning {
            background: #e2b84e;
            color: #2b2f33;
            border: 1px solid rgba(43, 47, 51, 0.18);
        }

        .btn.btn-primary,
        .btn.btn-danger,
        .btn.btn-warning,
        .btn.btn-success,
        .btn.btn-info,
        .btn.btn-dark,
        .btn.btn-secondary {
            color: #ffffff !important;
        }

        .btn.btn-primary {
            background: linear-gradient(135deg, #5f95ff, #4f86ff) !important;
            border-color: #4f86ff !important;
            box-shadow: 0 4px 10px rgba(79, 134, 255, 0.24) !important;
        }

        .btn.btn-danger {
            background: linear-gradient(135deg, #ef8a94, #e76f7a) !important;
            border-color: #e76f7a !important;
            box-shadow: 0 4px 10px rgba(231, 111, 122, 0.22) !important;
        }

        .btn.btn-warning {
            background: linear-gradient(135deg, #f0c761, #e2b84e) !important;
            border-color: #e2b84e !important;
            color: #2b2f33 !important;
            box-shadow: 0 4px 10px rgba(226, 184, 78, 0.22) !important;
        }

        .btn.btn-success {
            background: linear-gradient(135deg, #7fc79e, #67b389) !important;
            border-color: #67b389 !important;
            box-shadow: 0 4px 10px rgba(103, 179, 137, 0.22) !important;
        }

        .btn.btn-info {
            background: linear-gradient(135deg, #7cc2df, #65aecd) !important;
            border-color: #65aecd !important;
            box-shadow: 0 4px 10px rgba(101, 174, 205, 0.22) !important;
        }

        .btn.btn-dark {
            background: linear-gradient(135deg, #6f7887, #5f6875) !important;
            border-color: #5f6875 !important;
            box-shadow: 0 4px 10px rgba(95, 104, 117, 0.2) !important;
        }

        .btn.btn-secondary {
            background: linear-gradient(135deg, #98a6bc, #7f8ca0) !important;
            border-color: #7f8ca0 !important;
            color: #ffffff !important;
            box-shadow: 0 4px 10px rgba(127, 140, 160, 0.2) !important;
        }

        .btn {
            font-weight: 600;
            border-radius: 9px;
            box-shadow: 0 2px 8px rgba(17, 24, 39, 0.12);
            transition: transform 0.12s ease, filter 0.15s ease;
        }

        .btn.btn-primary:hover,
        .btn.btn-danger:hover,
        .btn.btn-warning:hover,
        .btn.btn-success:hover,
        .btn.btn-info:hover,
        .btn.btn-dark:hover,
        .btn.btn-secondary:hover,
        .btn.btn-primary:focus,
        .btn.btn-danger:focus,
        .btn.btn-warning:focus,
        .btn.btn-success:focus,
        .btn.btn-info:focus,
        .btn.btn-dark:focus,
        .btn.btn-secondary:focus,
        .btn.btn-primary:active,
        .btn.btn-danger:active,
        .btn.btn-warning:active,
        .btn.btn-success:active,
        .btn.btn-info:active,
        .btn.btn-dark:active,
        .btn.btn-secondary:active {
            filter: brightness(0.93);
            color: #ffffff !important;
            box-shadow: none !important;
        }

        .btn.btn-warning:hover,
        .btn.btn-warning:focus,
        .btn.btn-warning:active {
            color: #2b2f33 !important;
        }

        .btn.btn-outline-primary,
        .btn.btn-outline-danger,
        .btn.btn-outline-warning,
        .btn.btn-outline-success,
        .btn.btn-outline-info,
        .btn.btn-outline-dark,
        .btn.btn-outline-secondary {
            background-color: transparent !important;
        }

        .btn.btn-outline-primary { color: #5f95ff !important; border-color: #5f95ff !important; }
        .btn.btn-outline-danger { color: #e76f7a !important; border-color: #e76f7a !important; }
        .btn.btn-outline-warning { color: #a77f22 !important; border-color: #e2b84e !important; }
        .btn.btn-outline-success { color: #67b389 !important; border-color: #67b389 !important; }
        .btn.btn-outline-info { color: #65aecd !important; border-color: #65aecd !important; }
        .btn.btn-outline-dark { color: #5f6875 !important; border-color: #5f6875 !important; }
        .btn.btn-outline-secondary { color: #7f8ca0 !important; border-color: #7f8ca0 !important; }

        .btn.btn-outline-primary:hover,
        .btn.btn-outline-danger:hover,
        .btn.btn-outline-warning:hover,
        .btn.btn-outline-success:hover,
        .btn.btn-outline-info:hover,
        .btn.btn-outline-dark:hover,
        .btn.btn-outline-secondary:hover,
        .btn.btn-outline-primary:focus,
        .btn.btn-outline-danger:focus,
        .btn.btn-outline-warning:focus,
        .btn.btn-outline-success:focus,
        .btn.btn-outline-info:focus,
        .btn.btn-outline-dark:focus,
        .btn.btn-outline-secondary:focus,
        .btn.btn-outline-primary:active,
        .btn.btn-outline-danger:active,
        .btn.btn-outline-warning:active,
        .btn.btn-outline-success:active,
        .btn.btn-outline-info:active,
        .btn.btn-outline-dark:active,
        .btn.btn-outline-secondary:active {
            color: #ffffff !important;
            box-shadow: none !important;
        }

        .btn.btn-outline-primary:hover, .btn.btn-outline-primary:focus, .btn.btn-outline-primary:active { border-color: #5f95ff !important; background-color: #5f95ff !important; }
        .btn.btn-outline-danger:hover, .btn.btn-outline-danger:focus, .btn.btn-outline-danger:active { border-color: #e76f7a !important; background-color: #e76f7a !important; }
        .btn.btn-outline-warning:hover, .btn.btn-outline-warning:focus, .btn.btn-outline-warning:active { border-color: #e2b84e !important; background-color: #e2b84e !important; color: #2b2f33 !important; }
        .btn.btn-outline-success:hover, .btn.btn-outline-success:focus, .btn.btn-outline-success:active { border-color: #67b389 !important; background-color: #67b389 !important; }
        .btn.btn-outline-info:hover, .btn.btn-outline-info:focus, .btn.btn-outline-info:active { border-color: #65aecd !important; background-color: #65aecd !important; }
        .btn.btn-outline-dark:hover, .btn.btn-outline-dark:focus, .btn.btn-outline-dark:active { border-color: #5f6875 !important; background-color: #5f6875 !important; }
        .btn.btn-outline-secondary:hover, .btn.btn-outline-secondary:focus, .btn.btn-outline-secondary:active { border-color: #7f8ca0 !important; background-color: #7f8ca0 !important; }

    </style>
</head>
<body>