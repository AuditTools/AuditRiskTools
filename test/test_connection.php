<?php
/**
 * Database Connection Test
 * File ini untuk testing koneksi database
 */
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Database Connection Test</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 50px;
            margin: 0;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            padding: 40px;
        }
        .success { 
            color: #28a745; 
            background: #d4edda; 
            border: 1px solid #c3e6cb;
            padding: 15px;
            border-radius: 5px;
            margin: 15px 0;
        }
        .error { 
            color: #dc3545; 
            background: #f8d7da; 
            border: 1px solid #f5c6cb;
            padding: 15px;
            border-radius: 5px;
            margin: 15px 0;
        }
        .info {
            background: #d1ecf1;
            border: 1px solid #bee5eb;
            color: #0c5460;
            padding: 15px;
            border-radius: 5px;
            margin: 15px 0;
        }
        h1 { color: #333; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        table th {
            background: #667eea;
            color: white;
            padding: 12px;
            text-align: left;
        }
        table td {
            padding: 10px;
            border-bottom: 1px solid #ddd;
        }
        .badge {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 3px;
            font-size: 12px;
            font-weight: bold;
        }
        .badge-success { background: #28a745; color: white; }
        .badge-danger { background: #dc3545; color: white; }
        .btn {
            display: inline-block;
            padding: 10px 20px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            margin-top: 20px;
        }
        .btn:hover { background: #5568d3; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔌 Database Connection Test</h1>
        
        <?php
        $tests = [];
        $allPassed = true;
        
        // Test 1: Check if db.php exists
        $tests[] = [
            'name' => 'File db.php exists',
            'status' => file_exists('functions/db.php'),
            'message' => file_exists('functions/db.php') ? 'File ditemukan' : 'File tidak ditemukan'
        ];
        
        // Test 2: Try to include db.php
        try {
            require_once 'functions/db.php';
            $tests[] = [
                'name' => 'Include db.php',
                'status' => true,
                'message' => 'Berhasil di-load'
            ];
        } catch (Exception $e) {
            $tests[] = [
                'name' => 'Include db.php',
                'status' => false,
                'message' => 'Error: ' . $e->getMessage()
            ];
            $allPassed = false;
        }
        
        // Test 3: Check PDO connection
        if (isset($pdo)) {
            try {
                $stmt = $pdo->query("SELECT VERSION() as version");
                $version = $stmt->fetch();
                
                $tests[] = [
                    'name' => 'Database Connection',
                    'status' => true,
                    'message' => 'Connected! MySQL Version: ' . $version['version']
                ];
            } catch (PDOException $e) {
                $tests[] = [
                    'name' => 'Database Connection',
                    'status' => false,
                    'message' => 'Error: ' . $e->getMessage()
                ];
                $allPassed = false;
            }
            
            // Test 4: Check if tables exist
            try {
                $tables = ['users', 'organizations', 'audit_sessions', 'assets', 'findings', 'ai_reports'];
                $existingTables = [];
                
                foreach ($tables as $table) {
                    $stmt = $pdo->query("SHOW TABLES LIKE '$table'");
                    if ($stmt->rowCount() > 0) {
                        $existingTables[] = $table;
                    }
                }
                
                if (count($existingTables) === count($tables)) {
                    $tests[] = [
                        'name' => 'Database Tables',
                        'status' => true,
                        'message' => 'Semua ' . count($tables) . ' tables ditemukan'
                    ];
                } else {
                    $tests[] = [
                        'name' => 'Database Tables',
                        'status' => false,
                        'message' => 'Hanya ' . count($existingTables) . '/' . count($tables) . ' tables ditemukan. Import database_schema.sql!'
                    ];
                    $allPassed = false;
                }
                
            } catch (PDOException $e) {
                $tests[] = [
                    'name' => 'Database Tables',
                    'status' => false,
                    'message' => 'Error checking tables: ' . $e->getMessage()
                ];
                $allPassed = false;
            }
            
            // Test 5: Check users table
            try {
                $stmt = $pdo->query("SELECT COUNT(*) as count FROM users");
                $result = $stmt->fetch();
                
                $tests[] = [
                    'name' => 'Users Table',
                    'status' => true,
                    'message' => 'Table accessible. Total users: ' . $result['count']
                ];
            } catch (PDOException $e) {
                $tests[] = [
                    'name' => 'Users Table',
                    'status' => false,
                    'message' => 'Error: ' . $e->getMessage()
                ];
                $allPassed = false;
            }
        } else {
            $tests[] = [
                'name' => 'PDO Object',
                'status' => false,
                'message' => 'PDO object tidak ditemukan'
            ];
            $allPassed = false;
        }
        
        // Display results
        if ($allPassed) {
            echo '<div class="success">';
            echo '<h2>✅ Semua Test Berhasil!</h2>';
            echo '<p>Database connection sudah siap digunakan.</p>';
            echo '</div>';
        } else {
            echo '<div class="error">';
            echo '<h2>❌ Ada Test yang Gagal</h2>';
            echo '<p>Silakan cek hasil test di bawah dan perbaiki masalahnya.</p>';
            echo '</div>';
        }
        ?>
        
        <h3>📊 Test Results:</h3>
        <table>
            <thead>
                <tr>
                    <th style="width: 40%;">Test Name</th>
                    <th style="width: 20%;">Status</th>
                    <th style="width: 40%;">Message</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($tests as $test): ?>
                    <tr>
                        <td><strong><?php echo $test['name']; ?></strong></td>
                        <td>
                            <span class="badge badge-<?php echo $test['status'] ? 'success' : 'danger'; ?>">
                                <?php echo $test['status'] ? '✓ PASS' : '✗ FAIL'; ?>
                            </span>
                        </td>
                        <td><?php echo $test['message']; ?></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        
        <div class="info">
            <h4>📝 Configuration Info:</h4>
            <ul>
                <li><strong>Host:</strong> <?php echo defined('DB_HOST') ? DB_HOST : 'Not defined'; ?></li>
                <li><strong>Port:</strong> <?php echo defined('DB_PORT') ? DB_PORT : 'Not defined'; ?></li>
                <li><strong>Database:</strong> <?php echo defined('DB_NAME') ? DB_NAME : 'Not defined'; ?></li>
                <li><strong>User:</strong> <?php echo defined('DB_USER') ? DB_USER : 'Not defined'; ?></li>
                <li><strong>PHP Version:</strong> <?php echo phpversion(); ?></li>
            </ul>
        </div>
        
        <?php if ($allPassed): ?>
            <a href="index.php" class="btn">🚀 Lanjut ke Aplikasi</a>
        <?php else: ?>
            <div class="error">
                <h4>🔧 Langkah Perbaikan:</h4>
                <ol>
                    <li>Pastikan MySQL di XAMPP sudah running (hijau)</li>
                    <li>Buka phpMyAdmin: <a href="http://localhost/phpmyadmin" target="_blank">http://localhost/phpmyadmin</a></li>
                    <li>Import file <code>database_schema.sql</code></li>
                    <li>Refresh halaman ini</li>
                </ol>
            </div>
        <?php endif; ?>
    </div>
</body>
</html>
