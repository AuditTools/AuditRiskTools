<?php
/**
 * SRM-Audit - Database Connection
 * PDO connection with error handling
 */

// Database configuration
define('DB_HOST', 'localhost');
define('DB_PORT', '3306');
define('DB_NAME', 'audit');
define('DB_USER', 'root');        // Ganti dengan username MySQL Anda
define('DB_PASS', '');            // Ganti dengan password MySQL Anda

// Database connection
try {
    $dsn = "mysql:host=" . DB_HOST . ";port=" . DB_PORT . ";dbname=" . DB_NAME . ";charset=utf8mb4";
    
    $options = [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
    ];
    
    $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
    
} catch (PDOException $e) {
    // Log error (jangan tampilkan detail error di production)
    error_log("Database Connection Error: " . $e->getMessage());
    
    // Tampilkan pesan error yang user-friendly
    die("
        <!DOCTYPE html>
        <html>
        <head>
            <title>Database Connection Error</title>
            <style>
                body { font-family: Arial; padding: 50px; background: #f5f5f5; }
                .error-box { 
                    max-width: 600px; 
                    margin: 0 auto; 
                    background: white; 
                    padding: 30px; 
                    border-radius: 8px; 
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }
                h2 { color: #dc3545; }
                .steps { background: #f8f9fa; padding: 15px; border-radius: 5px; margin-top: 20px; }
                code { background: #e9ecef; padding: 2px 6px; border-radius: 3px; }
            </style>
        </head>
        <body>
            <div class='error-box'>
                <h2>❌ Database Connection Error</h2>
                <p><strong>Tidak dapat terhubung ke database!</strong></p>
                
                <div class='steps'>
                    <h4>Langkah-langkah setup:</h4>
                    <ol>
                        <li><strong>Pastikan MySQL/XAMPP sudah running</strong>
                            <br>• Buka XAMPP Control Panel
                            <br>• Start Apache dan MySQL
                        </li>
                        <br>
                        <li><strong>Import database schema</strong>
                            <br>• Buka phpMyAdmin: <a href='http://localhost/phpmyadmin' target='_blank'>http://localhost/phpmyadmin</a>
                            <br>• Klik tab 'SQL'
                            <br>• Copy-paste isi file <code>database_schema.sql</code>
                            <br>• Klik 'Go' untuk execute
                        </li>
                        <br>
                        <li><strong>Update kredensial database</strong>
                            <br>• Edit file: <code>functions/db.php</code>
                            <br>• Sesuaikan DB_USER dan DB_PASS dengan setting MySQL Anda
                            <br>• Default XAMPP: username='root', password=''
                        </li>
                        <br>
                        <li><strong>Refresh halaman ini</strong></li>
                    </ol>
                </div>
                
                <p style='margin-top: 20px; color: #666; font-size: 0.9em;'>
                    <strong>Current Settings:</strong><br>
                    Host: " . DB_HOST . ":" . DB_PORT . "<br>
                    Database: " . DB_NAME . "<br>
                    User: " . DB_USER . "
                </p>
            </div>
        </body>
        </html>
    ");
}
?>
