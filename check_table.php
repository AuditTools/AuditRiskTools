<?php
require_once __DIR__ . '/config/config.php';
require_once __DIR__ . '/functions/db.php';

echo "Checking ai_reports table structure...\n\n";

try {
    $stmt = $pdo->query("DESCRIBE ai_reports");
    $columns = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    echo "Current columns in ai_reports table:\n";
    echo str_repeat('-', 80) . "\n";
    printf("%-30s %-20s %-10s\n", "Field", "Type", "Key");
    echo str_repeat('-', 80) . "\n";
    
    foreach ($columns as $col) {
        printf("%-30s %-20s %-10s\n", $col['Field'], $col['Type'], $col['Key']);
    }
    
} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
?>
