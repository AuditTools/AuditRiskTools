<?php
require_once 'config/config.php';
require_once 'functions/db.php';

$stmt = $pdo->query("DESCRIBE audit_sessions");
$columns = $stmt->fetchAll(PDO::FETCH_COLUMN);
echo "audit_sessions columns:\n";
foreach($columns as $col) {
    echo "- $col\n";
}
?>
