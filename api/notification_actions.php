<?php
/**
 * SRM-Audit - Notification Actions API
 * Handle notification listing, mark-read operations
 */
session_start();
require_once '../functions/db.php';
require_once '../functions/auth.php';

header('Content-Type: application/json');

if (!isLoggedIn()) {
    echo json_encode(['success' => false, 'message' => 'Unauthorized']);
    exit();
}

$userId = $_SESSION['user_id'];
$action = $_GET['action'] ?? 'list';

try {
    switch ($action) {
        case 'list':
            $limit = intval($_GET['limit'] ?? 20);
            $notifications = getNotifications($pdo, $userId, $limit);
            $unreadCount = getUnreadNotificationCount($pdo, $userId);
            echo json_encode(['success' => true, 'data' => $notifications, 'unread_count' => $unreadCount]);
            break;

        case 'mark_read':
            $data = json_decode(file_get_contents('php://input'), true);
            $ids = $data['ids'] ?? [];
            if (!empty($ids)) {
                $ids = array_map('intval', $ids);
                markNotificationsRead($pdo, $ids, $userId);
            }
            $unreadCount = getUnreadNotificationCount($pdo, $userId);
            echo json_encode(['success' => true, 'message' => 'Marked as read', 'unread_count' => $unreadCount]);
            break;

        case 'mark_all_read':
            markAllNotificationsRead($pdo, $userId);
            echo json_encode(['success' => true, 'message' => 'All notifications marked as read', 'unread_count' => 0]);
            break;

        case 'count':
            $unreadCount = getUnreadNotificationCount($pdo, $userId);
            echo json_encode(['success' => true, 'unread_count' => $unreadCount]);
            break;

        default:
            throw new Exception('Invalid action');
    }
} catch (Exception $e) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => $e->getMessage()]);
}
?>
