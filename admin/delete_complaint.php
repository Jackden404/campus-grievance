<?php
include "../php/security_headers.php";
include "../php/security_log.php";
include "auth.php";
require_admin();
include "../php/connect.php";
include "../php/csrf.php";

if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    http_response_code(405);
    exit("Method not allowed.");
}

require_csrf_token();

$id = isset($_POST['id']) ? (int)$_POST['id'] : 0;
if ($id <= 0) {
    exit("Invalid complaint id.");
}

$has_attachment_column = false;
$column_check = mysqli_query($conn, "SHOW COLUMNS FROM complaints LIKE 'attachment'");
if ($column_check && mysqli_num_rows($column_check) > 0) {
    $has_attachment_column = true;
}

$attachment_path = "";
if ($has_attachment_column) {
    $fetch_stmt = mysqli_prepare($conn, "SELECT attachment FROM complaints WHERE id = ? LIMIT 1");
    if ($fetch_stmt) {
        mysqli_stmt_bind_param($fetch_stmt, "i", $id);
        mysqli_stmt_execute($fetch_stmt);
        $fetch_result = mysqli_stmt_get_result($fetch_stmt);
        if ($fetch_result && mysqli_num_rows($fetch_result) === 1) {
            $row = mysqli_fetch_assoc($fetch_result);
            $attachment_path = trim($row['attachment'] ?? '');
        }
        mysqli_stmt_close($fetch_stmt);
    }
}

$votes_table_check = mysqli_query($conn, "SHOW TABLES LIKE 'complaint_votes'");
if ($votes_table_check && mysqli_num_rows($votes_table_check) > 0) {
    $votes_stmt = mysqli_prepare($conn, "DELETE FROM complaint_votes WHERE complaint_id = ?");
    if ($votes_stmt) {
        mysqli_stmt_bind_param($votes_stmt, "i", $id);
        mysqli_stmt_execute($votes_stmt);
        mysqli_stmt_close($votes_stmt);
    }
}

$delete_stmt = mysqli_prepare($conn, "DELETE FROM complaints WHERE id = ?");
if (!$delete_stmt) {
    http_response_code(500);
    exit("Unable to delete complaint.");
}

mysqli_stmt_bind_param($delete_stmt, "i", $id);
$ok = mysqli_stmt_execute($delete_stmt);
$deleted_rows = mysqli_stmt_affected_rows($delete_stmt);
mysqli_stmt_close($delete_stmt);

if ($ok && $deleted_rows > 0) {
    if ($attachment_path !== '') {
        $full_path = realpath(__DIR__ . '/../') . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, ltrim($attachment_path, '/'));
        if ($full_path && is_file($full_path)) {
            @unlink($full_path);
        }
    }
    security_log('COMPLAINT_DELETED', [
        'admin' => $_SESSION['admin_username'] ?? '',
        'id'    => $id,
    ]);
    header('Location: view_complaints.php');
    exit;
}

http_response_code(404);
echo "Complaint not found or already deleted.";
?>