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
$status = trim($_POST['status'] ?? '');
$allowed_statuses = array("Pending", "In Progress", "Resolved", "Rejected");

if ($id <= 0 || !in_array($status, $allowed_statuses, true)) {
    http_response_code(400);
    security_log('UPDATE_STATUS_INVALID_INPUT', ['admin' => $_SESSION['admin_username'] ?? '', 'id' => $id, 'status' => $status]);
    exit("Invalid request.");
}

$stmt = mysqli_prepare($conn, "UPDATE complaints SET status=? WHERE id=?");
mysqli_stmt_bind_param($stmt, "si", $status, $id);

if (mysqli_stmt_execute($stmt)) {
    security_log('COMPLAINT_STATUS_UPDATED', [
        'admin'  => $_SESSION['admin_username'] ?? '',
        'id'     => $id,
        'status' => $status,
    ]);
    header('Location: view_complaints.php');
    exit;
} else {
    security_log('COMPLAINT_STATUS_UPDATE_FAIL', ['id' => $id]);
    http_response_code(500);
    exit('Status update failed.');
}

mysqli_stmt_close($stmt);
?>