<?php
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
    exit("Invalid request.");
}

$stmt = mysqli_prepare($conn, "UPDATE complaints SET status=? WHERE id=?");
mysqli_stmt_bind_param($stmt, "si", $status, $id);

if (mysqli_stmt_execute($stmt)) {
    header("Location: view_complaints.php");
} else {
    echo "Status update failed";
}

mysqli_stmt_close($stmt);
?>