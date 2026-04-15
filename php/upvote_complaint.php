<?php
include "connect.php";
include "csrf.php";

header("Content-Type: application/json");

if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    http_response_code(405);
    echo json_encode(array("success" => false, "message" => "Method not allowed"));
    exit;
}

require_csrf_token();

function column_exists($conn, $table, $column) {
    $table_safe = mysqli_real_escape_string($conn, $table);
    $column_safe = mysqli_real_escape_string($conn, $column);
    $check = mysqli_query($conn, "SHOW COLUMNS FROM `$table_safe` LIKE '$column_safe'");
    return $check && mysqli_num_rows($check) > 0;
}

function table_exists($conn, $table) {
    $table_safe = mysqli_real_escape_string($conn, $table);
    $check = mysqli_query($conn, "SHOW TABLES LIKE '$table_safe'");
    return $check && mysqli_num_rows($check) > 0;
}

if (!column_exists($conn, "complaints", "is_public")) {
    echo json_encode(array("success" => false, "message" => "Public complaints feature is not configured"));
    exit;
}

if (!table_exists($conn, "complaint_votes")) {
    echo json_encode(array("success" => false, "message" => "Voting table is not configured"));
    exit;
}

$complaint_id = isset($_POST["complaint_id"]) ? (int)$_POST["complaint_id"] : 0;
$voter_email = trim($_POST["voter_email"] ?? "");

if ($complaint_id <= 0 || !filter_var($voter_email, FILTER_VALIDATE_EMAIL)) {
    echo json_encode(array("success" => false, "message" => "Invalid complaint or email"));
    exit;
}

$check_stmt = mysqli_prepare($conn, "SELECT id FROM complaints WHERE id = ? AND is_public = 1 LIMIT 1");
mysqli_stmt_bind_param($check_stmt, "i", $complaint_id);
mysqli_stmt_execute($check_stmt);
$check_result = mysqli_stmt_get_result($check_stmt);

if (!$check_result || mysqli_num_rows($check_result) === 0) {
    mysqli_stmt_close($check_stmt);
    echo json_encode(array("success" => false, "message" => "Complaint not available for public voting"));
    exit;
}
mysqli_stmt_close($check_stmt);

$insert_stmt = mysqli_prepare($conn, "INSERT IGNORE INTO complaint_votes (complaint_id, voter_email) VALUES (?, ?)");
mysqli_stmt_bind_param($insert_stmt, "is", $complaint_id, $voter_email);
mysqli_stmt_execute($insert_stmt);
$rows_changed = mysqli_stmt_affected_rows($insert_stmt);
mysqli_stmt_close($insert_stmt);

$count_stmt = mysqli_prepare($conn, "SELECT COUNT(*) AS total_votes FROM complaint_votes WHERE complaint_id = ?");
mysqli_stmt_bind_param($count_stmt, "i", $complaint_id);
mysqli_stmt_execute($count_stmt);
$count_result = mysqli_stmt_get_result($count_stmt);
$vote_total = 0;

if ($count_result) {
    $count_row = mysqli_fetch_assoc($count_result);
    $vote_total = (int)$count_row["total_votes"];
}
mysqli_stmt_close($count_stmt);

if ($rows_changed > 0) {
    echo json_encode(array("success" => true, "message" => "Upvote added", "upvotes" => $vote_total));
} else {
    echo json_encode(array("success" => true, "message" => "You already upvoted this complaint", "upvotes" => $vote_total));
}
?>