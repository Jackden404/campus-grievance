<?php
include "connect.php";

header("Content-Type: application/json");

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

$has_public_column = column_exists($conn, "complaints", "is_public");
if (!$has_public_column) {
    echo json_encode(array("success" => false, "message" => "Public complaints feature is not configured.", "data" => array()));
    exit;
}

if (!table_exists($conn, "complaint_votes")) {
    echo json_encode(array("success" => false, "message" => "Voting table is not configured.", "data" => array()));
    exit;
}

$has_created_at = column_exists($conn, "complaints", "created_at");

$sql = "SELECT MIN(c.id) AS id, c.category, c.description, " . ($has_created_at ? "MAX(c.created_at)" : "NULL") . " AS created_at,
        COUNT(DISTINCT v.voter_email) AS upvotes
        FROM complaints c
        LEFT JOIN complaint_votes v ON v.complaint_id = c.id
        WHERE c.is_public = 1
        GROUP BY c.category, c.description
        ORDER BY upvotes DESC, created_at DESC, id DESC
        LIMIT 10";

$result = mysqli_query($conn, $sql);
$data = array();

if (!$result) {
    echo json_encode(array("success" => false, "message" => "Failed to load public complaints"));
    exit;
}

if ($result) {
    while ($row = mysqli_fetch_assoc($result)) {
        $data[] = array(
            "id" => (int)$row["id"],
            "category" => $row["category"],
            "description" => $row["description"],
            "created_at" => $row["created_at"],
            "upvotes" => (int)$row["upvotes"]
        );
    }
}

echo json_encode(array("success" => true, "data" => $data));
?>
