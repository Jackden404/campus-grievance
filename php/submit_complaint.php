<?php
include "connect.php";
include "csrf.php";

if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    http_response_code(405);
    exit("Method not allowed.");
}

require_csrf_token();
ensure_session_started();

if (empty($_SESSION["user_email"])) {
    http_response_code(401);
    exit("Please login to submit complaints.");
}

function column_exists($conn, $table, $column) {
    $table_safe = mysqli_real_escape_string($conn, $table);
    $column_safe = mysqli_real_escape_string($conn, $column);
    $sql = "SHOW COLUMNS FROM `$table_safe` LIKE '$column_safe'";
    $result = mysqli_query($conn, $sql);
    return $result && mysqli_num_rows($result) > 0;
}

function fail($message, $status_code = 400) {
    http_response_code($status_code);
    exit($message);
}

$user_email = trim($_POST['email'] ?? '');
$session_email = $_SESSION["user_email"];
$category = trim($_POST['category'] ?? '');
$category_other = trim($_POST['category_other'] ?? '');
$description = trim($_POST['description'] ?? '');
$is_public = isset($_POST['is_public']) ? 1 : 0;
$status = "Pending";
$attachment_path = "";

if (!filter_var($user_email, FILTER_VALIDATE_EMAIL)) {
    fail("Invalid email address.");
}

if (!hash_equals($session_email, $user_email)) {
    fail("You can submit complaints only from your logged-in account.", 403);
}

if ($category === "Other" && $category_other !== "") {
    $category = $category_other;
}

if ($user_email === "" || $category === "" || $description === "") {
    fail("Missing required fields.");
}

if (strlen($category) > 100) {
    fail("Category is too long.");
}

if (strlen($description) > 5000) {
    fail("Description is too long.");
}

if (isset($_FILES['attachment']) && $_FILES['attachment']['error'] !== UPLOAD_ERR_NO_FILE) {
    if ($_FILES['attachment']['error'] !== UPLOAD_ERR_OK) {
        fail("Error uploading file.");
    }

    $max_size = 10 * 1024 * 1024;
    if ($_FILES['attachment']['size'] > $max_size) {
        fail("File size must be 10 MB or less.");
    }

    $allowed_types = array(
        "jpg" => "image/jpeg",
        "jpeg" => "image/jpeg",
        "png" => "image/png",
        "pdf" => "application/pdf"
    );

    $original_name = $_FILES['attachment']['name'];
    $tmp_name = $_FILES['attachment']['tmp_name'];
    $extension = strtolower(pathinfo($original_name, PATHINFO_EXTENSION));

    if (!array_key_exists($extension, $allowed_types)) {
        fail("Invalid file type. Only JPG, JPEG, PNG, and PDF are allowed.");
    }

    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mime_type = finfo_file($finfo, $tmp_name);
    finfo_close($finfo);

    if ($mime_type !== $allowed_types[$extension]) {
        fail("Invalid file type. Only JPG, JPEG, PNG, and PDF are allowed.");
    }

    $upload_dir = __DIR__ . "/uploads/complaints/";
    if (!is_dir($upload_dir)) {
        if (!mkdir($upload_dir, 0775, true) && !is_dir($upload_dir)) {
            fail("Unable to create upload directory.", 500);
        }
    }

    $safe_name = preg_replace("/[^a-zA-Z0-9_-]/", "_", pathinfo($original_name, PATHINFO_FILENAME));
    $new_file_name = time() . "_" . bin2hex(random_bytes(4)) . "_" . $safe_name . "." . $extension;
    $target_path = $upload_dir . $new_file_name;

    if (!move_uploaded_file($tmp_name, $target_path)) {
        fail("Unable to save uploaded file.", 500);
    }

    $attachment_path = "php/uploads/complaints/" . $new_file_name;
}

$has_attachment_column = column_exists($conn, "complaints", "attachment");
$has_public_column = column_exists($conn, "complaints", "is_public");
$has_created_at_column = column_exists($conn, "complaints", "created_at");

if ($has_created_at_column) {
    $dupe_sql = "SELECT id FROM complaints
                 WHERE user_email = ? AND category = ? AND description = ?
                 AND created_at >= (NOW() - INTERVAL 5 MINUTE)
                 LIMIT 1";
    $dupe_stmt = mysqli_prepare($conn, $dupe_sql);
    if ($dupe_stmt) {
        mysqli_stmt_bind_param($dupe_stmt, "sss", $user_email, $category, $description);
        mysqli_stmt_execute($dupe_stmt);
        $dupe_result = mysqli_stmt_get_result($dupe_stmt);
        if ($dupe_result && mysqli_num_rows($dupe_result) > 0) {
            mysqli_stmt_close($dupe_stmt);
            if ($attachment_path !== "" && file_exists(__DIR__ . "/../" . $attachment_path)) {
                @unlink(__DIR__ . "/../" . $attachment_path);
            }
            fail("Duplicate complaint detected. This complaint was already submitted recently.");
        }
        mysqli_stmt_close($dupe_stmt);
    }
}

$columns = array("user_email", "category", "description", "status");
$values = array($user_email, $category, $description, $status);
$types = "ssss";

if ($has_attachment_column) {
    $columns[] = "attachment";
    $values[] = $attachment_path;
    $types .= "s";
}

if ($has_public_column) {
    $columns[] = "is_public";
    $values[] = $is_public;
    $types .= "i";
}

$placeholder = implode(", ", array_fill(0, count($columns), "?"));
$column_sql = implode(", ", $columns);
$sql = "INSERT INTO complaints ($column_sql) VALUES ($placeholder)";

$stmt = mysqli_prepare($conn, $sql);
if (!$stmt) {
    fail("Unable to prepare complaint submission.", 500);
}

mysqli_stmt_bind_param($stmt, $types, ...$values);

if (mysqli_stmt_execute($stmt)) {
    echo "Complaint submitted successfully.";
} else {
    fail("Error submitting complaint.", 500);
}

mysqli_stmt_close($stmt);
?>