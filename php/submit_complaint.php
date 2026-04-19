<?php
include 'security_headers.php';
include 'security_log.php';
include 'connect.php';
include 'csrf.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit('Method not allowed.');
}

require_csrf_token();
ensure_session_started();

// ── Authentication guard ───────────────────────────────────────────────────────
if (empty($_SESSION['user_email']) || empty($_SESSION['user_id'])) {
    security_log('SUBMIT_COMPLAINT_UNAUTH', ['uri' => $_SERVER['REQUEST_URI'] ?? '']);
    http_response_code(401);
    exit('Please login to submit complaints.');
}

// ── Helper ────────────────────────────────────────────────────────────────────
function fail(string $message, int $status_code = 400): never {
    http_response_code($status_code);
    exit($message);
}

function column_exists(mysqli $conn, string $table, string $column): bool {
    $table_safe  = mysqli_real_escape_string($conn, $table);
    $column_safe = mysqli_real_escape_string($conn, $column);
    $res = mysqli_query($conn, "SHOW COLUMNS FROM `{$table_safe}` LIKE '{$column_safe}'");
    return $res && mysqli_num_rows($res) > 0;
}

// ── 1. Collect from session — never trust POST for the user identity ───────────
// IDOR fix: the email used in the INSERT comes from the session,
// not from user-supplied POST data.
$session_email = (string)$_SESSION['user_email'];
$session_uid   = (int)$_SESSION['user_id'];

// Still accept the email field from POST and verify it matches the session.
// This keeps the existing form working while blocking cross-account submission.
$post_email = strtolower(trim($_POST['email'] ?? ''));
if (!filter_var($post_email, FILTER_VALIDATE_EMAIL)
    || !hash_equals($session_email, $post_email)) {
    security_log('SUBMIT_COMPLAINT_EMAIL_MISMATCH', [
        'session_user' => $session_uid,
        'post_email'   => $post_email,
    ]);
    fail('You can only submit complaints from your own account.', 403);
}

// ── 2. Validated inputs ───────────────────────────────────────────────────────
$ALLOWED_CATEGORIES = ['Hostel', 'Mess', 'Department', 'Library', 'Infrastructure', 'Other'];

$category       = trim($_POST['category']       ?? '');
$category_other = trim($_POST['category_other'] ?? '');
$description    = trim($_POST['description']    ?? '');
$is_public      = isset($_POST['is_public']) ? 1 : 0;
$status         = 'Pending';

// Category whitelist — prevents arbitrary string injection via category field
if (!in_array($category, $ALLOWED_CATEGORIES, true)) {
    fail('Invalid issue category.');
}

if ($category === 'Other') {
    if ($category_other === '') {
        fail('Please specify the category.');
    }
    // Strip HTML and limit length
    $category = htmlspecialchars(strip_tags($category_other), ENT_QUOTES, 'UTF-8');
    if (mb_strlen($category) > 100) {
        fail('Category name is too long (max 100 characters).');
    }
}

if ($description === '') {
    fail('Description is required.');
}

// Strip HTML tags from free-text fields; output will be htmlspecialchars'd on display
$description = strip_tags($description);
if (mb_strlen($description) > 5000) {
    fail('Description is too long (max 5000 characters).');
}

// ── 3. File upload — strict validation ───────────────────────────────────────
$attachment_path = '';

if (isset($_FILES['attachment']) && $_FILES['attachment']['error'] !== UPLOAD_ERR_NO_FILE) {
    if ($_FILES['attachment']['error'] !== UPLOAD_ERR_OK) {
        fail('File upload error. Please try again.');
    }

    $max_size = 10 * 1024 * 1024; // 10 MB
    if ($_FILES['attachment']['size'] > $max_size || $_FILES['attachment']['size'] === 0) {
        fail('File must be between 1 byte and 10 MB.');
    }

    $allowed_types = [
        'jpg'  => 'image/jpeg',
        'jpeg' => 'image/jpeg',
        'png'  => 'image/png',
        'pdf'  => 'application/pdf',
    ];

    $original_name = $_FILES['attachment']['name'];
    $tmp_name      = $_FILES['attachment']['tmp_name'];
    $extension     = strtolower(pathinfo($original_name, PATHINFO_EXTENSION));

    // Check extension whitelist
    if (!array_key_exists($extension, $allowed_types)) {
        fail('Invalid file type. Only JPG, PNG, and PDF are allowed.');
    }

    // Verify MIME type from file contents (not from HTTP header)
    $finfo     = finfo_open(FILEINFO_MIME_TYPE);
    $mime_type = finfo_file($finfo, $tmp_name);
    finfo_close($finfo);

    if ($mime_type !== $allowed_types[$extension]) {
        fail('File content does not match the file extension.');
    }

    // Additional check: PNG/JPEG files must pass getimagesize()
    if (in_array($extension, ['jpg', 'jpeg', 'png'], true)) {
        if (!getimagesize($tmp_name)) {
            fail('Uploaded image appears to be corrupt or invalid.');
        }
    }

    // Build a safe, randomised filename (no user-controlled characters in path)
    $upload_dir = __DIR__ . '/uploads/complaints/';
    if (!is_dir($upload_dir)) {
        if (!mkdir($upload_dir, 0750, true) && !is_dir($upload_dir)) {
            security_log('SUBMIT_COMPLAINT_MKDIR_FAIL', []);
            fail('Unable to prepare upload directory.', 500);
        }
    }

    // Ensure the upload directory has an .htaccess that prevents script execution
    $htaccess = $upload_dir . '.htaccess';
    if (!file_exists($htaccess)) {
        file_put_contents(
            $htaccess,
            "Options -Indexes\n" .
            "<FilesMatch \"\\.php$\">\n  Deny from all\n</FilesMatch>\n"
        );
    }

    $new_file_name = bin2hex(random_bytes(16)) . '.' . $extension;
    $target_path   = $upload_dir . $new_file_name;

    if (!move_uploaded_file($tmp_name, $target_path)) {
        security_log('SUBMIT_COMPLAINT_UPLOAD_FAIL', ['user_id' => $session_uid]);
        fail('Unable to save uploaded file.', 500);
    }

    $attachment_path = 'php/uploads/complaints/' . $new_file_name;
}

// ── 4. Duplicate submission guard ────────────────────────────────────────────
if (column_exists($conn, 'complaints', 'created_at')) {
    $dupe = mysqli_prepare(
        $conn,
        'SELECT id FROM complaints
         WHERE user_email = ? AND category = ? AND description = ?
         AND created_at >= (NOW() - INTERVAL 5 MINUTE)
         LIMIT 1'
    );
    if ($dupe) {
        mysqli_stmt_bind_param($dupe, 'sss', $session_email, $category, $description);
        mysqli_stmt_execute($dupe);
        $dupe_result = mysqli_stmt_get_result($dupe);
        if ($dupe_result && mysqli_num_rows($dupe_result) > 0) {
            mysqli_stmt_close($dupe);
            if ($attachment_path !== '' && file_exists(__DIR__ . '/../' . $attachment_path)) {
                @unlink(__DIR__ . '/../' . $attachment_path);
            }
            fail('Duplicate submission detected. The same complaint was submitted recently.');
        }
        mysqli_stmt_close($dupe);
    }
}

// ── 5. Insert complaint ───────────────────────────────────────────────────────
$has_attachment = column_exists($conn, 'complaints', 'attachment');
$has_public     = column_exists($conn, 'complaints', 'is_public');

$columns = ['user_email', 'category', 'description', 'status'];
$values  = [$session_email, $category, $description, $status];  // session_email, not post_email
$types   = 'ssss';

if ($has_attachment) {
    $columns[] = 'attachment';
    $values[]  = $attachment_path;
    $types    .= 's';
}

if ($has_public) {
    $columns[] = 'is_public';
    $values[]  = $is_public;
    $types    .= 'i';
}

$placeholder = implode(', ', array_fill(0, count($columns), '?'));
$column_sql  = implode(', ', $columns);
$sql         = "INSERT INTO complaints ({$column_sql}) VALUES ({$placeholder})";

$stmt = mysqli_prepare($conn, $sql);
if (!$stmt) {
    security_log('SUBMIT_COMPLAINT_PREPARE_FAIL', ['user_id' => $session_uid]);
    fail('Unable to submit complaint. Please try again.', 500);
}

mysqli_stmt_bind_param($stmt, $types, ...$values);

if (mysqli_stmt_execute($stmt)) {
    security_log('COMPLAINT_SUBMITTED', [
        'user_id'  => $session_uid,
        'category' => $category,
    ]);
    mysqli_stmt_close($stmt);
    echo 'Complaint submitted successfully.';
} else {
    mysqli_stmt_close($stmt);
    security_log('COMPLAINT_INSERT_FAIL', ['user_id' => $session_uid]);
    fail('Error submitting complaint. Please try again.', 500);
}