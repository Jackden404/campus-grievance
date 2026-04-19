<?php
include 'security_headers.php';
include 'security_log.php';
include 'connect.php';
include 'csrf.php';

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Method not allowed']);
    exit;
}

require_csrf_token();

// ── Rate limiting on upvote (prevent vote spam per IP) ─────────────────────────
include 'rate_limit.php';
$rl_key = 'upvote_' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown');
rate_limit($rl_key, 20, 300); // 20 upvotes per 5 minutes per IP

function column_exists_local(mysqli $conn, string $table, string $col): bool {
    $t = mysqli_real_escape_string($conn, $table);
    $c = mysqli_real_escape_string($conn, $col);
    $r = mysqli_query($conn, "SHOW COLUMNS FROM `{$t}` LIKE '{$c}'");
    return $r && mysqli_num_rows($r) > 0;
}

function table_exists_local(mysqli $conn, string $table): bool {
    $t = mysqli_real_escape_string($conn, $table);
    $r = mysqli_query($conn, "SHOW TABLES LIKE '{$t}'");
    return $r && mysqli_num_rows($r) > 0;
}

if (!column_exists_local($conn, 'complaints', 'is_public')) {
    echo json_encode(['success' => false, 'message' => 'Public complaints feature is not configured']);
    exit;
}

if (!table_exists_local($conn, 'complaint_votes')) {
    echo json_encode(['success' => false, 'message' => 'Voting table is not configured']);
    exit;
}

// ── Input validation ───────────────────────────────────────────────────────────
$complaint_id = isset($_POST['complaint_id']) ? (int)$_POST['complaint_id'] : 0;
$voter_email  = strtolower(trim($_POST['voter_email'] ?? ''));

if ($complaint_id <= 0) {
    echo json_encode(['success' => false, 'message' => 'Invalid complaint ID']);
    exit;
}

if (!filter_var($voter_email, FILTER_VALIDATE_EMAIL)) {
    echo json_encode(['success' => false, 'message' => 'A valid email is required to upvote']);
    exit;
}

// ── Verify the complaint is public (prevents IDOR — can't upvote private ones) ─
$check = mysqli_prepare($conn, 'SELECT id FROM complaints WHERE id = ? AND is_public = 1 LIMIT 1');
if (!$check) {
    echo json_encode(['success' => false, 'message' => 'Server error']);
    exit;
}
mysqli_stmt_bind_param($check, 'i', $complaint_id);
mysqli_stmt_execute($check);
$check_result = mysqli_stmt_get_result($check);

if (!$check_result || mysqli_num_rows($check_result) === 0) {
    mysqli_stmt_close($check);
    echo json_encode(['success' => false, 'message' => 'Complaint not available for public voting']);
    exit;
}
mysqli_stmt_close($check);

// ── Record vote (INSERT IGNORE = one vote per email per complaint) ────────────
$insert = mysqli_prepare(
    $conn,
    'INSERT IGNORE INTO complaint_votes (complaint_id, voter_email) VALUES (?, ?)'
);
if (!$insert) {
    echo json_encode(['success' => false, 'message' => 'Server error']);
    exit;
}
mysqli_stmt_bind_param($insert, 'is', $complaint_id, $voter_email);
mysqli_stmt_execute($insert);
$rows_changed = mysqli_stmt_affected_rows($insert);
mysqli_stmt_close($insert);

// ── Tally votes ───────────────────────────────────────────────────────────────
$count_stmt = mysqli_prepare(
    $conn,
    'SELECT COUNT(*) AS total_votes FROM complaint_votes WHERE complaint_id = ?'
);
mysqli_stmt_bind_param($count_stmt, 'i', $complaint_id);
mysqli_stmt_execute($count_stmt);
$count_result = mysqli_stmt_get_result($count_stmt);
$vote_total   = 0;
if ($count_result) {
    $row        = mysqli_fetch_assoc($count_result);
    $vote_total = (int)$row['total_votes'];
}
mysqli_stmt_close($count_stmt);

if ($rows_changed > 0) {
    echo json_encode(['success' => true, 'message' => 'Upvote added', 'upvotes' => $vote_total]);
} else {
    echo json_encode(['success' => true, 'message' => 'You have already upvoted this complaint', 'upvotes' => $vote_total]);
}