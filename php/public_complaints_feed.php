<?php
include 'security_headers.php';
include 'connect.php';

header('Content-Type: application/json');

// ── Public read-only endpoint — no auth required ───────────────────────────────
// Rate-limit to prevent scraping / DoS
include 'rate_limit.php';
$rl_key = 'public_feed_' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown');
rate_limit($rl_key, 60, 60); // 60 requests per minute per IP

// Only GET is sensible for a feed
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Method not allowed']);
    exit;
}

// Cache-control: allow CDN / browser to cache for 30 seconds
header('Cache-Control: public, max-age=30');

function col_exists(mysqli $conn, string $table, string $col): bool {
    $t = mysqli_real_escape_string($conn, $table);
    $c = mysqli_real_escape_string($conn, $col);
    $r = mysqli_query($conn, "SHOW COLUMNS FROM `{$t}` LIKE '{$c}'");
    return $r && mysqli_num_rows($r) > 0;
}

function tbl_exists(mysqli $conn, string $table): bool {
    $t = mysqli_real_escape_string($conn, $table);
    $r = mysqli_query($conn, "SHOW TABLES LIKE '{$t}'");
    return $r && mysqli_num_rows($r) > 0;
}

if (!col_exists($conn, 'complaints', 'is_public')) {
    echo json_encode(['success' => false, 'message' => 'Public complaints not configured.', 'data' => []]);
    exit;
}

if (!tbl_exists($conn, 'complaint_votes')) {
    echo json_encode(['success' => false, 'message' => 'Voting not configured.', 'data' => []]);
    exit;
}

$has_created_at = col_exists($conn, 'complaints', 'created_at');
$created_select = $has_created_at ? 'MAX(c.created_at)' : 'NULL';

// ── NOTE: user_email is intentionally excluded from the public feed ────────────
// Never expose PII (emails) in the public JSON response.
$sql = "SELECT MIN(c.id) AS id, c.category, c.description,
               {$created_select} AS created_at,
               COUNT(DISTINCT v.voter_email) AS upvotes
        FROM complaints c
        LEFT JOIN complaint_votes v ON v.complaint_id = c.id
        WHERE c.is_public = 1
        GROUP BY c.category, c.description
        ORDER BY upvotes DESC, created_at DESC, id DESC
        LIMIT 10";

$result = mysqli_query($conn, $sql);
$data   = [];

if (!$result) {
    echo json_encode(['success' => false, 'message' => 'Failed to load public complaints']);
    exit;
}

while ($row = mysqli_fetch_assoc($result)) {
    $data[] = [
        'id'          => (int)$row['id'],
        // Escape at the source; the JS layer also escapes on render
        'category'    => htmlspecialchars((string)$row['category'],    ENT_QUOTES, 'UTF-8'),
        'description' => htmlspecialchars((string)$row['description'], ENT_QUOTES, 'UTF-8'),
        'created_at'  => $row['created_at'],
        'upvotes'     => (int)$row['upvotes'],
    ];
}

echo json_encode(['success' => true, 'data' => $data]);
