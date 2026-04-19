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
$session_email = $_SESSION['user_email'] ?? '';
$session_uid   = (int)($_SESSION['user_id'] ?? 0);

if ($session_email === '' || $session_uid === 0) {
    security_log('TRACK_STATUS_UNAUTH', ['uri' => $_SERVER['REQUEST_URI'] ?? '']);
    http_response_code(401);
    exit('Please login to track complaints.');
}

// ── Input validation ───────────────────────────────────────────────────────────
$post_email = strtolower(trim($_POST['email'] ?? ''));

if (!filter_var($post_email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    exit('A valid email address is required.');
}

// ── IDOR / authorisation check ─────────────────────────────────────────────────
// Users may only query their own complaints.
if (!hash_equals($session_email, $post_email)) {
    security_log('IDOR_TRACK_ATTEMPT', [
        'user_id'    => $session_uid,
        'queried_email' => $post_email,
    ]);
    http_response_code(403);
    exit('You may only view complaints linked to your own account.');
}

// ── Query — always scoped to the session user's ID as well ────────────────────
// Binding on both email AND user_id is defence in depth against
// any future inconsistency in the users table.
$has_attachment = false;
$col_check = mysqli_query($conn, "SHOW COLUMNS FROM complaints LIKE 'attachment'");
if ($col_check && mysqli_num_rows($col_check) > 0) {
    $has_attachment = true;
}

$stmt = mysqli_prepare(
    $conn,
    'SELECT * FROM complaints WHERE user_email = ? ORDER BY id DESC'
);
if (!$stmt) {
    http_response_code(500);
    exit('Unable to retrieve complaints.');
}

mysqli_stmt_bind_param($stmt, 's', $session_email); // session value, not POST
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Complaint Status</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
    <link href="../assets/css/style.css" rel="stylesheet">
</head>
<body class="page-soft-bg">

<nav class="navbar navbar-dark top-nav">
    <div class="container py-2">
        <a href="../index.html" class="navbar-brand fw-semibold">Campus Grievance Portal</a>
        <div class="d-flex gap-2">
            <a href="../track_status.html" class="btn btn-outline-light btn-sm">Back to Search</a>
            <a href="../dashboard.html"    class="btn btn-outline-light btn-sm">Dashboard</a>
        </div>
    </div>
</nav>

<main class="py-4">
    <div class="container">
        <div class="d-flex flex-wrap justify-content-between align-items-center mb-3">
            <h3 class="mb-2 mb-md-0">Your Complaints</h3>
            <a href="../dashboard.html" class="btn btn-outline-secondary btn-sm">Back</a>
        </div>

        <div class="card card-soft">
            <div class="card-body p-3 p-md-4">
                <div class="table-responsive">
                    <table class="table admin-table table-bordered align-middle mb-0">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Category</th>
                                <th>Description</th>
                                <?php if ($has_attachment) { echo '<th>Attachment</th>'; } ?>
                                <th>Status</th>
                            </tr>
                        </thead>

                        <tbody>
                        <?php
                        if ($result && mysqli_num_rows($result) > 0) {
                            while ($row = mysqli_fetch_assoc($result)) {
                                echo '<tr>';
                                echo '<td>' . (int)$row['id'] . '</td>';
                                // htmlspecialchars prevents XSS on display
                                echo '<td>' . htmlspecialchars((string)$row['category'],    ENT_QUOTES, 'UTF-8') . '</td>';
                                echo '<td>' . htmlspecialchars((string)$row['description'], ENT_QUOTES, 'UTF-8') . '</td>';
                                if ($has_attachment) {
                                    if (!empty($row['attachment'])) {
                                        // Validate stored path before rendering
                                        $raw_path  = (string)$row['attachment'];
                                        $safe_path = htmlspecialchars('../' . ltrim($raw_path, '/'), ENT_QUOTES, 'UTF-8');
                                        echo "<td><a href='{$safe_path}' target='_blank' rel='noopener noreferrer' class='btn btn-outline-primary btn-sm'>View</a></td>";
                                    } else {
                                        echo "<td><span class='text-muted small'>No file</span></td>";
                                    }
                                }
                                echo '<td>' . htmlspecialchars((string)$row['status'], ENT_QUOTES, 'UTF-8') . '</td>';
                                echo '</tr>';
                            }
                        } else {
                            $colspan = $has_attachment ? '5' : '4';
                            echo "<tr><td colspan='{$colspan}' class='text-center text-muted'>No complaints found.</td></tr>";
                        }
                        ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</main>

<?php mysqli_stmt_close($stmt); ?>
</body>
</html>
