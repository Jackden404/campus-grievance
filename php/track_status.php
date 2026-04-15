<?php
include "connect.php";
include "csrf.php";

if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    http_response_code(405);
    exit("Method not allowed.");
}

require_csrf_token();
ensure_session_started();

$email = trim($_POST['email'] ?? '');
$session_email = $_SESSION["user_email"] ?? "";

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    exit("Valid email is required.");
}

if ($session_email === "") {
    http_response_code(401);
    exit("Please login to track complaints.");
}

if (!hash_equals($session_email, $email)) {
    http_response_code(403);
    exit("You can view complaints only for your logged-in account.");
}

$has_attachment_column = false;
$column_check = mysqli_query($conn, "SHOW COLUMNS FROM complaints LIKE 'attachment'");
if ($column_check && mysqli_num_rows($column_check) > 0) {
    $has_attachment_column = true;
}

$stmt = mysqli_prepare($conn, "SELECT * FROM complaints WHERE user_email = ? ORDER BY id DESC");
mysqli_stmt_bind_param($stmt, "s", $email);
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
    <link href="../assets/css/style.css" rel="stylesheet">
</head>
<body class="page-soft-bg">

<nav class="navbar navbar-dark top-nav">
    <div class="container py-2">
        <a href="../index.html" class="navbar-brand fw-semibold">Campus Grievance Portal</a>
        <div class="d-flex gap-2">
            <a href="../track_status.html" class="btn btn-outline-light btn-sm">Back to Search</a>
            <a href="../dashboard.html" class="btn btn-outline-light btn-sm">Dashboard</a>
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
                                <?php if ($has_attachment_column) { echo "<th>Attachment</th>"; } ?>
                                <th>Status</th>
                            </tr>
                        </thead>

                        <tbody>
                        <?php
                        if ($result && mysqli_num_rows($result) > 0) {
                            while ($row = mysqli_fetch_assoc($result)) {
                                echo "<tr>";
                                echo "<td>" . (int)$row['id'] . "</td>";
                                echo "<td>" . htmlspecialchars($row['category']) . "</td>";
                                echo "<td>" . htmlspecialchars($row['description']) . "</td>";
                                if ($has_attachment_column) {
                                    if (!empty($row['attachment'])) {
                                        $file = htmlspecialchars("../" . ltrim($row['attachment'], '/'));
                                        echo "<td><a href='" . $file . "' target='_blank' rel='noopener' class='btn btn-outline-primary btn-sm'>View</a></td>";
                                    } else {
                                        echo "<td><span class='text-muted small'>No file</span></td>";
                                    }
                                }
                                echo "<td>" . htmlspecialchars($row['status']) . "</td>";
                                echo "</tr>";
                            }
                        } else {
                            $colspan = $has_attachment_column ? "5" : "4";
                            echo "<tr><td colspan='" . $colspan . "' class='text-center text-muted'>No complaints found</td></tr>";
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
