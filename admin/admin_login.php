<?php
include "../php/csrf.php";

if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    http_response_code(405);
    exit("Method not allowed.");
}

require_csrf_token();
ensure_session_started();

$username = trim($_POST["username"] ?? "");
$password = $_POST["password"] ?? "";

$valid_user = "admin";
$valid_pass = "admin123";

if (hash_equals($valid_user, $username) && hash_equals($valid_pass, $password)) {
    session_regenerate_id(true);
    $_SESSION["is_admin"] = true;
    $_SESSION["admin_username"] = $username;
    header("Location: admin_dashboard.php");
    exit;
}

http_response_code(401);
echo "Invalid admin credentials.";
?>