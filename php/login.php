<?php
include "connect.php";
include "csrf.php";

if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    http_response_code(405);
    exit("Method not allowed.");
}

require_csrf_token();

$email = trim($_POST['email'] ?? '');
$password = $_POST['password'] ?? '';

if (!filter_var($email, FILTER_VALIDATE_EMAIL) || $password === "") {
    http_response_code(400);
    exit("Invalid Email or Password");
}

$stmt = mysqli_prepare($conn, "SELECT id, password FROM users WHERE email = ? LIMIT 1");
if (!$stmt) {
    http_response_code(500);
    exit("Login failed.");
}

mysqli_stmt_bind_param($stmt, "s", $email);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);

if ($result && mysqli_num_rows($result) === 1) {
    $user = mysqli_fetch_assoc($result);
    $stored = $user["password"];
    $is_valid = password_verify($password, $stored);

    if (!$is_valid && hash_equals($stored, $password)) {
        $new_hash = password_hash($password, PASSWORD_DEFAULT);
        $update_stmt = mysqli_prepare($conn, "UPDATE users SET password = ? WHERE id = ?");
        if ($update_stmt) {
            $user_id = (int)$user["id"];
            mysqli_stmt_bind_param($update_stmt, "si", $new_hash, $user_id);
            mysqli_stmt_execute($update_stmt);
            mysqli_stmt_close($update_stmt);
        }
        $is_valid = true;
    }

    if ($is_valid) {
        mysqli_stmt_close($stmt);
        ensure_session_started();
        session_regenerate_id(true);
        $_SESSION["user_email"] = $email;
        $_SESSION["user_id"] = (int)$user["id"];
        header("Location: ../dashboard.html");
        exit;
    }
}

mysqli_stmt_close($stmt);
http_response_code(401);
exit("Invalid Email or Password");
?>