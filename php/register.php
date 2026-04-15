<?php
include "connect.php";
include "csrf.php";

if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    http_response_code(405);
    exit("Method not allowed.");
}

require_csrf_token();

$name = trim($_POST['name'] ?? '');
$email = trim($_POST['email'] ?? '');
$password = $_POST['password'] ?? '';
$role = "user";

if ($name === "" || !filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($password) < 6) {
    http_response_code(400);
    exit("Invalid registration input.");
}

$password_hash = password_hash($password, PASSWORD_DEFAULT);

$stmt = mysqli_prepare($conn, "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)");
if (!$stmt) {
    http_response_code(500);
    exit("Registration failed.");
}

mysqli_stmt_bind_param($stmt, "ssss", $name, $email, $password_hash, $role);

if (mysqli_stmt_execute($stmt)) {
    mysqli_stmt_close($stmt);
    header("Location: ../login.html");
    exit;
} else {
    mysqli_stmt_close($stmt);
    if (mysqli_errno($conn) === 1062) {
        http_response_code(409);
        exit("Email already registered.");
    }
    http_response_code(500);
    exit("Registration failed.");
}
?>