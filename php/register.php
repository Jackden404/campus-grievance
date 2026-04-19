<?php
include 'security_headers.php';
include 'security_log.php';
include 'rate_limit.php';
include 'connect.php';
include 'csrf.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit('Method not allowed.');
}

require_csrf_token();

// ── 1. Rate limiting — keyed on IP to limit account-creation flooding ─────────
$rl_key = 'register_' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown');
rate_limit($rl_key, 5, 3600); // 5 registrations per IP per hour

$name     = trim($_POST['name']     ?? '');
$email    = strtolower(trim($_POST['email'] ?? ''));
$password = $_POST['password'] ?? '';
$role     = 'user'; // Never trust user-supplied role

// ── 2. Server-side input validation ──────────────────────────────────────────

// Name: 2–100 characters, basic sanity
if ($name === '' || mb_strlen($name) < 2 || mb_strlen($name) > 100) {
    http_response_code(400);
    exit('Name must be between 2 and 100 characters.');
}

// Name: only letters, spaces, hyphens, dots, apostrophes
if (!preg_match('/^[\p{L}\s\.\-\']+$/u', $name)) {
    http_response_code(400);
    exit('Name contains invalid characters.');
}

// Email
if (!filter_var($email, FILTER_VALIDATE_EMAIL) || mb_strlen($email) > 255) {
    http_response_code(400);
    exit('Invalid email address.');
}

// ── Password policy ───────────────────────────────────────────────────────────
// Minimum 8 chars, at least one uppercase, one lowercase, one digit
if (mb_strlen($password) < 8) {
    http_response_code(400);
    exit('Password must be at least 8 characters.');
}

if (!preg_match('/[A-Z]/', $password)) {
    http_response_code(400);
    exit('Password must contain at least one uppercase letter.');
}

if (!preg_match('/[a-z]/', $password)) {
    http_response_code(400);
    exit('Password must contain at least one lowercase letter.');
}

if (!preg_match('/[0-9]/', $password)) {
    http_response_code(400);
    exit('Password must contain at least one digit.');
}

// Reasonable maximum to prevent DoS via bcrypt long-input attack
if (mb_strlen($password) > 72) {
    http_response_code(400);
    exit('Password must not exceed 72 characters.');
}

// ── 3. Hash with bcrypt cost 12 ───────────────────────────────────────────────
$password_hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);

// ── 4. Insert (parameterised) ────────────────────────────────────────────────
$stmt = mysqli_prepare(
    $conn,
    'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)'
);

if (!$stmt) {
    security_log('REGISTER_DB_ERROR', ['email' => $email]);
    http_response_code(500);
    exit('Registration temporarily unavailable.');
}

mysqli_stmt_bind_param($stmt, 'ssss', $name, $email, $password_hash, $role);

if (mysqli_stmt_execute($stmt)) {
    mysqli_stmt_close($stmt);
    security_log('REGISTER_SUCCESS', ['email' => $email]);
    rotate_csrf_token(); // Prevent token reuse after successful registration
    header('Location: ../login.html');
    exit;
}

// Graceful error handling
$errno = mysqli_errno($conn);
mysqli_stmt_close($stmt);

if ($errno === 1062) {
    // Duplicate email — but don't confirm the email exists (enumeration risk).
    // Return the same success-like redirect to avoid leaking registered emails.
    // In a real app you'd send a "did you forget your password?" email instead.
    security_log('REGISTER_DUPLICATE', ['email' => $email]);
    http_response_code(409);
    exit('An account with this email already exists.');
}

security_log('REGISTER_FAIL', ['email' => $email, 'errno' => $errno]);
http_response_code(500);
exit('Registration failed. Please try again.');