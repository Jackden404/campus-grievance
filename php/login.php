<?php
include 'security_headers.php'; // Sets HTTP security headers
include 'security_log.php';     // Structured logging
include 'rate_limit.php';       // Brute-force protection
include 'connect.php';
include 'csrf.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit('Method not allowed.');
}

require_csrf_token();

$email    = trim($_POST['email']    ?? '');
$password = $_POST['password']      ?? '';

// ── 1. Input validation ───────────────────────────────────────────────────────
if (!filter_var($email, FILTER_VALIDATE_EMAIL) || $password === '') {
    http_response_code(400);
    exit('Invalid email or password.');
}

// Normalise email to avoid case-based bypass
$email = strtolower($email);

// ── 2. Rate limiting — keyed on IP + email ────────────────────────────────────
// 5 attempts per 15-minute window per email address
$rl_key = 'login_' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown') . '_' . $email;
rate_limit($rl_key, 5, 900);

// ── 3. Lookup user ────────────────────────────────────────────────────────────
$stmt = mysqli_prepare($conn, 'SELECT id, password FROM users WHERE email = ? LIMIT 1');
if (!$stmt) {
    security_log('LOGIN_DB_ERROR', ['email' => $email]);
    http_response_code(500);
    exit('Login temporarily unavailable.');
}

mysqli_stmt_bind_param($stmt, 's', $email);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);
mysqli_stmt_close($stmt);

// ── 4. Constant-time credential check ────────────────────────────────────────
// We always call password_verify even when the user is not found
// to avoid timing-based user enumeration.
$dummy_hash = '$2y$12$usesomesillystringfore2uD1/pMGCBFkj0vEHEWTdGfFWlJvK6Ob1e'; // bcrypt dummy
$user       = ($result && mysqli_num_rows($result) === 1) ? mysqli_fetch_assoc($result) : null;
$stored_hash = $user ? $user['password'] : $dummy_hash;

$is_valid = password_verify($password, $stored_hash);

// Migration path: if stored hash is a plain-text legacy value, re-hash it
if (!$is_valid && $user && hash_equals((string)$stored_hash, $password)) {
    $new_hash    = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
    $upd         = mysqli_prepare($conn, 'UPDATE users SET password = ? WHERE id = ?');
    if ($upd) {
        $uid = (int)$user['id'];
        mysqli_stmt_bind_param($upd, 'si', $new_hash, $uid);
        mysqli_stmt_execute($upd);
        mysqli_stmt_close($upd);
    }
    $is_valid = true;
}

// ── 5. Rehash if bcrypt cost is outdated ──────────────────────────────────────
if ($is_valid && $user && password_needs_rehash($stored_hash, PASSWORD_BCRYPT, ['cost' => 12])) {
    $new_hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
    $upd      = mysqli_prepare($conn, 'UPDATE users SET password = ? WHERE id = ?');
    if ($upd) {
        $uid = (int)$user['id'];
        mysqli_stmt_bind_param($upd, 'si', $new_hash, $uid);
        mysqli_stmt_execute($upd);
        mysqli_stmt_close($upd);
    }
}

// ── 6. Session fixation prevention + session start ───────────────────────────
if ($is_valid && $user) {
    rate_limit_clear($rl_key);           // Reset the brute-force counter
    ensure_session_started();
    session_regenerate_id(true);         // New session ID on privilege change
    $_SESSION['user_email'] = $email;
    $_SESSION['user_id']    = (int)$user['id'];
    $_SESSION['logged_in_at'] = time();  // For absolute timeout enforcement

    security_log('LOGIN_SUCCESS', ['user_id' => (int)$user['id']]);

    header('Location: ../dashboard.html');
    exit;
}

// ── 7. Failed login: log and return generic error ─────────────────────────────
security_log('LOGIN_FAIL', ['email' => $email]);
http_response_code(401);
// Generic message — never reveal whether the email exists
exit('Invalid email or password.');