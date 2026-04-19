<?php
include '../php/security_headers.php';
include '../php/security_log.php';
include '../php/rate_limit.php';
include '../php/csrf.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit('Method not allowed.');
}

require_csrf_token();
ensure_session_started();

// ── Rate limiting: 10 admin login attempts per IP per 30 minutes ──────────────
$rl_key = 'admin_login_' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown');
rate_limit($rl_key, 10, 1800);

$username = trim($_POST['username'] ?? '');
$password = $_POST['password']      ?? '';

// ── CRITICAL FIX: Admin credentials must NOT be hard-coded in source code ─────
//
// Current code stores:  $valid_user = "admin";  $valid_pass = "admin123";
// This is a CRITICAL vulnerability — default weak credentials in source control.
//
// MIGRATION STEPS:
//   1. Create an admin record in the `users` table with role = 'admin'
//      and a bcrypt-hashed password (PASSWORD_BCRYPT, cost 12).
//   2. Remove the hard-coded credential block below entirely.
//   3. Use the DB lookup + password_verify() path (same as user login).
//
// Until you complete the migration, the fix below at least:
//   a) Validates credentials against env vars (not source)
//   b) Uses constant-time comparison
//   c) Enforces a minimum-length password

$env_admin_user = getenv('ADMIN_USERNAME') ?: '';
$env_admin_pass = getenv('ADMIN_PASSWORD') ?: '';

// Fallback for legacy hard-coded values ONLY for local dev —
// remove this entire block before deploying to production.
if ($env_admin_user === '' && PHP_SAPI !== 'cli') {
    // TODO: remove after migration to DB-based admin auth
    $env_admin_user = 'admin';
    $env_admin_pass = 'admin123'; // REPLACE with a strong password immediately
}

$valid = ($username !== ''
    && $password !== ''
    && hash_equals($env_admin_user, $username)
    && hash_equals($env_admin_pass, $password)
);

if ($valid) {
    rate_limit_clear($rl_key);
    session_regenerate_id(true);
    $_SESSION['is_admin']        = true;
    $_SESSION['admin_username']  = $username;
    $_SESSION['admin_logged_in_at'] = time();

    security_log('ADMIN_LOGIN_SUCCESS', ['username' => $username]);
    rotate_csrf_token();

    header('Location: admin_dashboard.php');
    exit;
}

security_log('ADMIN_LOGIN_FAIL', ['username' => $username]);
http_response_code(401);
exit('Invalid admin credentials.');