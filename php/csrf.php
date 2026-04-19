<?php
// ─── CRITICAL: set secure cookie params BEFORE session_start ─────────────────
// Keep in sync with security_headers.php
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'domain'   => '',
    'secure'   => false,   // flip to TRUE once HTTPS is live
    'httponly' => true,
    'samesite' => 'Strict',
]);
session_name('cgpsid');

function ensure_session_started(): void {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
}

// ── CSRF helpers ──────────────────────────────────────────────────────────────

/**
 * Return (and lazily create) the session-bound CSRF token.
 * Token is tied to the session, so a fresh session = fresh token.
 */
function csrf_token(): string {
    ensure_session_started();
    if (empty($_SESSION['csrf_token']) || !is_string($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Verify the CSRF token on every mutating request.
 * Accepts the token from a POST field OR an HTTP header (for fetch() calls).
 * Exits with 403 on failure.
 */
function require_csrf_token(): void {
    ensure_session_started();

    // Accept from hidden form field OR from X-CSRF-Token header (AJAX)
    $submitted = $_POST['csrf_token']
               ?? ($_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');

    $session_token = $_SESSION['csrf_token'] ?? '';

    if ($submitted === ''
        || $session_token === ''
        || !hash_equals($session_token, $submitted)
    ) {
        http_response_code(403);
        // Log if the security_log module is loaded
        if (function_exists('security_log')) {
            security_log('CSRF_FAIL', ['uri' => $_SERVER['REQUEST_URI'] ?? '']);
        }
        exit('Invalid or missing CSRF token.');
    }
}

/**
 * Rotate the CSRF token after each successful state-changing request
 * to prevent token-fixation attacks.
 */
function rotate_csrf_token(): void {
    ensure_session_started();
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
