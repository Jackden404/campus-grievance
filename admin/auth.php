<?php
// ─── hardened auth.php ────────────────────────────────────────────────────────
// Include BEFORE any output. Sets secure session cookie params.
require_once __DIR__ . '/../php/csrf.php'; // csrf.php also sets session cookie params

function require_admin(): void {
    ensure_session_started();

    $is_admin        = !empty($_SESSION['is_admin']) && $_SESSION['is_admin'] === true;
    $logged_in_at    = $_SESSION['admin_logged_in_at'] ?? 0;
    $session_timeout = 3600; // 1 hour absolute timeout — adjust as needed

    // ── Check admin flag ───────────────────────────────────────────────────────
    if (!$is_admin) {
        if (function_exists('security_log')) {
            security_log('ADMIN_ACCESS_DENIED', [
                'uri' => $_SERVER['REQUEST_URI'] ?? '',
                'reason' => 'not_admin',
            ]);
        }
        header('Location: admin_login.html');
        exit;
    }

    // ── Absolute session timeout ───────────────────────────────────────────────
    if ((time() - $logged_in_at) > $session_timeout) {
        // Expire the session and force re-login
        $_SESSION = [];
        session_destroy();
        if (function_exists('security_log')) {
            security_log('ADMIN_SESSION_EXPIRED', ['uri' => $_SERVER['REQUEST_URI'] ?? '']);
        }
        header('Location: admin_login.html?reason=timeout');
        exit;
    }

    // ── Refresh last-active timestamp (for future idle-timeout extension) ──────
    $_SESSION['admin_last_active'] = time();
}
