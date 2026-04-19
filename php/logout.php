<?php
include '../php/security_headers.php'; // Sets HTTP headers
include '../php/security_log.php';
include '../php/csrf.php';             // ensure_session_started() + cookie params

ensure_session_started();
security_log('LOGOUT', ['user_id' => $_SESSION['user_id'] ?? $_SESSION['admin_username'] ?? 'unknown']);

// Remove all session data
$_SESSION  = [];

// Destroy the session cookie in the browser
if (ini_get('session.use_cookies')) {
    $params = session_get_cookie_params();
    setcookie(
        session_name(),
        '',
        time() - 42000,
        $params['path'],
        $params['domain'],
        $params['secure'],
        $params['httponly']
    );
}

session_destroy();

header('Location: ../login.html');
exit;
