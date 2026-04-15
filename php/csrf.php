<?php
function ensure_session_started() {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
}

function csrf_token() {
    ensure_session_started();
    if (empty($_SESSION["csrf_token"])) {
        $_SESSION["csrf_token"] = bin2hex(random_bytes(32));
    }
    return $_SESSION["csrf_token"];
}

function require_csrf_token() {
    ensure_session_started();
    $token = $_POST["csrf_token"] ?? ($_SERVER["HTTP_X_CSRF_TOKEN"] ?? "");
    $session_token = $_SESSION["csrf_token"] ?? "";

    if ($token === "" || $session_token === "" || !hash_equals($session_token, $token)) {
        http_response_code(403);
        exit("Invalid CSRF token.");
    }
}
?>
