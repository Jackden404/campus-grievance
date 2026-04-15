<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

function require_admin() {
    if (empty($_SESSION["is_admin"])) {
        header("Location: admin_login.html");
        exit;
    }
}
?>
