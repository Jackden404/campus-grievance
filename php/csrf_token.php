<?php
include 'security_headers.php';
include 'security_log.php';
include 'connect.php';
include 'csrf.php';

// ── CSRF token is needed by the page; include it safely ─────────────────────
header('Content-Type: application/json');

// Only allow GET (reading the token) — reject everything else
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    echo json_encode(['success' => false, 'error' => 'Method not allowed']);
    exit;
}

// Require the X-Requested-With header so browsers (but not naive scripts)
// can call this endpoint. This is defence in depth — not the primary CSRF defence.
if (($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '') !== 'XMLHttpRequest') {
    http_response_code(403);
    echo json_encode(['success' => false, 'error' => 'Forbidden']);
    exit;
}

$token = csrf_token();

// Cache-control: token should never be cached
header('Cache-Control: no-store, no-cache, must-revalidate');
header('Pragma: no-cache');

echo json_encode(['success' => true, 'csrf_token' => $token]);
