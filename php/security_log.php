<?php
// =====================================================
// Security Logger — append-only, structured log file
// =====================================================

// Log directory — OUTSIDE the web root in production.
// For XAMPP dev this writes next to the php/ folder.
define('LOG_FILE', __DIR__ . '/../logs/security.log');

/**
 * Append an event to the security log.
 *
 * @param string $event   Short event name, e.g. "LOGIN_FAIL", "CSRF_FAIL"
 * @param array  $context Associative array of extra data (email, ip, etc.)
 */
function security_log(string $event, array $context = []): void {
    $log_dir = dirname(LOG_FILE);
    if (!is_dir($log_dir)) {
        mkdir($log_dir, 0700, true);
    }

    // Never log raw passwords — strip them from context
    foreach (['password', 'password_hash', 'pass', 'secret', 'token'] as $sensitive) {
        if (isset($context[$sensitive])) {
            $context[$sensitive] = '[REDACTED]';
        }
    }

    $ip = filter_var(
        $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        FILTER_VALIDATE_IP
    ) ?: 'unknown';

    $entry = json_encode([
        'ts'    => date('c'),          // ISO-8601 timestamp
        'event' => $event,
        'ip'    => $ip,
        'ctx'   => $context,
    ]);

    file_put_contents(LOG_FILE, $entry . PHP_EOL, FILE_APPEND | LOCK_EX);
}
