<?php
// =====================================================
// Rate Limiter — file-based, zero dependencies
// Protects login / register endpoints from brute-force
// =====================================================

/**
 * Check and record an attempt for the given key.
 *
 * @param  string $key        Unique identifier, e.g. "login_{email}" or "login_{ip}"
 * @param  int    $max        Maximum attempts allowed in the window
 * @param  int    $window_sec Window duration in seconds
 * @return void   Exits with HTTP 429 if the limit is exceeded
 */
function rate_limit(string $key, int $max = 5, int $window_sec = 900): void {
    // Store rate-limit files in a directory that is NOT web-accessible.
    // Adjust the path if your layout differs.
    $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'cgp_rate_limits';

    if (!is_dir($dir)) {
        mkdir($dir, 0700, true);
    }

    // Sanitise the key so it maps to a safe filename
    $safe_key = preg_replace('/[^a-zA-Z0-9_@.\-]/', '_', $key);
    $file     = $dir . DIRECTORY_SEPARATOR . $safe_key . '.json';

    $now      = time();
    $attempts = [];

    if (file_exists($file)) {
        $raw = file_get_contents($file);
        $all = json_decode($raw, true);
        if (is_array($all)) {
            // Keep only attempts within the current window
            $attempts = array_filter($all, fn($ts) => ($now - $ts) < $window_sec);
            $attempts = array_values($attempts);
        }
    }

    if (count($attempts) >= $max) {
        $retry_after = $window_sec - ($now - min($attempts));
        http_response_code(429);
        header("Retry-After: $retry_after");
        exit("Too many attempts. Please wait " . ceil($retry_after / 60) . " minute(s) before trying again.");
    }

    // Record this attempt
    $attempts[] = $now;
    file_put_contents($file, json_encode($attempts), LOCK_EX);
}

/**
 * Clear the rate-limit counter for a key (call after successful login).
 *
 * @param string $key The same key used in rate_limit()
 */
function rate_limit_clear(string $key): void {
    $dir      = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'cgp_rate_limits';
    $safe_key = preg_replace('/[^a-zA-Z0-9_@.\-]/', '_', $key);
    $file     = $dir . DIRECTORY_SEPARATOR . $safe_key . '.json';
    if (file_exists($file)) {
        @unlink($file);
    }
}
