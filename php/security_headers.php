<?php
// =====================================================
// Security Headers — include BEFORE session_start()
// =====================================================

// ── Secure session cookie parameters ─────────────────
// Must be set before any session_start() call.
$cookie_params = [
    'lifetime' => 0,             // session cookie (browser-session only)
    'path'     => '/',
    'domain'   => '',            // empty = current hostname only
    'secure'   => false,         // set to TRUE once you have HTTPS
    'httponly' => true,          // never accessible from JavaScript
    'samesite' => 'Strict',      // blocks CSRF from cross-origin requests
];
session_set_cookie_params($cookie_params);

// Session name — harder to fingerprint than the default "PHPSESSID"
session_name('cgpsid');

// ── HTTP Security Headers ─────────────────────────────
function send_security_headers(): void {
    // Prevent clickjacking
    header('X-Frame-Options: DENY');

    // Prevent MIME-type sniffing
    header('X-Content-Type-Options: nosniff');

    // Stop built-in XSS filter quirks (modern browsers use CSP instead)
    header('X-XSS-Protection: 0');

    // Referrer policy — don't leak URL params to third parties
    header('Referrer-Policy: strict-origin-when-cross-origin');

    // Permissions policy — disable sensors not needed by this app
    header('Permissions-Policy: camera=(), microphone=(), geolocation=()');

    // Content Security Policy
    // Adjust hash/nonce approach if you add inline scripts later.
    header(
        "Content-Security-Policy: " .
        "default-src 'self'; " .
        "script-src 'self' https://cdn.jsdelivr.net; " .
        "style-src  'self' https://cdn.jsdelivr.net https://fonts.googleapis.com; " .
        "font-src   'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; " .
        "img-src    'self' data:; " .
        "connect-src 'self'; " .
        "frame-ancestors 'none'; " .
        "form-action 'self';"
    );

    // HSTS — comment out until HTTPS is fully in place
    // header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');

    // Hide PHP version (belt-and-suspenders with php.ini expose_php=Off)
    header_remove('X-Powered-By');
}

send_security_headers();
