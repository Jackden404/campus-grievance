<?php
// =============================================
// COPY this file and rename it to connect.php
// Then fill in your own database details below
// =============================================

$servername = "localhost";       // usually 'localhost'
$username   = "root";            // your DB username
$password   = "";                // your DB password
$database   = "campus_grievance"; // your DB name

$conn = mysqli_connect($servername, $username, $password, $database);

if (!$conn) {
    http_response_code(500);
    exit("Database connection failed.");
}

mysqli_set_charset($conn, "utf8mb4");
?>
