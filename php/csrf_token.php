<?php
include "csrf.php";

header("Content-Type: application/json");

$token = csrf_token();
echo json_encode(array("success" => true, "csrf_token" => $token));
?>
