<?php


header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

require_once '../../../includes/config.php';

if($conn->connect_error){
    http_response_code(500);
    echo json_encode(["status" => "error", "message" => "Database connection failed"]);
    exit;
}

// Adjust table/column name if needed

$sql  = "SELECT id, first_name, last_name, email, phone, role, created_at, is_blocked FROM users ORDER BY created_at DESC";
$result = $conn->query($sql);

$users = [];

if($result && $result->num_rows > 0){
    while($row = $result->fetch_assoc()){
        $users[] = $row;
    }
}

echo json_encode([
    "status" => "success",
    "count" => count($users),
    "data" => $users
]);

$conn->close();

?>