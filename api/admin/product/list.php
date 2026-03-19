<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

// Include database configuration
require_once '../../../includes/config.php';

// Check database connection
if ($conn->connect_error) {
    http_response_code(500);
    echo json_encode(["status" => "error", "message" => "Database connection failed"]);
    exit;
}

// Fetch products
$sql = "SELECT * FROM products ORDER BY created_at DESC";
$result = $conn->query($sql);

$products = [];

if ($result && $result->num_rows > 0) {
    while($row = $result->fetch_assoc()) {
        $products[] = $row;
    }
}

echo json_encode([
    "status" => "success",
    "count" => count($products),
    "data" => $products
]);

$conn->close();
?>
