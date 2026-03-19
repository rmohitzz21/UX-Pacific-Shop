<?php

require_once '../../../includes/config.php';

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');
header('Access-Control-Allow-Headers: Content-Type');


if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['status' => 'error', 'message' => 'Invalid request method']);
    exit;
}


$id = $_POST['id'];
if(!$id)
{
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Product ID is required']);
    exit;
}


$stmt = $conn->prepare("DELETE FROM products WHERE id = ?");
$stmt->bind_param("i", $id);

if($stmt->execute())
{
    http_response_code(200);
    echo json_encode(['status' => 'success', 'message' => 'Product deleted successfully']);
    exit;
}
else
{
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Failed to delete product']);
    exit;
}

$stmt->close();
$conn->close();

?>