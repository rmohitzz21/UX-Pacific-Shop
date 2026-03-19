<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');

require_once '../../../includes/config.php';

if ($conn->connect_error) {
    http_response_code(500);
    echo json_encode(["status" => "error", "message" => "Database connection failed"]);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(["status" => "error", "message" => "Method not allowed"]);
    exit;
}

$data = json_decode(file_get_contents("php://input"), true);

// Support both JSON input and form data
if (!$data && !empty($_POST)) {
    $data = $_POST;
}

if (!isset($data['id']) || !isset($data['action'])) {
    http_response_code(400);
    echo json_encode(["status" => "error", "message" => "Missing required parameters"]);
    exit;
}

$id = intval($data['id']);
$action = $data['action']; // 'block' or 'unblock'

if ($action !== 'block' && $action !== 'unblock') {
    http_response_code(400);
    echo json_encode(["status" => "error", "message" => "Invalid action"]);
    exit;
}

$is_blocked = ($action === 'block') ? 1 : 0;

$stmt = $conn->prepare("UPDATE users SET is_blocked = ? WHERE id = ?");
$stmt->bind_param("ii", $is_blocked, $id);

if ($stmt->execute()) {
    echo json_encode([
        "status" => "success", 
        "message" => "User " . ($action === 'block' ? "blocked" : "unblocked") . " successfully"
    ]);
} else {
    http_response_code(500);
    echo json_encode(["status" => "error", "message" => "Failed to update user status: " . $stmt->error]);
}

$stmt->close();
$conn->close();
?>
