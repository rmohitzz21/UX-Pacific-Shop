<?php
header("Content-Type: application/json");

// Correct path to the existing config file
require_once __DIR__ . "/../../includes/config.php";


// 🔥 Read JSON body
$input = file_get_contents("php://input");
$data = json_decode($input, true);

// Validate JSON
if (!$data) {
    http_response_code(400);
    echo json_encode(["success" => false, "message" => "Invalid JSON"]);
    exit;
}

// Required fields
$required = ['email', 'password', 'firstName', 'phone'];

foreach ($required as $field) {
    if (empty($data[$field])) {
        http_response_code(422);
        echo json_encode([
            "success" => false,
            "message" => ucfirst($field) . " is required"
        ]);
        exit;
    }
}

// Sanitize inputs
$email = strtolower(trim($data['email']));
$phone = trim($data['phone']);
$firstName = trim($data['firstName']);
$lastName = trim($data['lastName'] ?? '');
$password = $data['password'];

// Check email exists using MySQLi Prepared Statement
$stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
$stmt->bind_param("s", $email);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows > 0) {
    http_response_code(409);
    echo json_encode([
        "success" => false,
        "message" => "Email already registered"
    ]);
    exit;
}
$stmt->close();

// Hash password
$hash = password_hash($password, PASSWORD_BCRYPT);
$role = 'customer'; // Default role

// Insert using MySQLi Prepared Statement
$stmt = $conn->prepare("
  INSERT INTO users (email, password_hash, first_name, last_name, phone, role)
  VALUES (?, ?, ?, ?, ?, ?)
");

$stmt->bind_param("ssssss", $email, $hash, $firstName, $lastName, $phone, $role);

if ($stmt->execute()) {
    echo json_encode([
        "success" => true,
        "message" => "Account created successfully"
    ]);
} else {
    http_response_code(500);
    echo json_encode([
        "success" => false,
        "message" => "Database error: " . $stmt->error
    ]);
}

$stmt->close();
$conn->close();
?>
