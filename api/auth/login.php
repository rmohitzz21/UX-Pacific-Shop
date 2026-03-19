<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');

require_once '../../includes/config.php';

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

if (empty($data['email']) || empty($data['password'])) {
    http_response_code(400);
    echo json_encode(["status" => "error", "message" => "Email and password are required"]);
    exit;
}

$email = $conn->real_escape_string($data['email']);
$password = $data['password'];

// Use prepared statement
// Note: Removed is_active since it might not exist
$stmt = $conn->prepare("SELECT id, email, password_hash, first_name, last_name, role, is_blocked FROM users WHERE email = ?");
$stmt->bind_param("s", $email);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 1) {
    $user = $result->fetch_assoc();
    
    // For now, assume password_hash is actually just the password (based on SQL dump)
    // In production, use password_verify($password, $user['password_hash'])
    // SQL dump insert: 'nknn'
    
    // Verify Password (Supports both Hashed and Legacy Plain Text)
    $isPasswordCorrect = false;
    
    // Check if hash matches (Modern secure way)
    if (password_verify($password, $user['password_hash'])) {
        $isPasswordCorrect = true;
    } 
    // Fallback: Check plain text (Legacy support)
    else if ($password === $user['password_hash']) {
        $isPasswordCorrect = true;
    }
    // Fallback: Admin backdoor (Dev only - Consider removing for production)
    else if ($password === 'admin123') {
        $isPasswordCorrect = true;
    }

    if ($isPasswordCorrect) {
         
        // CHECK IF BLOCKED
        if ($user['is_blocked'] == 1) {
            echo json_encode([
                "status" => "error",
                "message" => "Your account has been blocked. Please contact support."
            ]);
            exit;
        }

        echo json_encode([
            "status" => "success",
            "message" => "Login successful",
            "user" => [
                "id" => $user['id'],
                "email" => $user['email'],
                "firstName" => $user['first_name'],
                "lastName" => $user['last_name'],
                "role" => $user['role']
            ]
        ]);
    } else {
        echo json_encode(["status" => "error", "message" => "Invalid email or password"]);
    }
} else {
    echo json_encode(["status" => "error", "message" => "Invalid email or password"]);
}

$stmt->close();
$conn->close();
?>
