<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');

// Include database configuration
// Path: root/api/admin/product/create.php -> ../../../includes/config.php
require_once '../../../includes/config.php';

// Check request method
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(["status" => "error", "message" => "Method not allowed"]);
    exit;
}

// Get form data
$name = $_POST['name'] ?? '';
$category = $_POST['category'] ?? '';
$description = $_POST['description'] ?? '';
$price = $_POST['price'] ?? 0;
$old_price = !empty($_POST['old_price']) ? $_POST['old_price'] : NULL;
$stock = $_POST['stock'] ?? 0;
$rating = $_POST['rating'] ?? 0;
// $featured = isset($_POST['featured']) ? 1 : 0;
$created_at = date('Y-m-d H:i:s');
$updated_at = date('Y-m-d H:i:s');      

// Validation
if (empty($name) || empty($category) || empty($price)) {
    http_response_code(400);
    echo json_encode(["status" => "error", "message" => "Name, category, and price are required"]);
    exit;
}

// Handle Image Upload
$imagePath = '';
if (isset($_FILES['image']) && $_FILES['image']['error'] === UPLOAD_ERR_OK) {
    // Define upload directory
    $uploadDir = '../../../img/products/';
    
    // Create directory if it doesn't exist
    if (!file_exists($uploadDir)) {
        if (!mkdir($uploadDir, 0777, true)) {
            http_response_code(500);
            echo json_encode(["status" => "error", "message" => "Failed to create upload directory"]);
            exit;
        }
    }

    $fileTmpPath = $_FILES['image']['tmp_name'];
    $fileName = $_FILES['image']['name'];
    $fileSize = $_FILES['image']['size'];
    $fileType = $_FILES['image']['type'];
    
    // Get extension
    $fileNameCmps = explode(".", $fileName);
    $fileExtension = strtolower(end($fileNameCmps));

    // Sanitize file name
    $newFileName = md5(time() . $fileName) . '.' . $fileExtension;
    
    // Check if file type is allowed
    $allowedfileExtensions = array('jpg', 'gif', 'png', 'webp', 'jpeg');
    if (in_array($fileExtension, $allowedfileExtensions)) {
        $dest_path = $uploadDir . $newFileName;
        
        if(move_uploaded_file($fileTmpPath, $dest_path)) {
            // Save relative path for DB (path from web root)
            $imagePath = 'img/products/' . $newFileName;
        } else {
             http_response_code(500);
             echo json_encode(["status" => "error", "message" => "There was an error moving the uploaded file."]);
             exit;
        }
    } else {
        http_response_code(400);
        echo json_encode(["status" => "error", "message" => "Upload failed. Allowed file types: " . implode(',', $allowedfileExtensions)]);
        exit;
    }
} else {
    // If image is required in the form, fail here.
    // The form has required attribute, so backend should also enforce.
    http_response_code(400);
    echo json_encode(["status" => "error", "message" => "Product image is required"]);
    exit;
}

// Insert into DB
$sql = "INSERT INTO products (name, description, category, price, old_price, image, stock, rating, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
$stmt = $conn->prepare($sql);

if ($stmt) {
    // Types: s=string, s=string, s=string, d=double, d=double, s=string, i=integer, d=double, s=string, s=string
    // name, description, category, price, old_price, image, stock, rating, created_at, updated_at
    $stmt->bind_param("sssdssidss", $name, $description, $category, $price, $old_price, $imagePath, $stock, $rating, $created_at, $updated_at);
    
    if ($stmt->execute()) {
        http_response_code(201);
        echo json_encode([
            "status" => "success",
            "message" => "Product created successfully",
            "product_id" => $conn->insert_id
        ]);
    } else {
        http_response_code(500);
        echo json_encode([
            "status" => "error",
            "message" => "Database error: " . $stmt->error
        ]);
    }
    $stmt->close();
} else {
    http_response_code(500);
    echo json_encode([
        "status" => "error",
        "message" => "Statement preparation failed: " . $conn->error
    ]);
}

$conn->close();
?>