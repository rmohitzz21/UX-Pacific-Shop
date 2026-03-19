<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');

require_once '../../../includes/config.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(["status" => "error", "message" => "Method not allowed"]);
    exit;
}

// Get ID
$id = $_POST['id'] ?? null;
if (!$id) {
    http_response_code(400);
    echo json_encode(["status" => "error", "message" => "Product ID is required"]);
    exit;
}

// Get other fields
$name = $_POST['name'] ?? '';
$category = $_POST['category'] ?? '';
$description = $_POST['description'] ?? '';
$price = $_POST['price'] ?? 0;
// $old_price = ... (optional, let's include it if posted)
$old_price = !empty($_POST['old_price']) ? $_POST['old_price'] : NULL;
$stock = $_POST['stock'] ?? 0;
$rating = $_POST['rating'] ?? 0; // Optional update
$updated_at = date('Y-m-d H:i:s');

// Handle Image Upload
$imagePath = null;
if (isset($_FILES['image']) && $_FILES['image']['error'] === UPLOAD_ERR_OK) {
    $uploadDir = '../../../img/products/';
    if (!file_exists($uploadDir)) {
        mkdir($uploadDir, 0777, true);
    }

    $fileTmpPath = $_FILES['image']['tmp_name'];
    $fileName = $_FILES['image']['name'];
    $fileNameCmps = explode(".", $fileName);
    $fileExtension = strtolower(end($fileNameCmps));
    $newFileName = md5(time() . $fileName) . '.' . $fileExtension;
    
    $allowedfileExtensions = array('jpg', 'gif', 'png', 'webp', 'jpeg');
    if (in_array($fileExtension, $allowedfileExtensions)) {
        $dest_path = $uploadDir . $newFileName;
        if(move_uploaded_file($fileTmpPath, $dest_path)) {
            $imagePath = 'img/products/' . $newFileName;
        }
    }
}

// Construct SQL
$sql = "";
$types = "";
$params = [];

if ($imagePath) {
    $sql = "UPDATE products SET name=?, description=?, category=?, price=?, old_price=?, stock=?, rating=?, updated_at=?, image=? WHERE id=?";
    // types: name(s), desc(s), cat(s), price(d), old(d), stock(i), rating(d), updated(s), image(s), id(i)
    $types = "sssd did ssi"; // spaces for readability
    $types = "sssddidssi";
    
    // Validate types for NULL
    // If old_price is NULL, we still use 'd'.
    
    $stmt = $conn->prepare($sql);
    if (!$stmt) {
        throw new Exception("Prepare failed: " . $conn->error);
    }
    
    $stmt->bind_param($types, $name, $description, $category, $price, $old_price, $stock, $rating, $updated_at, $imagePath, $id);

} else {
    $sql = "UPDATE products SET name=?, description=?, category=?, price=?, old_price=?, stock=?, rating=?, updated_at=? WHERE id=?";
    // types: name(s), desc(s), cat(s), price(d), old(d), stock(i), rating(d), updated(s), id(i)
    $types = "sssddidsi";
    
    $stmt = $conn->prepare($sql);
    if (!$stmt) {
        throw new Exception("Prepare failed: " . $conn->error);
    }
    
    $stmt->bind_param($types, $name, $description, $category, $price, $old_price, $stock, $rating, $updated_at, $id);
}

if ($stmt->execute()) {
    echo json_encode(["status" => "success", "message" => "Product updated successfully"]);
} else {
    http_response_code(500);
    echo json_encode(["status" => "error", "message" => "Database error: " . $stmt->error]);
}

$stmt->close();
$conn->close();
?>
