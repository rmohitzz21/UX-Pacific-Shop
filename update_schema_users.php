<?php
require_once 'includes/config.php';

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Add is_blocked column to users table if it doesn't exist
$sql = "ALTER TABLE users ADD COLUMN is_blocked TINYINT(1) DEFAULT 0";
if ($conn->query($sql) === TRUE) {
    echo "Column is_blocked added successfully";
} else {
    // Check if error is "Duplicate column name" which is fine
    if (strpos($conn->error, "Duplicate column name") !== false) {
        echo "Column is_blocked already exists";
    } else {
        echo "Error: " . $conn->error;
    }
}

$conn->close();
?>
