                                                                                                                                                                                                        # Add Product API Integration Guide

## 📋 Overview

This document provides a complete guide on how `addproduct.php` works with the backend API to add products to the database. The admin panel uses this functionality to create new products in the `uxmerchandise` database.

---

## 🎯 Purpose

The `addproduct.php` page allows administrators to:
- Add new products to the catalog
- Upload product images
- Set product details (name, description, category, price, stock, etc.)
- Mark products as featured
- Store all data in the MySQL database via RESTful API

---

## 📊 Database Structure

### Products Table Schema

Based on the `uxmerchandise` database, the `products` table has the following structure:

```sql
CREATE TABLE products (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(100),
    price DECIMAL(10,2) NOT NULL,
    old_price DECIMAL(10,2),
    image VARCHAR(255),
    stock INT DEFAULT 0,
    rating DECIMAL(3,2) DEFAULT 0,
    featured TINYINT(1) DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
```

### Table Columns Explained

| Column | Type | Required | Description |
|--------|------|----------|-------------|
| `id` | INT | Auto | Primary key, auto-incrementing |
| `name` | VARCHAR(255) | ✅ Yes | Product name |
| `description` | TEXT | ✅ Yes | Detailed product description |
| `category` | VARCHAR(100) | ✅ Yes | Product category (T-Shirts, Stickers, Booklet, etc.) |
| `price` | DECIMAL(10,2) | ✅ Yes | Current selling price |
| `old_price` | DECIMAL(10,2) | ❌ No | Previous price for discount display |
| `image` | VARCHAR(255) | ✅ Yes | Product image file path/URL |
| `stock` | INT | ✅ Yes | Available inventory quantity |
| `rating` | DECIMAL(3,2) | ❌ No | Average customer rating (0.0 to 5.0) |
| `featured` | TINYINT(1) | ❌ No | Featured product flag (0 or 1) |
| `created_at` | TIMESTAMP | Auto | Product creation timestamp |
| `updated_at` | TIMESTAMP | Auto | Last update timestamp |

---

## 🔌 API Endpoint

### Endpoint Details

**URL:** `/api/admin/product/create.php`  
**Method:** `POST`  
**Content-Type:** `multipart/form-data` (for file upload)  
**Authentication:** Required (Admin session)

### Request Format

The API accepts a `multipart/form-data` request with the following fields:

| Field Name | Type | Required | Description |
|------------|------|----------|-------------|
| `name` | string | ✅ Yes | Product name |
| `description` | text | ✅ Yes | Product description |
| `category` | string | ✅ Yes | Product category |
| `price` | decimal | ✅ Yes | Product price (e.g., 29.99) |
| `old_price` | decimal | ❌ No | Original price (optional) |
| `stock` | integer | ✅ Yes | Stock quantity |
| `rating` | decimal | ❌ No | Initial rating (0.0 to 5.0) |
| `featured` | integer | ❌ No | Featured flag (0 or 1) |
| `image` | file | ✅ Yes | Product image file |

### Request Example (JavaScript FormData)

```javascript
const formData = new FormData();
formData.append('name', 'UXPacific Classic T-Shirt');
formData.append('description', 'Premium quality cotton t-shirt with UXPacific branding');
formData.append('category', 'T-Shirts');
formData.append('price', '29.99');
formData.append('old_price', '39.99');
formData.append('stock', '100');
formData.append('rating', '4.5');
formData.append('featured', '1');
formData.append('image', fileInput.files[0]); // File object
```

---

## 📤 Response Format

### Success Response (HTTP 200)

```json
{
    "success": true,
    "message": "Product added successfully",
    "data": {
        "product_id": 123,
        "name": "UXPacific Classic T-Shirt",
        "image_url": "/uploads/products/123_uxpacific_tshirt.webp",
        "created_at": "2026-01-23 10:30:00"
    }
}
```

### Error Response (HTTP 400/401/500)

```json
{
    "success": false,
    "message": "Validation error",
    "errors": {
        "name": "Product name is required",
        "price": "Price must be greater than 0"
    }
}
```

### Authentication Error (HTTP 401)

```json
{
    "success": false,
    "message": "Unauthorized. Admin access required."
}
```

---

## 🛠️ Implementation Steps

### Step 1: Create API Endpoint File

Create the file: `api/admin/product/create.php`

```php
<?php
/**
 * API Endpoint: Create Product
 * POST /api/admin/product/create.php
 * 
 * Creates a new product in the database
 * Requires admin authentication
 */

header('Content-Type: application/json');
require_once __DIR__ . '/../../../includes/db_connect.php';
require_once __DIR__ . '/../../../includes/auth_check.php';
require_once __DIR__ . '/../../../utils/validation.php';
require_once __DIR__ . '/../../../utils/file_upload.php';

// Check if user is authenticated as admin
if (!isAdmin()) {
    http_response_code(401);
    echo json_encode([
        'success' => false,
        'message' => 'Unauthorized. Admin access required.'
    ]);
    exit;
}

// Check request method
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode([
        'success' => false,
        'message' => 'Method not allowed. Use POST.'
    ]);
    exit;
}

// Initialize response
$response = ['success' => false, 'message' => '', 'errors' => []];

try {
    // Get database connection
    $conn = DB::getConnection();
    
    // Validate required fields
    $required_fields = ['name', 'description', 'category', 'price', 'stock'];
    $errors = [];
    
    foreach ($required_fields as $field) {
        if (empty($_POST[$field])) {
            $errors[$field] = ucfirst($field) . ' is required';
        }
    }
    
    // Validate image upload
    if (!isset($_FILES['image']) || $_FILES['image']['error'] !== UPLOAD_ERR_OK) {
        $errors['image'] = 'Product image is required';
    }
    
    if (!empty($errors)) {
        http_response_code(400);
        $response['message'] = 'Validation error';
        $response['errors'] = $errors;
        echo json_encode($response);
        exit;
    }
    
    // Sanitize and validate input
    $name = sanitizeInput($_POST['name']);
    $description = sanitizeInput($_POST['description']);
    $category = sanitizeInput($_POST['category']);
    $price = floatval($_POST['price']);
    $old_price = !empty($_POST['old_price']) ? floatval($_POST['old_price']) : null;
    $stock = intval($_POST['stock']);
    $rating = !empty($_POST['rating']) ? floatval($_POST['rating']) : 0.0;
    $featured = isset($_POST['featured']) && $_POST['featured'] == '1' ? 1 : 0;
    
    // Validate price
    if ($price <= 0) {
        $errors['price'] = 'Price must be greater than 0';
    }
    
    // Validate stock
    if ($stock < 0) {
        $errors['stock'] = 'Stock cannot be negative';
    }
    
    // Validate rating
    if ($rating < 0 || $rating > 5) {
        $errors['rating'] = 'Rating must be between 0 and 5';
    }
    
    if (!empty($errors)) {
        http_response_code(400);
        $response['message'] = 'Validation error';
        $response['errors'] = $errors;
        echo json_encode($response);
        exit;
    }
    
    // Handle image upload
    $upload_result = uploadProductImage($_FILES['image']);
    
    if (!$upload_result['success']) {
        http_response_code(400);
        $response['message'] = 'Image upload failed';
        $response['errors'] = ['image' => $upload_result['message']];
        echo json_encode($response);
        exit;
    }
    
    $image_path = $upload_result['path'];
    
    // Prepare SQL statement
    $stmt = $conn->prepare("
        INSERT INTO products (name, description, category, price, old_price, image, stock, rating, featured)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ");
    
    $stmt->bind_param(
        "sssdddsid",
        $name,
        $description,
        $category,
        $price,
        $old_price,
        $image_path,
        $stock,
        $rating,
        $featured
    );
    
    // Execute query
    if ($stmt->execute()) {
        $product_id = $conn->insert_id;
        
        http_response_code(200);
        $response['success'] = true;
        $response['message'] = 'Product added successfully';
        $response['data'] = [
            'product_id' => $product_id,
            'name' => $name,
            'image_url' => $image_path,
            'created_at' => date('Y-m-d H:i:s')
        ];
    } else {
        throw new Exception('Database error: ' . $stmt->error);
    }
    
    $stmt->close();
    
} catch (Exception $e) {
    http_response_code(500);
    $response['message'] = 'Server error: ' . $e->getMessage();
    error_log('Add Product Error: ' . $e->getMessage());
}

echo json_encode($response);
?>
```

### Step 2: Create File Upload Utility

Create the file: `utils/file_upload.php`

```php
<?php
/**
 * File Upload Utility Functions
 */

// Define upload directory
define('UPLOAD_DIR', __DIR__ . '/../uploads/products/');
define('MAX_FILE_SIZE', 5 * 1024 * 1024); // 5MB
define('ALLOWED_EXTENSIONS', ['jpg', 'jpeg', 'png', 'webp']);

/**
 * Upload product image
 * @param array $file $_FILES['image'] array
 * @return array ['success' => bool, 'message' => string, 'path' => string]
 */
function uploadProductImage($file) {
    // Check if upload directory exists, create if not
    if (!file_exists(UPLOAD_DIR)) {
        mkdir(UPLOAD_DIR, 0755, true);
    }
    
    // Validate file
    if ($file['error'] !== UPLOAD_ERR_OK) {
        return [
            'success' => false,
            'message' => 'File upload error: ' . $file['error']
        ];
    }
    
    // Check file size
    if ($file['size'] > MAX_FILE_SIZE) {
        return [
            'success' => false,
            'message' => 'File size exceeds 5MB limit'
        ];
    }
    
    // Get file extension
    $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    
    // Validate extension
    if (!in_array($ext, ALLOWED_EXTENSIONS)) {
        return [
            'success' => false,
            'message' => 'Invalid file type. Allowed: ' . implode(', ', ALLOWED_EXTENSIONS)
        ];
    }
    
    // Generate unique filename
    $filename = uniqid('product_', true) . '_' . time() . '.' . $ext;
    $filepath = UPLOAD_DIR . $filename;
    
    // Move uploaded file
    if (move_uploaded_file($file['tmp_name'], $filepath)) {
        // Return relative path for database storage
        $relative_path = '/uploads/products/' . $filename;
        
        return [
            'success' => true,
            'message' => 'File uploaded successfully',
            'path' => $relative_path,
            'filename' => $filename
        ];
    } else {
        return [
            'success' => false,
            'message' => 'Failed to move uploaded file'
        ];
    }
}
?>
```

### Step 3: Update addproduct.php JavaScript

Update the `handleAddProduct` function in `addproduct.php`:

```javascript
// Form submission handler with API integration
async function handleAddProduct(event) {
    event.preventDefault();
    
    const form = event.target;
    const submitButton = form.querySelector('button[type="submit"]');
    const originalText = submitButton.textContent;
    
    // Disable submit button
    submitButton.disabled = true;
    submitButton.textContent = 'Adding Product...';
    
    try {
        // Create FormData object
        const formData = new FormData(form);
        
        // Get admin session token (if using token-based auth)
        const adminSession = JSON.parse(localStorage.getItem('adminSession') || '{}');
        
        // Make API request
        const response = await fetch('/api/admin/product/create.php', {
            method: 'POST',
            body: formData,
            // Note: Don't set Content-Type header, browser will set it automatically with boundary for FormData
            headers: {
                'X-Admin-Session': adminSession.token || '' // If using token auth
            }
        });
        
        const result = await response.json();
        
        if (result.success) {
            // Show success message
            showNotification('Product added successfully!', 'success');
            
            // Reset form
            form.reset();
            document.getElementById('file-preview').style.display = 'none';
            
            // Redirect to dashboard after 2 seconds
            setTimeout(() => {
                window.location.href = 'admin-dashboard.php';
            }, 2000);
        } else {
            // Show error messages
            if (result.errors) {
                let errorMessage = result.message + '\n\n';
                for (const [field, message] of Object.entries(result.errors)) {
                    errorMessage += `${field}: ${message}\n`;
                }
                showNotification(errorMessage, 'error');
            } else {
                showNotification(result.message || 'Failed to add product', 'error');
            }
            
            // Re-enable submit button
            submitButton.disabled = false;
            submitButton.textContent = originalText;
        }
    } catch (error) {
        console.error('Error:', error);
        showNotification('Network error. Please try again.', 'error');
        
        // Re-enable submit button
        submitButton.disabled = false;
        submitButton.textContent = originalText;
    }
}

// Notification function
function showNotification(message, type = 'info') {
    // You can use your existing toast/notification system
    // For example, if you have a showToast function:
    if (typeof showToast === 'function') {
        showToast(message, type);
    } else {
        alert(message);
    }
}
```

---

## 🔒 Security Considerations

### 1. Authentication & Authorization

- ✅ Verify admin session before processing request
- ✅ Check user role is 'admin'
- ✅ Validate session expiration

### 2. Input Validation

- ✅ Sanitize all user inputs
- ✅ Validate data types (price = decimal, stock = integer)
- ✅ Check required fields
- ✅ Validate file types and sizes
- ✅ Prevent SQL injection using prepared statements

### 3. File Upload Security

- ✅ Validate file extensions (only allow: jpg, jpeg, png, webp)
- ✅ Check file size limits (max 5MB)
- ✅ Generate unique filenames to prevent overwrites
- ✅ Store files outside web root if possible
- ✅ Scan uploaded files for malware (optional but recommended)

### 4. Database Security

- ✅ Use prepared statements (prevents SQL injection)
- ✅ Validate all input before database insertion
- ✅ Set appropriate data types in database
- ✅ Use transactions for critical operations

---

## 📁 Required File Structure

```
Ux-Merchandise/
├── api/
│   └── admin/
│       └── product/
│           └── create.php          # API endpoint
├── includes/
│   ├── db_connect.php              # Database connection
│   └── auth_check.php               # Authentication check
├── utils/
│   ├── validation.php               # Input validation
│   ├── sanitize.php                  # Input sanitization
│   └── file_upload.php               # File upload utility
├── uploads/
│   └── products/                    # Product images directory
│       └── (uploaded files here)
└── addproduct.php                   # Admin form page
```

---

## 🧪 Testing the API

### Using cURL

```bash
curl -X POST http://localhost/api/admin/product/create.php \
  -F "name=Test Product" \
  -F "description=Test Description" \
  -F "category=T-Shirts" \
  -F "price=29.99" \
  -F "old_price=39.99" \
  -F "stock=100" \
  -F "rating=4.5" \
  -F "featured=1" \
  -F "image=@/path/to/image.jpg" \
  -H "Cookie: PHPSESSID=your_session_id"
```

### Using Postman

1. Set method to `POST`
2. URL: `http://localhost/api/admin/product/create.php`
3. Body type: `form-data`
4. Add all fields as key-value pairs
5. Add `image` field as `File` type
6. Send request

### Expected Response

```json
{
    "success": true,
    "message": "Product added successfully",
    "data": {
        "product_id": 123,
        "name": "Test Product",
        "image_url": "/uploads/products/product_1234567890_1642934400.jpg",
        "created_at": "2026-01-23 10:30:00"
    }
}
```

---

## 🔄 Complete Workflow

```
1. Admin opens addproduct.php
   ↓
2. Admin fills form with product details
   ↓
3. Admin selects product image
   ↓
4. Admin clicks "Add Product" button
   ↓
5. JavaScript creates FormData object
   ↓
6. JavaScript sends POST request to /api/admin/product/create.php
   ↓
7. API validates admin session
   ↓
8. API validates form data
   ↓
9. API uploads image file
   ↓
10. API inserts product into database
    ↓
11. API returns success response
    ↓
12. JavaScript shows success message
    ↓
13. Admin is redirected to dashboard
```

---

## 🐛 Error Handling

### Common Errors and Solutions

| Error | Cause | Solution |
|-------|-------|----------|
| "Unauthorized" | Not logged in as admin | Check admin session |
| "Validation error" | Missing required fields | Fill all required fields |
| "File upload failed" | Invalid file type/size | Use valid image (jpg, png, webp, max 5MB) |
| "Database error" | SQL query failed | Check database connection and table structure |
| "Network error" | API endpoint not found | Verify API file path and server configuration |

---

## 📝 Additional Notes

1. **Image Optimization**: Consider resizing/optimizing images before storing
2. **Thumbnail Generation**: Generate thumbnails for product listings
3. **CDN Integration**: Store images on CDN for better performance
4. **Logging**: Log all product additions for audit trail
5. **Notifications**: Send email notification when product is added (optional)

---

## ✅ Checklist for Implementation

- [ ] Create `api/admin/product/create.php` endpoint
- [ ] Create `utils/file_upload.php` utility
- [ ] Create `includes/auth_check.php` for admin verification
- [ ] Create `uploads/products/` directory with proper permissions
- [ ] Update `addproduct.php` JavaScript to use API
- [ ] Test form submission with valid data
- [ ] Test file upload functionality
- [ ] Test error handling (invalid data, missing fields)
- [ ] Test authentication (unauthorized access)
- [ ] Verify product appears in database
- [ ] Verify image is uploaded correctly

---

## 🔗 Related Files

- `addproduct.php` - Admin form page
- `admin-dashboard.php` - Admin dashboard (shows products)
- `DATABASE_SCHEMA.md` - Complete database structure
- `PHP_INTEGRATION_GUIDE.md` - General PHP integration guide
- `PHP_BACKEND_TODO.md` - Complete backend implementation checklist

---

**Last Updated**: January 2026  
**Version**: 1.0  
**Author**: Backend Development Team
