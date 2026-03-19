# Backend API & CRUD Documentation

## Overview
This document outlines the current implementation of the Admin API for Product and User management in the UX Merchandise system. It explains the file structure, how the CRUD (Create, Read, Update, Delete) operations work, and provides a security assessment.

## File Structure

The API endpoints are organized in the `api/admin/` directory:

```
api/admin/
├── product/
│   ├── list.php      # GET: List all products
│   ├── get.php       # GET: Get single product by ID
│   ├── create.php    # POST: Create new product (multipart/form-data)
│   ├── update.php    # POST: Update existing product
│   └── delete.php    # POST: Delete product
└── user/
    └── list.php      # GET: List all registered users
```

## detailed CRUD Workflow

### 1. Products

**Create (POST `api/admin/product/create.php`)**
*   **Input**: Receives `name`, `category`, `description`, `price`, `stock`, `rating`, and an `image` file.
*   **Process**:
    1.  Validates input methods and required fields.
    2.  Handles Image Upload:
        *   Checks for valid extensions (jpg, png, webp, etc.).
        *   Generates a unique filename (MD5 hash of time + name).
        *    moves file to `img/products/`.
    3.  Inserts data into `products` table using **Prepared Statements** (`bind_param`) to prevent SQL injection.

**Read (GET `api/admin/product/list.php` & `get.php`)**
*   `list.php`: Returns a JSON array of all products.
*   `get.php?id=X`: Returns a single product object for the "Edit" modal.

**Update (POST `api/admin/product/update.php`)**
*   **Input**: `id` is required. Optional image upload.
*   **Process**:
    *   If a new image is provided, it uploads it and updates the `image` column.
    *   If no image is provided, it keeps the existing image path.
    *   Updates other fields (`name`, `price`, etc.) via SQL `UPDATE`.

**Delete (POST `api/admin/product/delete.php`)**
*   **Input**: `id`.
*   **Process**: Executes `DELETE FROM products WHERE id = ?`.

### 2. Users

**Read (GET `api/admin/user/list.php`)**
*   Fetches user data (`id`, `name`, `email`, `phone`, `created_at`).
*   **Security Note**: Sensitive fields like passwords are explicitly excluded from the SQL query.

---

## Security & Production Readiness Assessment

### Current Status: ⚠️ DEVELOPMENT / PROTOTYPE ONLY

While the code functions correctly for the given task, it is **NOT YET SAFE FOR PRODUCTION** deployment.

### Critical Issues to Address:

1.  **Missing Authentication & Authorization**:
    *   **Issue**: The API endpoints (`create.php`, `delete.php`, etc.) do not check if the user is actually an admin. Anyone who knows the URL (e.g., `yoursite.com/api/admin/product/delete.php`) could send a CURL request to delete products.
    *   **Current State**: Auth is handled entirely on the client-side (JavaScript checking `localStorage`). This can be easily bypassed.
    *   **Fix Required**: Implement server-side session management (`session_start()`) and check `$_SESSION['admin_logged_in']` at the top of every API file.

2.  **Input Validation**:
    *   **Issue**: While Prepared Statements are used (protecting against SQL Injection), there is minimal validation on business logic (e.g., allowing negative prices, no max file size limit check beyond PHP defaults).
    *   **Fix Required**: Add stricter server-side validation rules.

3.  **CSRF Protection**:
    *   **Issue**: There is no Anti-CSRF token implementation.
    *   **Fix Required**: Generate a CSRF token on login, pass it to the JavaScript, and verify it on every POST request.

### Conclusion

The current backend implementation successfully demonstrates the **functionality** of a Product Management System. It handles data persistence, file uploads, and JSON communication correctly. However, strictly due to the **lack of server-side security checks**, it should be kept in a protected environment until a proper PHP Session-based Authentication system is implemented.
