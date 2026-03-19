# PHP Backend Implementation - Complete TODO & Step-by-Step Guide

This document provides a comprehensive TODO list and step-by-step guide for implementing the PHP backend for the UX-Merchandise e-commerce platform.

---

## 📋 Table of Contents

1. [Phase 1: Project Setup](#phase-1-project-setup)
2. [Phase 2: Database Setup](#phase-2-database-setup)
3. [Phase 3: Core Infrastructure](#phase-3-core-infrastructure)
4. [Phase 4: Authentication System](#phase-4-authentication-system)
5. [Phase 5: Product Management](#phase-5-product-management)
6. [Phase 6: Shopping Cart System](#phase-6-shopping-cart-system)
7. [Phase 7: Order Processing](#phase-7-order-processing)
8. [Phase 8: User Management](#phase-8-user-management)
9. [Phase 9: Admin Panel Backend](#phase-9-admin-panel-backend)
10. [Phase 10: Frontend Integration](#phase-10-frontend-integration)
11. [Phase 11: Testing & Deployment](#phase-11-testing--deployment)

---

## Phase 1: Project Setup

### Tasks:
- [ ] Install PHP (version 7.4 or higher)
- [ ] Install MySQL/MariaDB
- [ ] Install Apache/Nginx web server
- [ ] Install Composer (PHP dependency manager)
- [ ] Set up local development environment (XAMPP/WAMP/MAMP or Docker)
- [ ] Verify PHP extensions: mysqli, pdo, json, mbstring, openssl

### Directory Structure:
```
Ux-Merchandise/
├── api/
│   ├── auth/
│   ├── products/
│   ├── cart/
│   ├── orders/
│   ├── wishlist/
│   ├── user/
│   └── admin/
├── config/
├── includes/
├── classes/
├── utils/
├── uploads/
│   ├── products/
│   └── avatars/
└── logs/
```

### Configuration Files:
- [ ] Create `config/database.php` - Database connection settings
- [ ] Create `config/config.php` - Application settings
- [ ] Create `config/constants.php` - Constants (order statuses, roles, categories)
- [ ] Create `.env.example` - Environment variables template
- [ ] Create `.env` - Actual environment variables (DO NOT COMMIT)
- [ ] Create `.gitignore` - Exclude sensitive files
- [ ] Create `composer.json` - PHP dependencies
- [ ] Create root `.htaccess` - URL rewriting and security
- [ ] Create `api/.htaccess` - API security

---

## Phase 2: Database Setup

### Tasks:
- [ ] Create MySQL database: `ux_merchandise`
- [ ] Set database charset to `utf8mb4`
- [ ] Create database user with appropriate permissions

### Database Tables:
- [ ] Create `users` table
  ```sql
  CREATE TABLE users (
      id INT PRIMARY KEY AUTO_INCREMENT,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      first_name VARCHAR(100),
      last_name VARCHAR(100),
      phone VARCHAR(20),
      role ENUM('customer', 'admin') DEFAULT 'customer',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
  );
  ```

- [ ] Create `products` table
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
      featured BOOLEAN DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
  );
  ```

- [ ] Create `cart` table
  ```sql
  CREATE TABLE cart (
      id INT PRIMARY KEY AUTO_INCREMENT,
      user_id INT NOT NULL,
      product_id INT NOT NULL,
      quantity INT NOT NULL DEFAULT 1,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE,
      UNIQUE KEY unique_cart_item (user_id, product_id)
  );
  ```

- [ ] Create `orders` table
  ```sql
  CREATE TABLE orders (
      id INT PRIMARY KEY AUTO_INCREMENT,
      order_number VARCHAR(50) UNIQUE NOT NULL,
      user_id INT NOT NULL,
      total DECIMAL(10,2) NOT NULL,
      subtotal DECIMAL(10,2) NOT NULL,
      shipping DECIMAL(10,2) DEFAULT 50,
      tax DECIMAL(10,2) NOT NULL,
      payment_method VARCHAR(50),
      status ENUM('Pending', 'Processing', 'Shipped', 'Delivered', 'Cancelled') DEFAULT 'Pending',
      shipping_address TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
  );
  ```

- [ ] Create `order_items` table
  ```sql
  CREATE TABLE order_items (
      id INT PRIMARY KEY AUTO_INCREMENT,
      order_id INT NOT NULL,
      product_id INT NOT NULL,
      quantity INT NOT NULL,
      price DECIMAL(10,2) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
      FOREIGN KEY (product_id) REFERENCES products(id)
  );
  ```

- [ ] Create `wishlist` table
  ```sql
  CREATE TABLE wishlist (
      id INT PRIMARY KEY AUTO_INCREMENT,
      user_id INT NOT NULL,
      product_id INT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE,
      UNIQUE KEY unique_wishlist_item (user_id, product_id)
  );
  ```

- [ ] Add indexes for performance
- [ ] Insert sample admin user
- [ ] Insert sample products for testing

---

## Phase 3: Core Infrastructure

### Database Connection:
- [ ] Create `includes/db_connect.php`
  ```php
  <?php
  class DB {
      private static $connection = null;
      
      public static function getConnection() {
          if (self::$connection === null) {
              require_once __DIR__ . '/../config/database.php';
              self::$connection = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
              if (self::$connection->connect_error) {
                  die("Connection failed: " . self::$connection->connect_error);
              }
              self::$connection->set_charset(DB_CHARSET);
          }
          return self::$connection;
      }
  }
  ?>
  ```

### Utility Functions:
- [ ] Create `utils/validation.php`
  - [ ] `validateEmail($email)` - Email validation
  - [ ] `validatePassword($password)` - Password strength validation
  - [ ] `validatePhone($phone)` - Phone number validation
  - [ ] `validateRequired($data)` - Required field validation

- [ ] Create `utils/sanitize.php`
  - [ ] `sanitizeInput($data)` - Sanitize single input
  - [ ] `sanitizeArray($array)` - Sanitize array of inputs
  - [ ] `sanitizeEmail($email)` - Email sanitization

- [ ] Create `utils/helpers.php`
  - [ ] `jsonResponse($data, $statusCode)` - Return JSON response
  - [ ] `getCurrentUserId()` - Get logged-in user ID
  - [ ] `isLoggedIn()` - Check if user is logged in
  - [ ] `isAdmin()` - Check if user is admin
  - [ ] `formatPrice($price)` - Format price display

### Include Files:
- [ ] Create `includes/functions.php` - Common functions
- [ ] Create `includes/auth_check.php` - Authentication middleware
- [ ] Create `includes/admin_check.php` - Admin authorization middleware
- [ ] Create `includes/nav.php` - Navigation component
- [ ] Create `includes/footer.php` - Footer component
- [ ] Create `includes/header.php` - HTML head section

### Core Classes:
- [ ] Create `classes/Database.php` - Database wrapper class
- [ ] Create `classes/User.php` - User model
- [ ] Create `classes/Product.php` - Product model
- [ ] Create `classes/Cart.php` - Cart model
- [ ] Create `classes/Order.php` - Order model
- [ ] Create `classes/Wishlist.php` - Wishlist model
- [ ] Create `classes/Auth.php` - Authentication class
- [ ] Create `classes/Admin.php` - Admin operations class

---

## Phase 4: Authentication System

### User Registration:
**File:** `api/auth/register.php`

**Step-by-Step Flow:**
1. Receive POST request with user data (email, password, first_name, last_name, phone)
2. Validate all input fields
3. Check if email already exists
4. Hash password using `password_hash()` with bcrypt
5. Insert user into database
6. Create session
7. Return JSON response with success status

**Frontend Integration:**
- Update `signup.html` form to POST to `/api/auth/register.php`
- Handle response and redirect to `index.php` on success
- Display error messages on failure

### User Login:
**File:** `api/auth/login.php`

**Step-by-Step Flow:**
1. Receive POST request with email and password
2. Validate input
3. Query database for user by email
4. Verify password using `password_verify()`
5. Create session with user data
6. Return JSON response with user info

**Frontend Integration:**
- Update `signin.html` form to POST to `/api/auth/login.php`
- Store session token (if using JWT) or rely on PHP sessions
- Redirect to `index.php` or previous page on success

### Admin Login:
**File:** `api/auth/admin-login.php`

**Step-by-Step Flow:**
1. Receive POST request with email and password
2. Validate input
3. Query database for user by email
4. Check if user role is 'admin'
5. Verify password
6. Create admin session
7. Return JSON response

**Frontend Integration:**
- Update `admin-login.html` form to POST to `/api/auth/admin-login.php`
- Redirect to `admin-dashboard.php` on success

### Password Reset:
**Files:** `api/auth/forgot-password.php`, `api/auth/reset-password.php`

**Step-by-Step Flow:**
1. User requests password reset (forgot-password.php)
2. Generate unique reset token
3. Store token in database with expiration time
4. Send email with reset link
5. User clicks link and enters new password (reset-password.php)
6. Validate token and expiration
7. Update password in database
8. Invalidate token

**Frontend Integration:**
- Update `forgot-password.html` to POST to `/api/auth/forgot-password.php`
- Create reset password page that accepts token from URL

### Logout:
**File:** `api/auth/logout.php`

**Step-by-Step Flow:**
1. Destroy PHP session
2. Clear session cookies
3. Return success response

**Frontend Integration:**
- Update logout links/buttons to call `/api/auth/logout.php`
- Redirect to `index.php` or `signin.php` after logout

---

## Phase 5: Product Management

### Get All Products:
**File:** `api/products/list.php`

**Step-by-Step Flow:**
1. Accept GET request with optional query parameters:
   - `page` - Page number for pagination
   - `limit` - Items per page
   - `category` - Filter by category
   - `search` - Search query
2. Query database with filters
3. Calculate total count
4. Return JSON with products array and pagination info

**Frontend Integration:**
- Update `shopAll.html` to fetch from `/api/products/list.php`
- Display products dynamically
- Implement pagination
- Add category filtering

### Get Single Product:
**File:** `api/products/get.php`

**Step-by-Step Flow:**
1. Accept GET request with `id` parameter
2. Query database for product by ID
3. Return JSON with product details

**Frontend Integration:**
- Update `product.html` to fetch product details from `/api/products/get.php?id={id}`
- Display product information dynamically

### Search Products:
**File:** `api/products/search.php`

**Step-by-Step Flow:**
1. Accept GET request with `q` (query) parameter
2. Search products by name or description using LIKE query
3. Return JSON with matching products

**Frontend Integration:**
- Update `search.html` to fetch from `/api/products/search.php?q={query}`
- Display search results

### Filter Products:
**File:** `api/products/filter.php`

**Step-by-Step Flow:**
1. Accept GET request with `category` parameter
2. Query products filtered by category
3. Return JSON with filtered products

**Frontend Integration:**
- Update category filter buttons to call `/api/products/filter.php?category={category}`
- Update product grid with filtered results

---

## Phase 6: Shopping Cart System

### Get Cart:
**File:** `api/cart/get.php`

**Step-by-Step Flow:**
1. Check if user is logged in (require authentication)
2. Get user ID from session
3. Query cart table joined with products table
4. Calculate totals
5. Return JSON with cart items and total

**Frontend Integration:**
- Update `cart.html` to fetch cart from `/api/cart/get.php`
- Display cart items dynamically
- Update cart count in navigation

### Add to Cart:
**File:** `api/cart/add.php`

**Step-by-Step Flow:**
1. Check authentication
2. Receive POST request with `product_id` and `quantity`
3. Validate product exists and has stock
4. Check if item already in cart
   - If exists: Update quantity
   - If not: Insert new cart item
5. Return updated cart

**Frontend Integration:**
- Update "Add to Cart" buttons to POST to `/api/cart/add.php`
- Show success message
- Update cart count in navigation
- Refresh cart display

### Update Cart Item:
**File:** `api/cart/update.php`

**Step-by-Step Flow:**
1. Check authentication
2. Receive POST request with `cart_item_id` and `quantity`
3. Validate cart item belongs to user
4. Update quantity in database
5. Return updated cart

**Frontend Integration:**
- Update quantity inputs in `cart.html` to POST to `/api/cart/update.php`
- Update cart display after change

### Remove from Cart:
**File:** `api/cart/remove.php`

**Step-by-Step Flow:**
1. Check authentication
2. Receive POST request with `cart_item_id`
3. Validate cart item belongs to user
4. Delete cart item from database
5. Return updated cart

**Frontend Integration:**
- Update "Remove" buttons in `cart.html` to POST to `/api/cart/remove.php`
- Remove item from display
- Update totals

### Clear Cart:
**File:** `api/cart/clear.php`

**Step-by-Step Flow:**
1. Check authentication
2. Get user ID from session
3. Delete all cart items for user
4. Return success response

**Frontend Integration:**
- Add "Clear Cart" button that calls `/api/cart/clear.php`
- Refresh cart display

---

## Phase 7: Order Processing

### Create Order:
**File:** `api/orders/create.php`

**Step-by-Step Flow:**
1. Check authentication
2. Receive POST request with:
   - Shipping address
   - Payment method
   - Cart items
3. Validate cart is not empty
4. Calculate totals (subtotal, shipping, tax, total)
5. Generate unique order number
6. Insert order into `orders` table
7. Insert order items into `order_items` table
8. Clear user's cart
9. Send order confirmation email
10. Return JSON with order ID and order number

**Frontend Integration:**
- Update `checkout.html` form to POST to `/api/orders/create.php`
- On success, redirect to `order-confirmation.php?order_id={id}`
- Display order confirmation

### Get User Orders:
**File:** `api/orders/list.php`

**Step-by-Step Flow:**
1. Check authentication
2. Get user ID from session
3. Query orders table for user's orders
4. Join with order_items to get item details
5. Return JSON with orders array

**Frontend Integration:**
- Update `orders.html` to fetch from `/api/orders/list.php`
- Display orders list with status badges

### Get Single Order:
**File:** `api/orders/get.php`

**Step-by-Step Flow:**
1. Check authentication
2. Accept GET request with `order_id`
3. Query order and order_items
4. Verify order belongs to user
5. Return JSON with order details

**Frontend Integration:**
- Update order detail pages to fetch from `/api/orders/get.php?id={id}`
- Display full order information

### Track Order:
**File:** `api/orders/track.php`

**Step-by-Step Flow:**
1. Accept GET request with `order_number` or `order_id`
2. Query order status
3. Return JSON with tracking information

**Frontend Integration:**
- Update `order-tracking.html` to fetch from `/api/orders/track.php?order_number={number}`
- Display order status and tracking info

### Cancel Order:
**File:** `api/orders/cancel.php`

**Step-by-Step Flow:**
1. Check authentication
2. Receive POST request with `order_id`
3. Verify order belongs to user
4. Check if order can be cancelled (status must be Pending or Processing)
5. Update order status to 'Cancelled'
6. Return success response

**Frontend Integration:**
- Add "Cancel Order" button in order details
- Call `/api/orders/cancel.php` on click
- Update order status display

---

## Phase 8: User Management

### Get User Profile:
**File:** `api/user/profile.php`

**Step-by-Step Flow:**
1. Check authentication
2. Get user ID from session
3. Query user data from database
4. Return JSON with user profile (exclude password)

**Frontend Integration:**
- Update `account.html` to fetch profile from `/api/user/profile.php`
- Display user information

### Update Profile:
**File:** `api/user/update.php`

**Step-by-Step Flow:**
1. Check authentication
2. Receive POST request with profile data
3. Validate input
4. Update user record in database
5. Return updated profile

**Frontend Integration:**
- Update profile form in `account.html` to POST to `/api/user/update.php`
- Show success message
- Refresh profile display

### Change Password:
**File:** `api/user/change-password.php`

**Step-by-Step Flow:**
1. Check authentication
2. Receive POST request with old_password and new_password
3. Verify old password
4. Validate new password strength
5. Hash new password
6. Update password in database
7. Return success response

**Frontend Integration:**
- Add change password form in `account.html`
- POST to `/api/user/change-password.php`
- Show success/error messages

### Wishlist Management:
**Files:** `api/wishlist/get.php`, `api/wishlist/add.php`, `api/wishlist/remove.php`

**Step-by-Step Flow:**
1. Check authentication
2. Get user ID from session
3. For GET: Query wishlist items
4. For ADD: Insert product into wishlist (check if already exists)
5. For REMOVE: Delete product from wishlist
6. Return JSON response

**Frontend Integration:**
- Update `wishlist.html` to fetch from `/api/wishlist/get.php`
- Add "Add to Wishlist" buttons on product pages
- Call `/api/wishlist/add.php` or `/api/wishlist/remove.php`

---

## Phase 9: Admin Panel Backend

### Admin Products Management:
**Files:** `api/admin/products/list.php`, `api/admin/products/create.php`, `api/admin/products/update.php`, `api/admin/products/delete.php`

**Step-by-Step Flow:**
1. Check admin authentication
2. For LIST: Get all products with pagination
3. For CREATE: Receive product data, handle image upload, insert into database
4. For UPDATE: Update product data, handle image update if provided
5. For DELETE: Delete product and associated images
6. Return JSON response

**Frontend Integration:**
- Update `admin-dashboard.html` products section to fetch from API
- Update `addproduct.html` form to POST to `/api/admin/products/create.php`
- Add edit/delete functionality

### Admin Orders Management:
**Files:** `api/admin/orders/list.php`, `api/admin/orders/get.php`, `api/admin/orders/update-status.php`

**Step-by-Step Flow:**
1. Check admin authentication
2. For LIST: Get all orders with filters (status, date range)
3. For GET: Get single order with all details
4. For UPDATE-STATUS: Update order status, send notification email
5. Return JSON response

**Frontend Integration:**
- Update admin orders table to fetch from `/api/admin/orders/list.php`
- Update status modal to POST to `/api/admin/orders/update-status.php`
- Refresh orders table after update

### Admin Users Management:
**Files:** `api/admin/users/list.php`, `api/admin/users/get.php`, `api/admin/users/update.php`

**Step-by-Step Flow:**
1. Check admin authentication
2. Query users from database
3. Return user list with order counts
4. Allow updating user information

**Frontend Integration:**
- Update admin users table to fetch from `/api/admin/users/list.php`
- Display user information

### Admin Analytics:
**Files:** `api/admin/analytics/dashboard.php`, `api/admin/analytics/reports.php`

**Step-by-Step Flow:**
1. Check admin authentication
2. Calculate statistics:
   - Total users, products, orders
   - Revenue (today, this month, total)
   - Average order value
   - Conversion rate
   - Top selling products
3. Return JSON with analytics data

**Frontend Integration:**
- Update admin dashboard overview to fetch from `/api/admin/analytics/dashboard.php`
- Display statistics and charts

---

## Phase 10: Frontend Integration

### Convert HTML to PHP:
- [ ] Rename all `.html` files to `.php`
- [ ] Add PHP session start at top of each file
- [ ] Add includes for config and functions
- [ ] Add authentication checks where needed
- [ ] Replace static data with database queries

### Update Navigation:
- [ ] Update `includes/nav.php` to show user info if logged in
- [ ] Display cart count from API
- [ ] Show "Sign in" or user menu based on login status

### Update JavaScript:
- [ ] Replace all `localStorage` cart operations with API calls
- [ ] Update `addToCart()` to use `/api/cart/add.php`
- [ ] Update `getCart()` to use `/api/cart/get.php`
- [ ] Update product loading to use `/api/products/list.php`
- [ ] Update search to use `/api/products/search.php`
- [ ] Update login/register forms to use API endpoints
- [ ] Add error handling for all API calls
- [ ] Add loading states for async operations

### Form Handling:
- [ ] Update all forms to POST to appropriate API endpoints
- [ ] Add CSRF token protection
- [ ] Add form validation (client-side and server-side)
- [ ] Display success/error messages

### Page-Specific Updates:

**index.php:**
- [ ] Fetch featured products from database
- [ ] Display dynamic product data
- [ ] Update cart count from API

**shopAll.php:**
- [ ] Fetch products from `/api/products/list.php`
- [ ] Implement pagination
- [ ] Add category filtering
- [ ] Add search functionality

**product.php:**
- [ ] Get product ID from URL
- [ ] Fetch product details from `/api/products/get.php`
- [ ] Display product information dynamically
- [ ] Update "Add to Cart" to use API

**cart.php:**
- [ ] Require authentication
- [ ] Fetch cart from `/api/cart/get.php`
- [ ] Display cart items dynamically
- [ ] Update quantity/remove to use API
- [ ] Calculate and display totals

**checkout.php:**
- [ ] Require authentication
- [ ] Verify cart is not empty
- [ ] Fetch cart items
- [ ] Submit order to `/api/orders/create.php`
- [ ] Handle order creation response

**orders.php:**
- [ ] Require authentication
- [ ] Fetch user orders from `/api/orders/list.php`
- [ ] Display orders with status badges
- [ ] Add order detail links

**account.php:**
- [ ] Require authentication
- [ ] Fetch user profile from `/api/user/profile.php`
- [ ] Update profile form to POST to `/api/user/update.php`
- [ ] Add change password functionality

**admin-dashboard.php:**
- [ ] Require admin authentication
- [ ] Fetch dashboard stats from `/api/admin/analytics/dashboard.php`
- [ ] Update all tables to use API endpoints
- [ ] Implement status update functionality

---

## Phase 11: Testing & Deployment

### Testing Checklist:
- [ ] Test user registration
- [ ] Test user login/logout
- [ ] Test admin login
- [ ] Test password reset flow
- [ ] Test product listing and search
- [ ] Test add to cart functionality
- [ ] Test cart update and remove
- [ ] Test order creation
- [ ] Test order tracking
- [ ] Test wishlist functionality
- [ ] Test admin product management
- [ ] Test admin order management
- [ ] Test admin user management
- [ ] Test all API endpoints return correct JSON
- [ ] Test error handling
- [ ] Test form validation
- [ ] Test authentication/authorization
- [ ] Test file uploads (product images)
- [ ] Test email sending
- [ ] Test mobile responsiveness

### Security Testing:
- [ ] Test SQL injection prevention
- [ ] Test XSS prevention
- [ ] Test CSRF protection
- [ ] Test authentication bypass attempts
- [ ] Test file upload security
- [ ] Test rate limiting
- [ ] Test input validation and sanitization

### Performance Testing:
- [ ] Test database query performance
- [ ] Test API response times
- [ ] Test with large datasets
- [ ] Optimize slow queries
- [ ] Add database indexes where needed

### Deployment:
- [ ] Set up production server
- [ ] Configure production database
- [ ] Set environment variables
- [ ] Configure SSL certificate
- [ ] Set up domain and DNS
- [ ] Configure email service
- [ ] Set up backup system
- [ ] Configure monitoring
- [ ] Test all functionality in production
- [ ] Set up error logging
- [ ] Configure log rotation

---

## 🔄 Complete Website Workflow

### Customer Journey Flow:

1. **Homepage (index.php)**
   - User visits homepage
   - PHP fetches featured products from database
   - Products displayed dynamically
   - Cart count fetched from API if logged in

2. **Browse Products (shopAll.php)**
   - User clicks "Buy Now" or "Shop All"
   - PHP fetches products from database with pagination
   - User can filter by category (calls `/api/products/filter.php`)
   - User can search (calls `/api/products/search.php`)

3. **View Product (product.php)**
   - User clicks on a product
   - PHP gets product ID from URL
   - Fetches product details from database
   - Displays product information
   - User clicks "Add to Cart"
   - JavaScript calls `/api/cart/add.php`
   - Cart count updates in navigation

4. **Shopping Cart (cart.php)**
   - User clicks cart icon
   - PHP checks authentication (redirects to signin if not logged in)
   - Fetches cart items from database
   - Displays cart with totals
   - User updates quantity (calls `/api/cart/update.php`)
   - User removes item (calls `/api/cart/remove.php`)

5. **Checkout (checkout.php)**
   - User clicks "Proceed to Checkout"
   - PHP verifies cart is not empty
   - Displays checkout form
   - User fills shipping and payment information
   - User submits form
   - JavaScript POSTs to `/api/orders/create.php`
   - Order created in database
   - Cart cleared
   - User redirected to order confirmation

6. **Order Confirmation (order-confirmation.php)**
   - PHP gets order ID from URL
   - Fetches order details from database
   - Displays confirmation with order number
   - Email sent to user

7. **Order History (orders.php)**
   - User clicks "My Orders"
   - PHP checks authentication
   - Fetches user's orders from database
   - Displays orders list with status

8. **Order Tracking (order-tracking.php)**
   - User enters order number
   - PHP queries order status from database
   - Displays tracking information

### Admin Journey Flow:

1. **Admin Login (admin-login.php)**
   - Admin enters credentials
   - Form POSTs to `/api/auth/admin-login.php`
   - PHP verifies admin credentials
   - Creates admin session
   - Redirects to admin dashboard

2. **Admin Dashboard (admin-dashboard.php)**
   - PHP checks admin authentication
   - Fetches dashboard statistics from database
   - Displays overview with stats
   - Admin can navigate to different sections

3. **Manage Products**
   - Admin clicks "Products" tab
   - JavaScript fetches products from `/api/admin/products/list.php`
   - Admin clicks "Add Product"
   - Opens add product form
   - Admin submits form
   - POSTs to `/api/admin/products/create.php`
   - Product created in database
   - Image uploaded to server

4. **Manage Orders**
   - Admin clicks "Orders" tab
   - JavaScript fetches orders from `/api/admin/orders/list.php`
   - Admin clicks "Update" on an order
   - Modal opens with current status
   - Admin selects new status
   - POSTs to `/api/admin/orders/update-status.php`
   - Order status updated in database
   - Email notification sent to customer

---

## 📝 Implementation Priority

### High Priority (Core Functionality):
1. Database setup and connection
2. User authentication (login/register)
3. Product listing and display
4. Shopping cart functionality
5. Order creation

### Medium Priority (Enhanced Features):
1. Order management
2. User profile management
3. Wishlist functionality
4. Admin panel basic features

### Low Priority (Nice to Have):
1. Advanced analytics
2. Email notifications
3. Search functionality
4. Advanced filtering

---

## 🔐 Security Checklist

- [ ] All passwords hashed with bcrypt
- [ ] SQL injection prevented with prepared statements
- [ ] XSS prevented with output escaping
- [ ] CSRF tokens on all forms
- [ ] Input validation on server-side
- [ ] File upload validation
- [ ] Session security configured
- [ ] HTTPS enabled in production
- [ ] Error messages don't expose sensitive info
- [ ] Rate limiting on API endpoints
- [ ] Admin routes protected
- [ ] User data access restricted

---

## 📊 Progress Tracking

**Total Tasks:** ~150+ tasks
**Completed:** ___ / ___
**In Progress:** ___
**Not Started:** ___

---

*Last Updated: [Current Date]*
*Project: UX-Merchandise E-commerce Platform - PHP Backend Implementation*
