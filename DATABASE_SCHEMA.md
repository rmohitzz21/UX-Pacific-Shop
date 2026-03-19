# MySQLi Database Schema Documentation

## Overview
This document provides comprehensive details about all MySQLi database tables used in the UXMerchandise e-commerce platform. The database follows a relational structure to support user management, product catalog, shopping cart, orders, and wishlist functionality.

---

## Database Tables

### 1. `users` Table
**Purpose**: Stores user account information including customers and administrators.

**Table Structure**:
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

**Columns**:
- `id` - Primary key, auto-incrementing integer
- `email` - Unique email address for login (required)
- `password_hash` - Hashed password using bcrypt (required)
- `first_name` - User's first name (optional)
- `last_name` - User's last name (optional)
- `phone` - Contact phone number (optional)
- `role` - User role: 'customer' or 'admin' (default: 'customer')
- `created_at` - Timestamp of account creation
- `updated_at` - Timestamp of last update

**Used By**:
- User registration (`/api/auth/register.php`)
- User login (`/api/auth/login.php`)
- Admin login (`/api/auth/admin-login.php`)
- User profile (`/api/user/profile.php`)
- Order creation (to link orders to users)
- Admin dashboard (user management)

**Relationships**:
- One-to-many with `orders` table
- One-to-many with `cart` table
- One-to-many with `wishlist` table (if implemented)
- One-to-many with `user_addresses` table (if implemented)

---

### 2. `products` Table
**Purpose**: Stores product catalog information including physical and digital products.

**Table Structure**:
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
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
```

**Columns**:
- `id` - Primary key, auto-incrementing integer
- `name` - Product name (required)
- `description` - Detailed product description (TEXT)
- `category` - Product category (e.g., 'tshirts', 'mockup', 'templates')
- `price` - Current selling price (required, DECIMAL 10,2)
- `old_price` - Previous price for discount display (optional)
- `image` - Product image file path/URL
- `stock` - Available inventory quantity (default: 0)
- `rating` - Average customer rating (DECIMAL 3,2, default: 0)
- `created_at` - Timestamp of product creation
- `updated_at` - Timestamp of last update

**Used By**:
- Product listing (`/api/products/list.php`)
- Single product view (`/api/products/get.php`)
- Product search (`/api/products/search.php`)
- Product filtering (`/api/products/filter.php`)
- Shopping cart (product details)
- Order items (product information)
- Admin product management (`/api/admin/products.php`)
- Wishlist (product references)

**Relationships**:
- One-to-many with `order_items` table
- One-to-many with `cart` table
- One-to-many with `wishlist` table (if implemented)

---

### 3. `orders` Table
**Purpose**: Stores order information including payment details, shipping address, and order status.

**Table Structure**:
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
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

**Columns**:
- `id` - Primary key, auto-incrementing integer
- `order_number` - Unique order identifier (required, unique)
- `user_id` - Foreign key to `users` table (required)
- `total` - Total order amount including all charges (required)
- `subtotal` - Subtotal before shipping and tax (required)
- `shipping` - Shipping cost (default: 50)
- `tax` - Tax amount (required)
- `payment_method` - Payment method used (e.g., 'Credit Card', 'PayPal')
- `status` - Order status: 'Pending', 'Processing', 'Shipped', 'Delivered', 'Cancelled' (default: 'Pending')
- `shipping_address` - Full shipping address as TEXT
- `created_at` - Timestamp of order creation

**Used By**:
- Order creation (`/api/orders/create.php`)
- Order listing (`/api/orders/list.php`)
- Order details (`/api/orders/get.php`)
- Order tracking (`order-tracking.html`)
- Order status update (`/api/orders/update-status.php`) - Admin only
- Admin dashboard (order management)
- Order confirmation page

**Relationships**:
- Many-to-one with `users` table (via `user_id`)
- One-to-many with `order_items` table

---

### 4. `order_items` Table
**Purpose**: Stores individual line items within an order, linking products to orders with quantity and pricing.

**Table Structure**:
```sql
CREATE TABLE order_items (
    id INT PRIMARY KEY AUTO_INCREMENT,
    order_id INT NOT NULL,
    product_id INT NOT NULL,
    quantity INT NOT NULL,
    price DECIMAL(10,2) NOT NULL,
    size VARCHAR(20),
    FOREIGN KEY (order_id) REFERENCES orders(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
);
```

**Columns**:
- `id` - Primary key, auto-incrementing integer
- `order_id` - Foreign key to `orders` table (required)
- `product_id` - Foreign key to `products` table (required)
- `quantity` - Quantity of product ordered (required)
- `price` - Price per unit at time of order (required)
- `size` - Product size/variant (optional, VARCHAR 20)

**Used By**:
- Order creation (when creating order items)
- Order details display (showing order line items)
- Order confirmation page
- Order history page
- Admin order management

**Relationships**:
- Many-to-one with `orders` table (via `order_id`)
- Many-to-one with `products` table (via `product_id`)

---

### 5. `cart` Table
**Purpose**: Stores shopping cart items for logged-in users, persisting cart data across sessions.

**Table Structure**:
```sql
CREATE TABLE cart (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    product_id INT NOT NULL,
    quantity INT NOT NULL DEFAULT 1,
    size VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
);
```

**Columns**:
- `id` - Primary key, auto-incrementing integer
- `user_id` - Foreign key to `users` table (required)
- `product_id` - Foreign key to `products` table (required)
- `quantity` - Quantity of product in cart (default: 1)
- `size` - Product size/variant selection (optional)
- `created_at` - Timestamp when item was added to cart

**Used By**:
- Add to cart (`/api/cart/add.php`)
- Get cart items (`/api/cart/get.php`)
- Update cart quantity (`/api/cart/update.php`)
- Remove from cart (`/api/cart/remove.php`)
- Checkout process (reading cart items)
- Cart page display

**Relationships**:
- Many-to-one with `users` table (via `user_id`)
- Many-to-one with `products` table (via `product_id`)

**Note**: Cart items are typically cleared after successful order creation.

---

## Additional Recommended Tables

### 6. `wishlist` Table (Recommended)
**Purpose**: Stores user wishlist/favorites for products they want to save for later.

**Suggested Table Structure**:
```sql
CREATE TABLE wishlist (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    product_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (product_id) REFERENCES products(id),
    UNIQUE KEY unique_wishlist_item (user_id, product_id)
);
```

**Columns**:
- `id` - Primary key, auto-incrementing integer
- `user_id` - Foreign key to `users` table (required)
- `product_id` - Foreign key to `products` table (required)
- `created_at` - Timestamp when item was added to wishlist

**Used By**:
- Add to wishlist functionality
- Remove from wishlist functionality
- Wishlist page display (`wishlist.html`)
- Product page (wishlist button state)

**Relationships**:
- Many-to-one with `users` table (via `user_id`)
- Many-to-one with `products` table (via `product_id`)

**Note**: Currently implemented in localStorage, but should be migrated to database for multi-device support.

---

### 7. `user_addresses` Table (Recommended)
**Purpose**: Stores saved shipping addresses for users to speed up checkout.

**Suggested Table Structure**:
```sql
CREATE TABLE user_addresses (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    address_type VARCHAR(50) DEFAULT 'home',
    full_name VARCHAR(255),
    address TEXT NOT NULL,
    city VARCHAR(100),
    state VARCHAR(100),
    postal_code VARCHAR(20),
    country VARCHAR(100),
    phone VARCHAR(20),
    is_default BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

**Columns**:
- `id` - Primary key, auto-incrementing integer
- `user_id` - Foreign key to `users` table (required)
- `address_type` - Type of address: 'home', 'work', 'other' (default: 'home')
- `full_name` - Full name for delivery
- `address` - Street address (required)
- `city` - City name
- `state` - State/Province
- `postal_code` - ZIP/Postal code
- `country` - Country name
- `phone` - Contact phone for delivery
- `is_default` - Whether this is the default address (default: FALSE)
- `created_at` - Timestamp of address creation
- `updated_at` - Timestamp of last update

**Used By**:
- Get saved addresses (`/api/user/addresses.php`)
- Add address (`/api/user/add-address.php`)
- Update address
- Delete address
- Checkout page (address selection)
- Account page (`account.html` - Addresses tab)

**Relationships**:
- Many-to-one with `users` table (via `user_id`)

**Note**: Currently implemented in localStorage, but should be migrated to database for persistence.

---

## Database Relationships Diagram

```
users
  ├── orders (one-to-many)
  ├── cart (one-to-many)
  ├── wishlist (one-to-many) [recommended]
  └── user_addresses (one-to-many) [recommended]

products
  ├── order_items (one-to-many)
  ├── cart (one-to-many)
  └── wishlist (one-to-many) [recommended]

orders
  └── order_items (one-to-many)
```

---

## Table Usage Summary

| Table Name | Primary Use Case | Key Operations |
|------------|------------------|----------------|
| `users` | User authentication and profiles | Login, Registration, Profile Management |
| `products` | Product catalog | Browse, Search, Filter, Display |
| `orders` | Order management | Create, View, Track, Update Status |
| `order_items` | Order line items | Store order details, Display order contents |
| `cart` | Shopping cart | Add, Update, Remove, Checkout |
| `wishlist` | User favorites | Add, Remove, Display wishlist |
| `user_addresses` | Saved addresses | Save, Update, Delete, Select at checkout |

---

## API Endpoints Using Each Table

### Users Table
- `POST /api/auth/login.php`
- `POST /api/auth/register.php`
- `POST /api/auth/admin-login.php`
- `GET /api/user/profile.php`
- `POST /api/user/update-profile.php`
- `GET /api/admin/users.php`

### Products Table
- `GET /api/products/list.php`
- `GET /api/products/get.php`
- `GET /api/products/search.php`
- `GET /api/products/filter.php`
- `GET /api/admin/products.php`
- `POST /api/admin/product/create.php`
- `POST /api/admin/product/update.php`
- `POST /api/admin/product/delete.php`

### Orders Table
- `POST /api/orders/create.php`
- `GET /api/orders/list.php`
- `GET /api/orders/get.php`
- `POST /api/orders/update-status.php`
- `GET /api/admin/orders.php`
- `GET /api/admin/stats.php`

### Order Items Table
- `POST /api/orders/create.php` (creates order items)
- `GET /api/orders/get.php` (includes order items)
- `GET /api/orders/list.php` (may include order items)

### Cart Table
- `GET /api/cart/get.php`
- `POST /api/cart/add.php`
- `POST /api/cart/update.php`
- `POST /api/cart/remove.php`

### Wishlist Table (Recommended)
- `GET /api/wishlist/get.php` (to be implemented)
- `POST /api/wishlist/add.php` (to be implemented)
- `POST /api/wishlist/remove.php` (to be implemented)

### User Addresses Table (Recommended)
- `GET /api/user/addresses.php`
- `POST /api/user/add-address.php`
- `POST /api/user/update-address.php` (to be implemented)
- `POST /api/user/delete-address.php` (to be implemented)

---

## MySQLi Connection Example

```php
<?php
// includes/config.php
$host = 'localhost';
$username = 'your_username';
$password = 'your_password';
$database = 'ux_merchandise_db';

// Create connection
$conn = new mysqli($host, $username, $password, $database);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Set charset to utf8mb4 for proper character encoding
$conn->set_charset("utf8mb4");
?>
```

---

## Security Considerations

1. **Prepared Statements**: Always use prepared statements to prevent SQL injection
   ```php
   $stmt = $conn->prepare("SELECT * FROM users WHERE email = ?");
   $stmt->bind_param("s", $email);
   $stmt->execute();
   ```

2. **Password Hashing**: Use `password_hash()` and `password_verify()` for passwords
   ```php
   $password_hash = password_hash($password, PASSWORD_DEFAULT);
   ```

3. **Input Validation**: Validate and sanitize all user inputs before database operations

4. **Foreign Key Constraints**: Ensure referential integrity with foreign keys

5. **Indexes**: Add indexes on frequently queried columns (email, user_id, product_id, order_number)

---

## Notes

- All timestamps use `TIMESTAMP` type with automatic defaults
- Decimal fields use `DECIMAL(10,2)` for currency values
- Foreign keys ensure data integrity
- The `wishlist` and `user_addresses` tables are recommended but currently implemented in localStorage
- Consider adding indexes on foreign key columns for better query performance
- The `orders.status` field uses ENUM for controlled status values
- The `users.role` field uses ENUM to restrict to 'customer' or 'admin' only

---

**Last Updated**: January 2025
**Database Version**: MySQL 5.7+ / MariaDB 10.2+
