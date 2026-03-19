# Admin Dashboard Documentation

## Admin Access

### Login Credentials
- **URL**: `admin-login.html`
- **Email**: `admin@uxpacific.com`
- **Password**: `admin123`

### Features

1. **Overview Dashboard**
   - Total Users count
   - Total Products count
   - Total Orders count
   - Total Revenue
   - Recent Orders table

2. **Users Management**
   - View all registered users
   - User details (name, email, phone, registration date)
   - Number of orders per user
   - Search functionality

3. **Products Management**
   - View all products
   - Product details (image, name, category, price, stock, rating)
   - Search and filter by category
   - Edit/Delete actions (UI ready, backend integration needed)

4. **Orders Management**
   - View all orders
   - Order details (ID, customer, items, date, amount, payment method, status)
   - Search and filter by status
   - Update order status
   - View order details

5. **Analytics**
   - Today's revenue
   - This month's revenue
   - Average order value
   - Conversion rate
   - Top selling products

## Security Notes

- Admin authentication is handled via localStorage (frontend only)
- In production, this should be replaced with secure backend authentication
- Admin session is checked on every page load
- Non-admin users are redirected to login page

## Data Sources

- **Users**: Extracted from localStorage (userSession) and orders
- **Products**: From script.js products object
- **Orders**: From localStorage 'orders' array

## Workflow

1. Admin logs in at `admin-login.html`
2. Admin session is stored in localStorage
3. Dashboard loads data from localStorage
4. Admin can navigate between tabs
5. Admin can search and filter data
6. Admin can update order statuses
7. Admin can logout (clears session)

