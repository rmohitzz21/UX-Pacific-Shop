// Admin Dashboard JavaScript

// Check admin authentication
function checkAdminAuth() {
  const adminSession = JSON.parse(localStorage.getItem('adminSession'));
  if (!adminSession || !adminSession.isAdmin) {
    window.location.href = 'admin-login.php';
    return false;
  }
  return true;
}

// Admin logout
function handleAdminLogout() {
  if (confirm('Are you sure you want to logout?')) {
    localStorage.removeItem('adminSession');
    window.location.href = 'admin-login.php';
  }
}

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function() {
  if (!checkAdminAuth()) return;
  
  const adminSession = JSON.parse(localStorage.getItem('adminSession'));
  if (adminSession && adminSession.email) {
    document.getElementById('admin-email-display').textContent = adminSession.email;
  }
  
  // Setup tab navigation
  setupTabNavigation();
  
  // Load all data
  loadOverview();
  loadUsers();
  loadProducts();
  loadOrders();
  loadAnalytics();
});

// Tab Navigation (updated for sidebar)
function setupTabNavigation() {
  // Sidebar navigation items
  document.querySelectorAll('.sidebar-nav-item').forEach(item => {
    item.addEventListener('click', function(e) {
      e.preventDefault();
      const tab = this.dataset.tab;
      
      // Update sidebar nav
      document.querySelectorAll('.sidebar-nav-item').forEach(nav => nav.classList.remove('active'));
      this.classList.add('active');
      
      // Update tabs
      document.querySelectorAll('.admin-tab').forEach(t => t.classList.remove('active'));
      document.getElementById(tab + '-tab').classList.add('active');
      
      // Reload data for active tab
      if (tab === 'overview') loadOverview();
      else if (tab === 'users') loadUsers();
      else if (tab === 'products') loadProducts();
      else if (tab === 'orders') loadOrders();
      else if (tab === 'analytics') loadAnalytics();
      
      // Close mobile sidebar
      if (window.innerWidth <= 1024) {
        const sidebar = document.getElementById('admin-sidebar');
        const overlay = document.getElementById('sidebar-overlay');
        sidebar.classList.remove('open');
        overlay.classList.remove('active');
      }
    });
  });
}

// Load Overview Data
async function loadOverview() {
  const users = getAllUsers();
  const products = await fetchProducts();
  const orders = getAllOrders();
  
  // Update stats
  document.getElementById('stat-total-users').textContent = users.length;
  document.getElementById('stat-total-products').textContent = products.length;
  document.getElementById('stat-total-orders').textContent = orders.length;
  
  const totalRevenue = orders.reduce((sum, order) => sum + (order.total || 0), 0);
  document.getElementById('stat-total-revenue').textContent = `$${totalRevenue.toLocaleString()}`;
  
  // Load recent orders
  const recentOrders = orders.slice(0, 5).reverse();
  const recentOrdersTable = document.getElementById('recent-orders-table');
  
  if (recentOrders.length === 0) {
    recentOrdersTable.innerHTML = '<tr><td colspan="5" class="empty-state">No orders yet</td></tr>';
    return;
  }
  
  recentOrdersTable.innerHTML = recentOrders.map(order => {
    const orderDate = new Date(order.date || Date.now());
    const statusBadge = getStatusBadge(order.status || 'Pending');
    return `
      <tr>
        <td>${order.orderNumber || 'N/A'}</td>
        <td>${getOrderCustomerName(order)}</td>
        <td>${orderDate.toLocaleDateString()}</td>
        <td>$${(order.total || 0).toLocaleString()}</td>
        <td>${statusBadge}</td>
      </tr>
    `;
  }).join('');
}

// Load Users
// Load Users
async function loadUsers() {
  const usersTable = document.getElementById('users-table');
  if (!usersTable) return;

  try {
    const apiUsers = await fetchUsers();
    
    // Use only API users (Source of Truth)
    const allUsers = apiUsers;
    
    if (allUsers.length === 0) {
      usersTable.innerHTML = '<tr><td colspan="6" class="empty-state">No users found</td></tr>';
      return;
    }
    
    usersTable.innerHTML = allUsers.map(user => {
      // Handle various date formats
      let dateString = 'N/A';
      if (user.created_at) {
        dateString = new Date(user.created_at).toLocaleDateString();
      } else if (user.loginTime) {
        dateString = new Date(user.loginTime).toLocaleDateString();
      }
      
      // Orders currently purely local storage
      const orders = getAllOrders().filter(o => getOrderEmail(o) === user.email);
      
      // API returns first_name/last_name (snake_case), localStorage might use camelCase
      const firstName = user.first_name || user.firstName || '';
      const lastName = user.last_name || user.lastName || '';
      const fullName = `${firstName} ${lastName}`.trim();
      
      const displayName = user.name || fullName || user.username || 'N/A';
      
      return `
        <tr>
          <td>${displayName}</td>
          <td>${user.email || 'N/A'}</td>
          <td>${user.phone || 'N/A'}</td>
          <td>${dateString}</td>
          <td>${orders.length}</td>
          <td>
            ${user.is_blocked == 1 
              ? '<span class="badge badge-danger">Blocked</span>' 
              : '<span class="badge badge-success">Active</span>'}
          </td>
          <td>
            <button 
              class="btn-small ${user.is_blocked == 1 ? 'btn-success' : 'btn-delete'}" 
              onclick="toggleUserStatus(${user.id}, ${user.is_blocked == 1 ? 'true' : 'false'})"
            >
              ${user.is_blocked == 1 ? 'Unblock' : 'Block'}
            </button>
          </td>
        </tr>
      `;
    }).join('');
  } catch (error) {
    console.error('Error loading users:', error);
    usersTable.innerHTML = '<tr><td colspan="6" class="empty-state">Error loading users</td></tr>';
  }
}

// ... existing code ...

// Edit Product Functions
async function editProduct(productId) {
  try {
      // Fetch product details
      const response = await fetch(`../api/admin/product/get.php?id=${productId}`);
      const result = await response.json();
      
      if (result.status === 'success' && result.data) {
          const p = result.data;
          // Populate form
          const setVal = (id, val) => {
             const el = document.getElementById(id);
             if(el) el.value = val;
          };
          
          setVal('edit-product-id', p.id);
          setVal('edit-product-name', p.name);
          setVal('edit-product-category', p.category);
          setVal('edit-product-price', p.price);
          setVal('edit-product-stock', p.stock || 0);
          setVal('edit-product-rating', p.rating || 0);
          setVal('edit-product-description', p.description || '');
          
          const previewEl = document.getElementById('current-image-preview');
          if (previewEl) {
              if (p.image) {
                  // Ensure path is correct relative to admin folder
                  const imagePath = p.image.startsWith('img/') ? '../' + p.image : p.image;
                  previewEl.innerHTML = `
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <img src="${imagePath}" alt="Current Product Image" style="width: 60px; height: 60px; object-fit: cover; border-radius: 4px; border: 1px solid #ddd;">
                       <span>Current Image (<a href="${imagePath}" target="_blank">View Full</a>)</span>
                    </div>`;
              } else {
                  previewEl.innerHTML = 'No image currently set.';
              }
          }
          
          openEditProductModal();
      } else {
          alert('Failed to fetch product details.');
      }
  } catch (e) {
      console.error(e);
      alert('Error fetching product details.');
  }
}





async function fetchUsers(){
  try {
    const response = await fetch('../api/admin/user/list.php');

    if(!response.ok){
      throw new Error(`HTTP error ! status : ${response.status}`);
    }

    const result = await response.json();
    return result.data || [];
  } catch (error) {
    console.error('Error fetching users : ',error);
    return [];
  }
}

// Load Products
async function loadProducts() {
  const productsTable = document.getElementById('products-table');
  productsTable.innerHTML = '<tr><td colspan="7" style="text-align:center; padding: 2rem;">Loading products...</td></tr>';
  
  try {
    const products = await fetchProducts();
    
    if (products.length === 0) {
      productsTable.innerHTML = '<tr><td colspan="7" class="empty-state">No products found</td></tr>';
      return;
    }
    
    productsTable.innerHTML = products.map(product => {
      const category = product.category || 'Uncategorized';
      const categoryBadge = `<span class="badge badge-info">${category}</span>`;
      
      return `
        <tr>
          <td><img src="${product.image ? '../' + product.image : '../img/sticker.webp'}" alt="${product.name}" class="product-image" onerror="this.src='../img/sticker.webp'"></td>
          <td>${product.name || 'N/A'}</td>
          <td>${categoryBadge}</td>
          <td>$${parseFloat(product.price || 0).toLocaleString()}</td>
          <td>${product.stock || 0}</td>
          <td>★ ${product.rating || '0.0'}</td>
          <td>
            <div class="action-buttons">
              <button class="btn-small btn-edit" onclick="editProduct('${product.id}')">Edit</button>
              <button class="btn-small btn-delete" onclick="deleteProduct('${product.id}')">Delete</button>
            </div>
          </td>
        </tr>
      `;
    }).join('');
  } catch (error) {
    console.error('Error loading products:', error);
    productsTable.innerHTML = '<tr><td colspan="7" class="empty-state" style="color:red;">Error loading products. Please try again later.</td></tr>';
  }
}

// Fetch products from API
async function fetchProducts() {
  try {
    const response = await fetch('../api/admin/product/list.php');
    if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
    }
    const result = await response.json();
    return result.data || [];
  } catch (error) {
    console.error('Fetch products error:', error);
    return [];
  }
}

// Load Orders
function loadOrders() {
  const orders = getAllOrders();
  const ordersTable = document.getElementById('orders-table');
  
  if (orders.length === 0) {
    ordersTable.innerHTML = '<tr><td colspan="8" class="empty-state">No orders found</td></tr>';
    return;
  }
  
  ordersTable.innerHTML = orders.reverse().map(order => {
    const orderDate = new Date(order.date || Date.now());
    const statusBadge = getStatusBadge(order.status || 'Pending');
    const itemsCount = order.items ? order.items.length : 0;
    const paymentMethod = order.paymentMethod || 'card';
    const paymentBadge = `<span class="badge badge-info">${paymentMethod.toUpperCase()}</span>`;
    
    return `
      <tr>
        <td>${order.orderNumber || 'N/A'}</td>
        <td>${getOrderCustomerName(order)}</td>
        <td>${itemsCount} item(s)</td>
        <td>${orderDate.toLocaleDateString()}</td>
        <td>$${(order.total || 0).toLocaleString()}</td>
        <td>${paymentBadge}</td>
        <td>${statusBadge}</td>
        <td>
          <div class="action-buttons">
            <button class="btn-small btn-edit" onclick="viewOrder('${order.orderNumber}')">View</button>
            <button class="btn-small btn-edit" onclick="updateOrderStatus('${order.orderNumber}')">Update</button>
          </div>
        </td>
      </tr>
    `;
  }).join('');
}

// Load Analytics
function loadAnalytics() {
  const orders = getAllOrders();
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  
  // Today's revenue
  const todayOrders = orders.filter(o => {
    const orderDate = new Date(o.date || Date.now());
    orderDate.setHours(0, 0, 0, 0);
    return orderDate.getTime() === today.getTime();
  });
  const todayRevenue = todayOrders.reduce((sum, o) => sum + (o.total || 0), 0);
  document.getElementById('analytics-today-revenue').textContent = `$${todayRevenue.toLocaleString()}`;
  
  // This month's revenue
  const thisMonth = new Date(today.getFullYear(), today.getMonth(), 1);
  const monthOrders = orders.filter(o => {
    const orderDate = new Date(o.date || Date.now());
    return orderDate >= thisMonth;
  });
  const monthRevenue = monthOrders.reduce((sum, o) => sum + (o.total || 0), 0);
  document.getElementById('analytics-month-revenue').textContent = `$${monthRevenue.toLocaleString()}`;
  
  // Average order value
  const avgOrder = orders.length > 0 ? orders.reduce((sum, o) => sum + (o.total || 0), 0) / orders.length : 0;
  document.getElementById('analytics-avg-order').textContent = `$${Math.round(avgOrder).toLocaleString()}`;
  
  // Conversion rate (simplified - would need actual visitor data)
  const users = getAllUsers();
  const conversionRate = users.length > 0 ? (orders.length / users.length * 100).toFixed(1) : 0;
  document.getElementById('analytics-conversion').textContent = `${conversionRate}%`;
  
  // Top selling products
  const productSales = {};
  orders.forEach(order => {
    if (order.items) {
      order.items.forEach(item => {
        if (!productSales[item.id]) {
          productSales[item.id] = { name: item.name, category: item.category || 'Uncategorized', sold: 0, revenue: 0 };
        }
        productSales[item.id].sold += item.quantity || 1;
        productSales[item.id].revenue += (item.price || 0) * (item.quantity || 1);
      });
    }
  });
  
  const topProducts = Object.values(productSales)
    .sort((a, b) => b.sold - a.sold)
    .slice(0, 10);
  
  const topProductsTable = document.getElementById('top-products-table');
  if (topProducts.length === 0) {
    topProductsTable.innerHTML = '<tr><td colspan="4" class="empty-state">No sales data available</td></tr>';
    return;
  }
  
  topProductsTable.innerHTML = topProducts.map(product => `
    <tr>
      <td>${product.name}</td>
      <td><span class="badge badge-info">${product.category}</span></td>
      <td>${product.sold}</td>
      <td>$${product.revenue.toLocaleString()}</td>
    </tr>
  `).join('');
}

// Helper Functions
function getAllUsers() {
  // Get users from localStorage (from signup/signin)
  const users = [];
  const userSession = JSON.parse(localStorage.getItem('userSession'));
  if (userSession && userSession.email) {
    users.push(userSession);
  }
  
  // Also get users from orders
  const orders = getAllOrders();
  orders.forEach(order => {
    if (order.shipping && order.shipping.email) {
      const existingUser = users.find(u => u.email === order.shipping.email);
      if (!existingUser) {
        users.push({
          email: order.shipping.email,
          name: `${order.shipping.firstName || ''} ${order.shipping.lastName || ''}`.trim(),
          firstName: order.shipping.firstName,
          lastName: order.shipping.lastName,
          phone: order.shipping.phone
        });
      }
    }
  });
  
  return users;
}



function getAllOrders() {
  return JSON.parse(localStorage.getItem('orders')) || [];
}

function getOrderCustomerName(order) {
  if (order.shipping) {
    return `${order.shipping.firstName || ''} ${order.shipping.lastName || ''}`.trim() || 'N/A';
  }
  return 'N/A';
}

function getOrderEmail(order) {
  if (order.shipping && order.shipping.email) {
    return order.shipping.email;
  }
  return null;
}

function getStatusBadge(status) {
  const badges = {
    'Pending': '<span class="badge badge-warning">Pending</span>',
    'Processing': '<span class="badge badge-info">Processing</span>',
    'Shipped': '<span class="badge badge-info">Shipped</span>',
    'Delivered': '<span class="badge badge-success">Delivered</span>',
    'Cancelled': '<span class="badge badge-danger">Cancelled</span>'
  };
  return badges[status] || '<span class="badge badge-warning">Pending</span>';
}

// Filter Functions
function filterUsers() {
  const search = document.getElementById('user-search').value.toLowerCase();
  const rows = document.querySelectorAll('#users-table tr');
  
  rows.forEach(row => {
    const text = row.textContent.toLowerCase();
    row.style.display = text.includes(search) ? '' : 'none';
  });
}

function filterProducts() {
  const search = document.getElementById('product-search').value.toLowerCase();
  const category = document.getElementById('product-category-filter').value.toLowerCase();
  const rows = document.querySelectorAll('#products-table tr');
  
  rows.forEach(row => {
    const text = row.textContent.toLowerCase();
    const matchesSearch = text.includes(search);
    const matchesCategory = !category || text.includes(category);
    row.style.display = (matchesSearch && matchesCategory) ? '' : 'none';
  });
}

function filterOrders() {
  const search = document.getElementById('order-search').value.toLowerCase();
  const status = document.getElementById('order-status-filter').value.toLowerCase();
  const rows = document.querySelectorAll('#orders-table tr');
  
  rows.forEach(row => {
    const text = row.textContent.toLowerCase();
    const matchesSearch = text.includes(search);
    const matchesStatus = !status || text.includes(status);
    row.style.display = (matchesSearch && matchesStatus) ? '' : 'none';
  });
}

// Action Functions
// Edit Product Functions
async function editProduct(productId) {
  try {
      // Fetch product details
      const response = await fetch(`../api/admin/product/get.php?id=${productId}`);
      const result = await response.json();
      
      if (result.status === 'success' && result.data) {
          const p = result.data;
          // Populate form
          document.getElementById('edit-product-id').value = p.id;
          document.getElementById('edit-product-name').value = p.name;
          document.getElementById('edit-product-category').value = p.category;
          document.getElementById('edit-product-price').value = p.price;
          document.getElementById('edit-product-stock').value = p.stock || 0;
          document.getElementById('edit-product-rating').value = p.rating || 0; 
          document.getElementById('edit-product-description').value = p.description || '';
          
          if (p.image) {
              document.getElementById('current-image-preview').innerHTML = `Current: <a href="${p.image}" target="_blank">View Image</a>`;
          } else {
              document.getElementById('current-image-preview').innerHTML = 'No image currently set.';
          }
          
          openEditProductModal();
      } else {
          alert('Failed to fetch product details.');
      }
  } catch (e) {
      console.error(e);
      alert('Error fetching product details.');
  }
}

function openEditProductModal() {
  const modal = document.getElementById('edit-product-modal-overlay');
  if (modal) {
    modal.classList.add('active');
    document.body.style.overflow = 'hidden';
  }
}

function closeEditProductModal() {
  const modal = document.getElementById('edit-product-modal-overlay');
  if (modal) {
    modal.classList.remove('active');
    document.body.style.overflow = '';
    // Reset form
    document.getElementById('edit-product-form').reset();
    document.getElementById('current-image-preview').innerHTML = '';
  }
}

async function handleUpdateProduct(event) {
    event.preventDefault();
    const form = event.target;
    const btn = form.querySelector('button[type="submit"]');
    const originalText = btn.innerText;
    
    btn.disabled = true;
    btn.innerText = 'Saving...';
    
    try {
        const formData = new FormData(form);
        const response = await fetch('../api/admin/product/update.php', {
            method: 'POST',
            body: formData
        });
        const result = await response.json();
        
        if (result.status === 'success') {
            alert('Product updated successfully');
            closeEditProductModal();
            loadProducts(); // Reload list
            loadOverview(); // Reload stats
        } else {
            alert(result.message || 'Update failed');
        }
    } catch (e) {
        alert('Error updating product: ' + e.message);
    } finally {
        btn.disabled = false;
        btn.innerText = originalText;
    }
}



async function deleteProduct(productId) {
  if (!confirm('Are you sure you want to delete this product?')) return;

  // Attempt to find the button to show loading state (optional best effort)
  const btn = document.querySelector(`button[onclick="deleteProduct('${productId}')"]`);
  let originalText = 'Delete';
  if (btn) {
    originalText = btn.innerText;
    btn.disabled = true;
    btn.innerText = 'Deleting...';
  }

  try {
    const formData = new FormData();
    formData.append('id', productId);

    const response = await fetch('../api/admin/product/delete.php', {
      method: 'POST',
      body: formData
    });

    const result = await response.json();

    if (result.status === 'success') {
      // Refresh data
      loadProducts();
      loadOverview();
    } else {
      alert(result.message || 'Delete failed');
    }

  } catch (e) {
    alert('Error deleting product: ' + e.message);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerText = originalText;
    }
  }
}




async function toggleUserStatus(userId, isBlocked) {
  const action = isBlocked ? 'unblock' : 'block';
  const confirmMsg = isBlocked 
    ? 'Are you sure you want to UNBLOCK this user?' 
    : 'Are you sure you want to BLOCK this user?';

  if (!confirm('Are you sure you want to change this user\'s status?')) return;

  try {
    const response = await fetch('../api/admin/user/block.php', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        id: userId,
        action: action
      })
    });

    const result = await response.json();

    if (result.status === 'success') {
      // Reload users to reflect change
      loadUsers();
      // Optional: Show success message, or just let the table update speak for itself
    } else {
      alert(result.message || 'Failed to update user status');
    }
  } catch (error) {
    console.error('Error toggling user status:', error);
    alert('An error occurred while updating user status');
  }
}

function viewOrder(orderNumber) {
  alert(`View order ${orderNumber} - This would show order details in a real application.`);
}

// Modal UI Functions (UI only - no logic)
function updateOrderStatus(orderNumber) {
  // Open the modal - UI only
  openStatusModal();
}

function openStatusModal() {
  const modal = document.getElementById('status-modal-overlay');
  if (modal) {
    modal.classList.add('active');
    document.body.style.overflow = 'hidden'; // Prevent background scrolling
  }
}

function closeStatusModal() {
  const modal = document.getElementById('status-modal-overlay');
  if (modal) {
    modal.classList.remove('active');
    document.body.style.overflow = ''; // Restore scrolling
  }
}

function confirmStatusUpdate() {
  // UI only - just close the modal
  // Backend logic will be added later
  alert('Status update functionality will be implemented with backend integration.');
  closeStatusModal();
}

// Close modal on Escape key
document.addEventListener('keydown', function(event) {
  if (event.key === 'Escape') {
    closeStatusModal();
  }
});

// Make functions globally available
window.handleAdminLogout = handleAdminLogout;
window.filterUsers = filterUsers;
window.filterProducts = filterProducts;
window.filterOrders = filterOrders;
window.editProduct = editProduct;
window.closeEditProductModal = closeEditProductModal;
window.handleUpdateProduct = handleUpdateProduct;
window.deleteProduct = deleteProduct;
window.viewOrder = viewOrder;
window.updateOrderStatus = updateOrderStatus;
window.openStatusModal = openStatusModal;
window.closeStatusModal = closeStatusModal;
window.confirmStatusUpdate = confirmStatusUpdate;
window.toggleUserStatus = toggleUserStatus;


