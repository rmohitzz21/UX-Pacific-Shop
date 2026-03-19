<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8" />
  <title>My Account – UX Pacific Shop</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap"
    rel="stylesheet" />
  <link rel="stylesheet" href="style.css" />
</head>

<body>
  <div class="page">
    <!-- NAVBAR -->
    <header class="site-header" id="navbar">
      <nav class="nav-bar">
        <div class="nav-logo">
          <a href="index.php">
            <img src="img/LOGO.webp" alt="UX Pacific" />
          </a>
        </div>

        <ul class="nav-links">
          <li><a href="index.php" class="nav-link">Home</a></li>
          <li><a href="index.php#story" class="nav-link">About Us</a></li>
          <li><a href="index.php#products" class="nav-link">New</a></li>
          <li><a href="shopAll.php" class="nav-link">Buy Now</a></li>
        </ul>

        <div class="nav-actions">
          <a href="cart.php" class="nav-cart">
            <img src="img/cart-icon.webp" alt="Shopping cart" />
            <span id="cart-count">0</span>
          </a>
          <a href="signin.php" class="nav-cta">Sign in</a>
          <div class="nav-user">
            <div class="user-avatar"></div>
            <div class="user-info">
              <span class="user-name">User</span>
              <span class="user-role">Customer</span>
            </div>
            <div class="user-dropdown">
              <a href="account.php" class="user-dropdown-item">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                  <circle cx="12" cy="7" r="4"></circle>
                </svg>
                <span>My Account</span>
              </a>
              <a href="cart.php" class="user-dropdown-item">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <circle cx="9" cy="21" r="1"></circle>
                  <circle cx="20" cy="21" r="1"></circle>
                  <path d="M1 1h4l2.68 13.39a2 2 0 0 0 2 1.61h9.72a2 2 0 0 0 2-1.61L23 6H6"></path>
                </svg>
                <span>My Cart</span>
              </a>
              <a href="orders.php" class="user-dropdown-item">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"></path>
                  <rect x="8" y="2" width="8" height="4" rx="1" ry="1"></rect>
                </svg>
                <span>My Orders</span>
              </a>
              <div class="user-dropdown-divider"></div>
              <a href="#" onclick="handleSignOut(); return false;" class="user-dropdown-item logout">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path>
                  <polyline points="16 17 21 12 16 7"></polyline>
                  <line x1="21" y1="12" x2="9" y2="12"></line>
                </svg>
                <span>Sign Out</span>
              </a>
            </div>
          </div>
        </div>

        <button id="mobile-menu-btn" class="nav-toggle" aria-label="Toggle navigation">
          <span></span>
          <span></span>
          <span></span>
        </button>
      </nav>

      <div id="mobile-menu" class="nav-mobile-menu">
        <a href="index.php" class="nav-mobile-link">Home</a>
        <a href="index.php#story" class="nav-mobile-link">About Us</a>
        <a href="index.php#products" class="nav-mobile-link">New</a>
        <a href="shopAll.php" class="nav-mobile-link">Buy Now</a>
        <a href="cart.php" class="nav-mobile-link">Cart</a>
        <a href="signin.php" class="nav-mobile-link nav-mobile-cta">
          Sign in
        </a>
      </div>
    </header>

    <!-- MAIN CONTENT -->
    <main class="main">
      <section class="account-section">
        <div class="account-container">
          <h1 class="account-title">My Account</h1>

          <div class="account-layout">
            <!-- Account Sidebar -->
            <aside class="account-sidebar">
              <div class="account-profile">
                <div class="profile-avatar">
                  <span id="profile-initial">U</span>
                </div>
                <h3 id="profile-name">User Name</h3>
                <p id="profile-email">user@example.com</p>
              </div>

              <nav class="account-nav">
                <a href="#profile" class="account-nav-item active" data-tab="profile">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                    <circle cx="12" cy="7" r="4"></circle>
                  </svg>
                  <span>Profile</span>
                </a>
                <a href="#addresses" class="account-nav-item" data-tab="addresses">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"></path>
                    <circle cx="12" cy="10" r="3"></circle>
                  </svg>
                  <span>Addresses</span>
                </a>
                <a href="#orders" class="account-nav-item" data-tab="orders">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"></path>
                    <rect x="8" y="2" width="8" height="4" rx="1" ry="1"></rect>
                  </svg>
                  <span>Orders</span>
                </a>
                <a href="#settings" class="account-nav-item" data-tab="settings">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="12" cy="12" r="3"></circle>
                    <path
                      d="M12 1v6m0 6v6M5.64 5.64l4.24 4.24m4.24 4.24l4.24 4.24M1 12h6m6 0h6M5.64 18.36l4.24-4.24m4.24-4.24l4.24-4.24">
                    </path>
                  </svg>
                  <span>Settings</span>
                </a>
              </nav>
            </aside>

            <!-- Account Content -->
            <div class="account-content">
              <!-- Profile Tab -->
              <div class="account-tab active" id="profile-tab">
                <h2 class="tab-title">Profile Information</h2>
                <form class="account-form" id="profile-form">
                  <div class="form-row">
                    <div class="form-field">
                      <label for="first-name">First Name *</label>
                      <input id="first-name" name="firstName" type="text" required />
                    </div>
                    <div class="form-field">
                      <label for="last-name">Last Name *</label>
                      <input id="last-name" name="lastName" type="text" required />
                    </div>
                  </div>

                  <div class="form-field">
                    <label for="email">Email Address *</label>
                    <input id="email" name="email" type="email" required readonly />
                  </div>

                  <div class="form-field">
                    <label for="phone">Phone Number</label>
                    <input id="phone" name="phone" type="tel" placeholder="+91 xxxxx-xxxxx" />
                  </div>

                  <div class="form-actions">
                    <button type="submit" class="btn-primary">Save Changes</button>
                    <button type="button" class="btn-ghost" onclick="resetProfileForm()">Cancel</button>
                  </div>
                </form>
              </div>

              <!-- Addresses Tab -->
              <div class="account-tab" id="addresses-tab">
                <div class="tab-header">
                  <h2 class="tab-title">Saved Addresses</h2>
                </div>

                <button class="btn-primary small" onclick="showAddAddressForm()" style="width: 180px; height: 41px; text-align: center;margin-bottom: 25px;
">Add Address</button>


                <div id="addresses-list" class="addresses-list">
                  <!-- Addresses will be loaded here -->
                </div>

                <!-- Add Address Form (hidden by default) -->
                <div id="add-address-form" class="address-form" style="display: none;">
                  <h3>Add New Address</h3>
                  <form id="new-address-form">
                    <div class="form-row">
                      <div class="form-field">
                        <label>First Name *</label>
                        <input type="text" name="firstName" required />
                      </div>
                      <div class="form-field">
                        <label>Last Name *</label>
                        <input type="text" name="lastName" required />
                      </div>
                    </div>
                    <div class="form-field">
                      <label>Street Address *</label>
                      <input type="text" name="address" required />
                    </div>
                    <div class="form-row">
                      <div class="form-field">
                        <label>City *</label>
                        <input type="text" name="city" required />
                      </div>
                      <div class="form-field">
                        <label>State *</label>
                        <input type="text" name="state" required />
                      </div>
                    </div>
                    <div class="form-row">
                      <div class="form-field">
                        <label>ZIP Code *</label>
                        <input type="text" name="zip" required />
                      </div>
                      <div class="form-field" >
                        <label>Country *</label>
                        <select name="country" required style="background-color: #050519; color: #fff;">
                          <option value="IN">India</option>
                          <option value="US">United States</option>
                          <option value="UK">United Kingdom</option>
                          <option value="CA">Canada</option>
                          <option value="AU">Australia</option>
                        </select>
                      </div>
                    </div>
                    <div class="form-field">
                      <label>Phone Number *</label>
                      <input type="tel" name="phone" required />
                    </div>
                    <div class="form-actions">
                      <button type="submit" class="btn-primary">Save Address</button>
                      <button type="button" class="btn-ghost" onclick="hideAddAddressForm()">Cancel</button>
                    </div>
                  </form>
                </div>
              </div>

              <!-- Orders Tab -->
              <div class="account-tab" id="orders-tab">
                <h2 class="tab-title">Recent Orders</h2>
                <div id="account-orders-list">
                  <!-- Orders will be loaded here -->
                </div>
                <div class="tab-actions">
                  <a href="orders.php" class="btn-primary">View All Orders</a>
                </div>
              </div>

              <!-- Settings Tab -->
              <div class="account-tab" id="settings-tab">
                <h2 class="tab-title">Account Settings</h2>

                <div class="settings-section">
                  <h3>Change Password</h3>
                  <form class="account-form" id="password-form">
                    <div class="form-field">
                      <label for="current-password">Current Password *</label>
                      <input id="current-password" name="currentPassword" type="password" required />
                    </div>
                    <div class="form-field">
                      <label for="new-password">New Password *</label>
                      <input id="new-password" name="newPassword" type="password" required minlength="8" />
                    </div>
                    <div class="form-field">
                      <label for="confirm-password">Confirm New Password *</label>
                      <input id="confirm-password" name="confirmPassword" type="password" required minlength="8" />
                    </div>
                    <div class="form-actions">
                      <button type="submit" class="btn-primary">Update Password</button>
                    </div>
                  </form>
                </div>

                <div class="settings-section">
                  <h3>Notification Preferences</h3>
                  <form class="account-form">
                    <div class="checkbox-label">
                      <input type="checkbox" id="email-notifications" checked />
                      <label for="email-notifications">Email notifications</label>
                    </div>
                    <div class="checkbox-label">
                      <input type="checkbox" id="sms-notifications" />
                      <label for="sms-notifications">SMS notifications</label>
                    </div>
                    <div class="form-actions">
                      <button type="button" class="btn-primary" onclick="saveNotificationSettings()">Save
                        Preferences</button>
                    </div>
                  </form>
                </div>

                <div class="settings-section danger-zone">
                  <h3>Danger Zone</h3>
                  <p>Once you delete your account, there is no going back. Please be certain.</p>
                  <button type="button" class="btn-ghost logout" onclick="deleteAccount()">Delete Account</button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>
    </main>

    <!-- FOOTER -->
    <footer class="site-footer">
      <div class="footer-main">
        <div class="footer-top">
          <div class="footer-brand">
            <img src="img/LOGO.webp" alt="UX Pacific" />
            <p>
              Design resources and merchandise trusted by creators worldwide —
              built to be used, worn, and valued.
            </p>
            <div class="footer-socials">
              <a href="https://dribbble.com/social-ux-pacific" target="_blank" rel="noopener">
                <img src="img/bl.webp" alt="Dribbble" />
              </a>
              <a href="https://www.instagram.com/official_uxpacific/" target="_blank" rel="noopener">
                <img src="img/i.webp" alt="Instagram" />
              </a>
              <a href="https://www.linkedin.com/company/uxpacific/" target="_blank" rel="noopener">
                <img src="img/in.webp" alt="LinkedIn" />
              </a>
              <a href="https://in.pinterest.com/uxpacific/" target="_blank" rel="noopener">
                <img src="img/p.webp" alt="Pinterest" />
              </a>
              <a href="https://www.behance.net/ux_pacific" target="_blank" rel="noopener">
                <img src="img/be.webp" alt="Behance" />
              </a>
            </div>
          </div>

          <div class="footer-contact">
            <p>Support : +91 9274061063&nbsp;&nbsp;&nbsp;&nbsp;|</p>
            <p>
              Email :
              <a href="https://mail.google.com/mail/?view=cm&fs=1&to=hello@uxpacific.com"
                style="text-decoration: none; color: inherit" target="_blank">hello@uxpacific.com</a>
              &nbsp;&nbsp;&nbsp;&nbsp;
            </p>
          </div>
        </div>
      </div>

      <div class="footer-bottom">
        <p>©2026 UXPacific. All rights reserved.</p>
        <div class="footer-links">
          <a href="policies.php" target="">Our Policies </a>
          <span>•</span>
          <a href="contact.php" style="text-decoration: none;">Contact Us</a>
        </div>
      </div>
    </footer>
  </div>

  <script src="script.js"></script>
  <script>
    // Account page functionality
    document.addEventListener('DOMContentLoaded', function () {
      loadUserProfile();
      loadAddresses();
      loadAccountOrders();
      setupTabNavigation();
      setupForms();
    });

    function loadUserProfile() {
      const userSession = JSON.parse(localStorage.getItem('userSession')) || {};
      if (userSession.email) {
        document.getElementById('profile-name').textContent = userSession.name || userSession.firstName || 'User';
        document.getElementById('profile-email').textContent = userSession.email;
        document.getElementById('profile-initial').textContent = (userSession.firstName || userSession.name || 'U').charAt(0).toUpperCase();

        // Fill form
        document.getElementById('first-name').value = userSession.firstName || '';
        document.getElementById('last-name').value = userSession.lastName || '';
        document.getElementById('email').value = userSession.email || '';
        document.getElementById('phone').value = userSession.phone || '';
      }
    }

    function loadAddresses() {
      const addresses = JSON.parse(localStorage.getItem('savedAddresses')) || [];
      const addressesList = document.getElementById('addresses-list');

      if (addresses.length === 0) {
        addressesList.innerHTML = '<p class="empty-message">No saved addresses. Add one to get started.</p>';
        return;
      }

      addressesList.innerHTML = addresses.map((addr, index) => `
          <div class="address-card">
            <div class="address-header">
              <h4>${addr.firstName} ${addr.lastName}</h4>
              <button class="btn-ghost small" onclick="deleteAddress(${index})">Delete</button>
            </div>
            <p>${addr.address}</p>
            <p>${addr.city}, ${addr.state} ${addr.zip}</p>
            <p>${addr.country}</p>
            <p>Phone: ${addr.phone}</p>
          </div>
        `).join('');
    }

    function loadAccountOrders() {
      const orders = JSON.parse(localStorage.getItem('orders')) || [];
      const ordersList = document.getElementById('account-orders-list');

      if (orders.length === 0) {
        ordersList.innerHTML = '<p class="empty-message">No orders yet.</p>';
        return;
      }

      ordersList.innerHTML = orders.slice(0, 5).map(order => `
          <div class="account-order-item">
            <div>
              <h4>Order #${order.orderNumber}</h4>
              <p>${new Date(order.date).toLocaleDateString()} • $${order.total}</p>
            </div>
            <a href="order-confirmation.php?order=${order.orderNumber}" class="btn-ghost small">View</a>
          </div>
        `).join('');
    }

    function setupTabNavigation() {
      document.querySelectorAll('.account-nav-item').forEach(item => {
        item.addEventListener('click', function (e) {
          e.preventDefault();
          const tab = this.dataset.tab;

          // Update nav
          document.querySelectorAll('.account-nav-item').forEach(nav => nav.classList.remove('active'));
          this.classList.add('active');

          // Update tabs
          document.querySelectorAll('.account-tab').forEach(t => t.classList.remove('active'));
          document.getElementById(tab + '-tab').classList.add('active');
        });
      });
    }

    function setupForms() {
      // Profile form
      document.getElementById('profile-form').addEventListener('submit', function (e) {
        e.preventDefault();
        const userSession = JSON.parse(localStorage.getItem('userSession')) || {};
        userSession.firstName = this.firstName.value;
        userSession.lastName = this.lastName.value;
        userSession.name = `${this.firstName.value} ${this.lastName.value}`;
        userSession.phone = this.phone.value;
        localStorage.setItem('userSession', JSON.stringify(userSession));
        updateUserMenu();
        loadUserProfile();
        showToast('Profile updated successfully!', 'success');
      });

      // Password form
      document.getElementById('password-form').addEventListener('submit', function (e) {
        e.preventDefault();
        if (this.newPassword.value !== this.confirmPassword.value) {
          showToast('Passwords do not match', 'error');
          return;
        }
        showToast('Password updated successfully!', 'success');
        this.reset();
      });

      // New address form
      document.getElementById('new-address-form').addEventListener('submit', function (e) {
        e.preventDefault();
        const addresses = JSON.parse(localStorage.getItem('savedAddresses')) || [];
        addresses.push({
          firstName: this.firstName.value,
          lastName: this.lastName.value,
          address: this.address.value,
          city: this.city.value,
          state: this.state.value,
          zip: this.zip.value,
          country: this.country.value,
          phone: this.phone.value
        });
        localStorage.setItem('savedAddresses', JSON.stringify(addresses));
        loadAddresses();
        hideAddAddressForm();
        showToast('Address saved successfully!', 'success');
      });
    }

    function showAddAddressForm() {
      document.getElementById('add-address-form').style.display = 'block';
    }

    function hideAddAddressForm() {
      document.getElementById('add-address-form').style.display = 'none';
      document.getElementById('new-address-form').reset();
    }

    function deleteAddress(index) {
      if (confirm('Are you sure you want to delete this address?')) {
        const addresses = JSON.parse(localStorage.getItem('savedAddresses')) || [];
        addresses.splice(index, 1);
        localStorage.setItem('savedAddresses', JSON.stringify(addresses));
        loadAddresses();
        showToast('Address deleted', 'success');
      }
    }

    function resetProfileForm() {
      loadUserProfile();
    }

    function saveNotificationSettings() {
      showToast('Notification preferences saved!', 'success');
    }

    function deleteAccount() {
      if (confirm('Are you sure you want to delete your account? This action cannot be undone.')) {
        localStorage.removeItem('userSession');
        localStorage.removeItem('cart');
        localStorage.removeItem('orders');
        showToast('Account deleted', 'success');
        setTimeout(() => {
          window.location.href = 'index.php';
        }, 1500);
      }
    }

    window.showAddAddressForm = showAddAddressForm;
    window.hideAddAddressForm = hideAddAddressForm;
    window.deleteAddress = deleteAddress;
    window.resetProfileForm = resetProfileForm;
    window.saveNotificationSettings = saveNotificationSettings;
    window.deleteAccount = deleteAccount;
  </script>
</body>

</html>
