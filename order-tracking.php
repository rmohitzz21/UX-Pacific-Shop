<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="description" content="Track your order status and shipping information at UX Pacific Shop" />
    <meta name="keywords" content="order tracking, track order, shipping status, order status" />
    <title>Track Your Order – UX Pacific Shop</title>
    <link
      href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap"
      rel="stylesheet"
    />
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

          <button
            id="mobile-menu-btn"
            class="nav-toggle"
            aria-label="Toggle navigation"
          >
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
        <section class="tracking-section">
          <div class="tracking-container">
            <h1 class="tracking-title">Track Your Order</h1>
            <p class="tracking-subtitle">Enter your order number to track your shipment</p>

            <!-- Search Form -->
            <div class="tracking-search">
              <div class="tracking-input-wrapper">
                <input
                  type="text"
                  id="order-number-input"
                  class="tracking-input"
                  placeholder="Enter order number (e.g., UXP-2024-001234)"
                  autocomplete="off"
                />
                <button class="btn-primary" onclick="trackOrder()">Track Order</button>
              </div>
            </div>

            <!-- Tracking Results -->
            <div id="tracking-results" class="tracking-results" style="display: none;">
              <div class="tracking-order-info">
                <div class="order-info-card">
                  <h3 id="tracking-order-number"></h3>
                  <p class="order-date" id="tracking-order-date"></p>
                  <div class="order-status-badge" id="tracking-status-badge"></div>
                </div>
              </div>

              <!-- Timeline -->
              <div class="tracking-timeline">
                <h3>Order Timeline</h3>
                <div id="tracking-timeline-items" class="timeline-items">
                  <!-- Timeline items will be loaded here -->
                </div>
              </div>

              <!-- Shipping Info -->
              <div class="tracking-shipping">
                <h3>Shipping Information</h3>
                <div id="tracking-shipping-info" class="shipping-info-card">
                  <!-- Shipping info will be loaded here -->
                </div>
              </div>

              <!-- Order Items -->
              <div class="tracking-items">
                <h3>Order Items</h3>
                <div id="tracking-items-list" class="tracking-items-list">
                  <!-- Items will be loaded here -->
                </div>
              </div>
            </div>

            <!-- No Results -->
            <div id="tracking-no-results" class="tracking-no-results" style="display: none;">
              <img src="img/cart-icon.webp" alt="Order not found" />
              <h3>Order not found</h3>
              <p>Please check your order number and try again</p>
              <a href="orders.php" class="btn-primary">View My Orders</a>
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
                <a
                  href="https://dribbble.com/social-ux-pacific"
                  target="_blank"
                  rel="noopener"
                >
                  <img src="img/bl.webp" alt="Dribbble" />
                </a>
                <a
                  href="https://www.instagram.com/official_uxpacific/"
                  target="_blank"
                  rel="noopener"
                >
                  <img src="img/i.webp" alt="Instagram" />
                </a>
                <a
                  href="https://www.linkedin.com/company/uxpacific/"
                  target="_blank"
                  rel="noopener"
                >
                  <img src="img/in.webp" alt="LinkedIn" />
                </a>
                <a
                  href="https://in.pinterest.com/uxpacific/"
                  target="_blank"
                  rel="noopener"
                >
                  <img src="img/p.webp" alt="Pinterest" />
                </a>
                <a
                  href="https://www.behance.net/ux_pacific"
                  target="_blank"
                  rel="noopener"
                >
                  <img src="img/be.webp" alt="Behance" />
                </a>
              </div>
            </div>

            <div class="footer-contact">
              <p>Support : +91 9274061063&nbsp;&nbsp;&nbsp;&nbsp;|</p>
              <p>
                Email :
                <a
                  href="https://mail.google.com/mail/?view=cm&fs=1&to=hello@uxpacific.com"
                  style="text-decoration: none; color: inherit"
                  target="_blank"
                  >hello@uxpacific.com</a
                >
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
      function trackOrder() {
        const orderNumber = document.getElementById('order-number-input').value.trim();
        if (!orderNumber) {
          showToast('Please enter an order number', 'error');
          return;
        }

        // Get orders from localStorage
        const orders = JSON.parse(localStorage.getItem('orders')) || [];
        const order = orders.find(o => o.orderNumber === orderNumber);

        const results = document.getElementById('tracking-results');
        const noResults = document.getElementById('tracking-no-results');

        if (!order) {
          results.style.display = 'none';
          noResults.style.display = 'block';
          return;
        }

        noResults.style.display = 'none';
        results.style.display = 'block';

        // Display order info
        document.getElementById('tracking-order-number').textContent = `Order #${order.orderNumber}`;
        document.getElementById('tracking-order-date').textContent = `Placed on ${new Date(order.date).toLocaleDateString('en-US', { 
          year: 'numeric', 
          month: 'long', 
          day: 'numeric' 
        })}`;
        
        const statusBadge = document.getElementById('tracking-status-badge');
        statusBadge.className = `order-status-badge status-${order.status}`;
        statusBadge.textContent = order.status;

        // Timeline
        const timelineItems = document.getElementById('tracking-timeline-items');
        const statuses = [
          { status: 'Pending', label: 'Order Placed', date: order.date },
          { status: 'Processing', label: 'Order Processing', date: order.date },
          { status: 'Shipped', label: 'Order Shipped', date: order.date },
          { status: 'Delivered', label: 'Order Delivered', date: order.date }
        ];

        const currentStatusIndex = statuses.findIndex(s => s.status === order.status);
        timelineItems.innerHTML = statuses.map((status, index) => {
          const isActive = index <= currentStatusIndex;
          return `
            <div class="timeline-item ${isActive ? 'active' : ''}">
              <div class="timeline-dot"></div>
              <div class="timeline-content">
                <h4>${status.label}</h4>
                <p>${new Date(status.date).toLocaleDateString()}</p>
              </div>
            </div>
          `;
        }).join('');

        // Shipping info
        if (order.shipping) {
          const shippingInfo = document.getElementById('tracking-shipping-info');
          shippingInfo.innerHTML = `
            <p><strong>${order.shipping.firstName} ${order.shipping.lastName}</strong></p>
            <p>${order.shipping.address}</p>
            <p>${order.shipping.city}, ${order.shipping.state} ${order.shipping.zip}</p>
            <p>${order.shipping.country}</p>
            <p>Phone: ${order.shipping.phone}</p>
          `;
        }

        // Order items
        const itemsList = document.getElementById('tracking-items-list');
        itemsList.innerHTML = order.items.map(item => `
          <div class="tracking-item">
            <img src="${item.image}" alt="${item.name}" class="tracking-item-image" />
            <div class="tracking-item-details">
              <h4>${item.name}</h4>
              <p>${item.size ? `Size: ${item.size} • ` : ''}Quantity: ${item.quantity}</p>
            </div>
            <div class="tracking-item-price">$${item.price * item.quantity}</div>
          </div>
        `).join('');
      }

      document.addEventListener('DOMContentLoaded', function() {
        // Check for order number in URL
        const urlParams = new URLSearchParams(window.location.search);
        const orderNumber = urlParams.get('order');
        if (orderNumber) {
          document.getElementById('order-number-input').value = orderNumber;
          trackOrder();
        }

        // Track on Enter key
        document.getElementById('order-number-input').addEventListener('keypress', function(e) {
          if (e.key === 'Enter') {
            trackOrder();
          }
        });
      });

      window.trackOrder = trackOrder;
    </script>
  </body>
</html>


