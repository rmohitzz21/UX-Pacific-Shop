<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="description" content="Premium UI Design System and UX/UI design resources from UX Pacific Shop. High-quality templates, mockups, and design assets." />
    <meta name="keywords" content="UI design system, UX templates, design resources, UX Pacific, premium design assets" />
    <title>Premium UI Design System – UX Pacific Shop</title>
    <link
      href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap"
      rel="stylesheet"
    />
    <link rel="stylesheet" href="style.css" />
  </head>
  <body>
    <!-- NAVBAR -->

    <header class="site-header" id="navbar">
      <nav class="nav-bar">
        <!-- Logo -->
        <div class="nav-logo">
          <!-- replace with your logo -->
          <a href="index.php">
            <img src="img/LOGO.webp" alt="UX Pacific" />
          </a>
        </div>
        <!-- Desktop Menu -->
        <ul class="nav-links">
          <li><a href="index.php" class="nav-link ">Home</a></li>
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
            <div class="user-avatar">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                <circle cx="12" cy="7" r="4"></circle>
              </svg>
            </div>
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
        <!-- Mobile Menu Button -->
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
      <!-- Mobile Menu -->
      <div id="mobile-menu" class="nav-mobile-menu">
        <a href="index.php" class="nav-mobile-link">Home</a>
        <a href="index.php#story" class="nav-mobile-link">About Us</a>
        <a href="index.php#products" class="nav-mobile-link">New</a>
        <a href="shopAll.php" class="nav-mobile-link">Buy Now</a>
        <a href="signin.php" class="nav-mobile-link nav-mobile-cta">
          Sign in
        </a>
      </div>
    </header>

    <div class="product-page">
      <!-- LEFT : IMAGE GALLERY -->
      <div class="product-gallery">
        <div class="main-image">
          <img id="mainProductImage" src="img/t1.webp" alt="Product Image" />
          <button class="nav prev" onclick="changeImage(-1)">‹</button>
          <button class="nav next" onclick="changeImage(1)">›</button>

          <!-- DOTS INSIDE IMAGE -->
          <div class="image-dots" id="sliderDots"></div>
        </div>
        <div class="thumbnail-row">
          <img src="img/t2.webp" class="thumb active" onclick="setImage(0)" />
          <img src="img/t3.webp" class="thumb" onclick="setImage(1)" />
          <img src="img/t4.webp" class="thumb" onclick="setImage(2)" />
          <img src="img/t1.webp" class="thumb" onclick="setImage(3)" />
        </div>
        <div class="slider-indicator">
          <span id="slideCount">1 / 4</span>
        </div>
      </div>

      <!-- RIGHT : PRODUCT INFO -->
      <div class="product-info">
        <h1>Premium UI Design System</h1>
        <p class="description">
          A comprehensive UI/UX design system with 150+ components, layouts,
          templates, and professional assets for modern products.
        </p>
        <div class="rating">★★★★★ <span>4.9 (247 reviews)</span></div>
        <div class="price">
          <span class="current">$29</span>
          <span class="old">$99</span>
          <span class="badge">71% OFF</span>
        </div>

        <!-- Platform -->
        <!-- <div class="option">
          <label>Purchase From</label>
          <select id="platformSelect">
            <option value="">Select Platform</option>
            <option value="freepik">Freepik</option>
            <option value="gumroad">Gumroad</option>
            <option value="behance">Behance</option>
            <option value="uxpacific">UXPacific</option>
          </select>
        </div> -->

        <!-- UXPacific Options -->
         <div>
        <!-- <div id="uxOptions"> -->
          <!-- Product Type Selection -->
          <div class="option">
            <label>Product Type *</label>
            <select id="product-type-select" onchange="handleProductTypeChange(this.value)">
              <option value="physical">Physical Product</option>
              <option value="digital">Digital Product</option>
            </select>
          </div>

          <div class="option">
            <label>License Type</label>
            <select>
              <option>Personal</option>
              <option>Commercial</option>
            </select>
          </div>

           <!-- <div class="option">
            <label>Format Type</label>
            <select>
              <option>Digital Version (PDF / Download)</option>
              <option>Physical Version (Printed Copy)</option>
            </select>
          </div> -->

          <div class="block">
            <label>Select Size</label>
            <div class="sizes">
              <button>S</button>
              <button>M</button>
              <button class="active">L</button>
              <button>XL</button>
            </div>
          </div>

          <div class="block">
            <label>Quantity</label>
            <div class="qty">
              <button onclick="qty(-1)">−</button>
              <span id="count">1</span>
              <button onclick="qty(1)">+</button>
            </div>
          </div>
        </div>

        <div class="product-buttons">
          <button class="buy-btn" onclick="addToCart('template-001', document.querySelector('.sizes button.active')?.textContent || 'L', parseInt(document.getElementById('count').textContent))">Add to Cart</button>
          <button class="buy-btn buy-now-btn" onclick="buyNow('template-001', document.querySelector('.sizes button.active')?.textContent || 'L', parseInt(document.getElementById('count').textContent))">Buy Now</button>
        </div>

        <!-- TRUST CARDS -->
        <div class="trust-grid right-trust">
          <div class="trust-card">
            <span class="icon">
              <img src="img/m4.webp" alt="Secure Purchase Icon" />
            </span>
            <div>
              <h4>Secure Purchase</h4>
              <p>256-bit SSL encrypted</p>
            </div>
          </div>
          <div class="trust-card">
            <span class="icon">
              <img src="img/m2.webp" alt="Instant Download Icon" />
            </span>
            <div>
              <h4>Instant Download</h4>
              <p>Access immediately</p>
            </div>
          </div>
          <div class="trust-card">
            <span class="icon">
              <img src="img/m3.webp" alt="Safe Payment Icon" />
            </span>
            <div>
              <h4>Safe Payment</h4>
              <p>Multiple payment options</p>
            </div>
          </div>
          <div class="trust-card">
            <span class="icon">
              <img src="img/m1.webp" alt="Refund Policy Icon" />
            </span>
            <div>
              <h4>Refund Policy</h4>
              <p>30-day money back</p>
            </div>
          </div>
        </div>
      </div>
    </div>
    <!-- ================= PRODUCT DESCRIPTION & TABS ================= -->

    <section class="product-extra">
      <!-- TABS -->
      <div class="product-tabs">
        <button class="tab-btn active" data-tab="desc">Description</button>
        <button class="tab-btn" data-tab="included">What’s Included</button>
        <button class="tab-btn" data-tab="specs">File Specification</button>
      </div>
      <!-- TAB CONTENT -->
      <div class="tab-box active" id="desc">
        <h3>About This Product</h3>
        <p>
          This comprehensive design system includes everything you need to
          create stunning digital products. Built with modern design principles
          and best practices, it’s perfect for designers and developers who want
          to speed up their workflow.
        </p>
        <ul class="feature-list">
          <li>Professionally designed by expert UI/UX designers</li>
          <li>Regular updates and lifetime access</li>
          <li>Compatible with Figma, Sketch, and Adobe XD</li>
          <li>Comprehensive documentation included</li>
        </ul>
      </div>
      <div class="tab-box" id="included">
        <ul class="feature-list">
          <li>150+ UI components</li>
          <li>Design tokens & variables</li>
          <li>Responsive layouts</li>
          <li>Dark & Light themes</li>
          <li>Documentation files</li>
        </ul>
      </div>
      <div class="tab-box" id="specs">
        <div class="spec-row">
          <span>File Size : </span><strong>245 MB</strong>
        </div>
        <div class="spec-row">
          <span>Last Updated : </span><strong>December 2024</strong>
        </div>
        <div class="spec-row"><span>Version</span><strong>2.5.0</strong></div>
        <div class="spec-row">
          <span>Minimum Requirements : </span
          ><strong>Figma Desktop / Web</strong>
        </div>
        <div class="spec-row">
          <span>Language : </span><strong>English</strong>
        </div>
        <div class="spec-row">
          <span>License : </span><strong>Commercial Use Allowed</strong>
        </div>
      </div>
    </section>

    <!-- RELATED PRODUCTS -->
    <section class="related-section">
      <h2 class="section-title">Related Products</h2>

      <div class="related-grid">
        <!-- CARD -->
        <div class="related-card">
          <div class="card-img">
            <img src="img/t4.webp" alt="Designer Sticker Pack" />
            <!-- <span class="wishlist">♡</span> -->
          </div>

          <div class="card-body">
            <div class="title-row">
              <h4>Designer Sticker Pack</h4>
              <span class="rating">⭐ 4.5</span>
            </div>

            <p class="desc">
              A fun mix of flat icons, labels, and creative stickers made for
              laptops, planners, and workspace decor.
            </p>

            <p class="size">Size: A5 / A4 printable</p>

            <div class="price-row">
              <span class="price">$499</span>
              <span class="old">$1499</span>
              <span class="off">67% OFF</span>
            </div>

            <button class="buy-btn">Buy Now</button>
          </div>
        </div>

        <!-- DUPLICATE CARD -->
        <div class="related-card">
          <div class="card-img">
            <img src="img/t3.webp" alt="Designer Sticker Pack" />
            <!-- <span class="wishlist">♡</span> -->
          </div>

          <div class="card-body">
            <div class="title-row">
              <h4>Designer Sticker Pack</h4>
              <span class="rating">⭐ 4.5</span>
            </div>

            <p class="desc">
              A fun mix of flat icons, labels, and creative stickers made for
              laptops, planners, and workspace decor.
            </p>

            <p class="size">Size: A5 / A4 printable</p>

            <div class="price-row">
              <span class="price">$499</span>
              <span class="old">$1499</span>
              <span class="off">67% OFF</span>
            </div>

            <button class="buy-btn">Buy Now</button>
          </div>
        </div>

        <div class="related-card">
          <div class="card-img">
            <img src="img/t2.webp" alt="Designer Sticker Pack" />
            <!-- <span class="wishlist">♡</span> -->
          </div>

          <div class="card-body">
            <div class="title-row">
              <h4>Designer Sticker Pack</h4>
              <span class="rating">⭐ 4.5</span>
            </div>

            <p class="desc">
              A fun mix of flat icons, labels, and creative stickers made for
              laptops, planners, and workspace decor.
            </p>

            <p class="size">Size: A5 / A4 printable</p>

            <div class="price-row">
              <span class="price">$499</span>
              <span class="old">$1499</span>
              <span class="off">67% OFF</span>
            </div>

            <button class="buy-btn">Buy Now</button>
          </div>
        </div>

        <div class="related-card">
          <div class="card-img">
            <img src="img/t1.webp" alt="Designer Sticker Pack" />
            <!-- <span class="wishlist">♡</span> -->
          </div>

          <div class="card-body">
            <div class="title-row">
              <h4>Designer Sticker Pack</h4>
              <span class="rating">⭐ 4.5</span>
            </div>

            <p class="desc">
              A fun mix of flat icons, labels, and creative stickers made for
              laptops, planners, and workspace decor.
            </p>

            <p class="size">Size: A5 / A4 printable</p>

            <div class="price-row">
              <span class="price">$499</span>
              <span class="old">$1499</span>
              <span class="off">67% OFF</span>
            </div>

            <button class="buy-btn">Buy Now</button>
          </div>
        </div>
      </div>
    </section>

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
            <!-- <p>UX Pacific, Ahmedabad.</p> -->
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
      </div>
    </footer>

    <!-- </section> -->
    <!-- <script>
      /* Image Slider */
      const images = ["img/t2.webp", "img/t3.webp", "img/t4.webp", "img/t1.webp"];
      let currentIndex = 0;
      const mainImage = document.getElementById("mainProductImage");
      const thumbs = document.querySelectorAll(".thumb");
      const slideCount = document.getElementById("slideCount");
      const dotsContainer = document.getElementById("sliderDots");

      images.forEach((_, i) => {
        const dot = document.createElement("span");
        dot.onclick = () => setImage(i);
        dotsContainer.appendChild(dot);
      });
      const dots = dotsContainer.querySelectorAll("span");

      function updateSlider() {
        mainImage.src = images[currentIndex];
        slideCount.textContent = `${currentIndex + 1} / ${images.length}`;
        thumbs.forEach((t, i) =>
          t.classList.toggle("active", i === currentIndex)
        );
        dots.forEach((d, i) =>
          d.classList.toggle("active", i === currentIndex)
        );
      }
      function setImage(i) {
        currentIndex = i;
        updateSlider();
      }
      function changeImage(s) {
        currentIndex = (currentIndex + s + images.length) % images.length;
        updateSlider();
      }
      updateSlider();

      /* Quantity */
      let quantity = 1;
      function qty(change) {
        quantity += change;
        if (quantity < 1) quantity = 1;
        document.getElementById("count").textContent = quantity;
      }

      /* Product Type Selection - Frontend Only */
      // Store product type in localStorage for checkout page
      function handleProductTypeChange(value) {
        // Store product_type in localStorage
        localStorage.setItem('product_type', value);
        console.log('Product type set to:', value);
      }

      // Load saved product type on page load
      document.addEventListener('DOMContentLoaded', function() {
        const savedProductType = localStorage.getItem('product_type') || 'physical';
        const productTypeSelect = document.getElementById('product-type-select');
        if (productTypeSelect) {
          productTypeSelect.value = savedProductType;
        }
      });

      // Make function globally available
      window.handleProductTypeChange = handleProductTypeChange;

      /* Platform Logic */
      const platform = document.getElementById("platformSelect");
      const uxOptions = document.getElementById("uxOptions");
      const buyBtn = document.querySelector(".buy-btn");

      platform.onchange = () => {
        const val = platform.value;
        if (val === "uxpacific") {
          uxOptions.style.display = "block";
          buyBtn.textContent = "Buy on UXPacific";
        } else {
          uxOptions.style.display = "none";
          buyBtn.textContent =
            val === "freepik"
              ? "Buy on Freepik"
              : val === "gumroad"
              ? "Buy on Gumroad"
              : val === "behance"
              ? "View on Behance"
              : "Buy Now";
        }
      };
    </script> -->
    <script src="script.js"></script>
  </body>
</html>

