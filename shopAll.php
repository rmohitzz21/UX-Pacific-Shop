<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <title>UX Pacific – Shop All Products</title>
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <!-- Google Font -->
    <link
      href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap"
      rel="stylesheet"
    />
    <link rel="stylesheet" href="style.css" />
  </head>

  <body class="shopAll">
    <div class="page">
      <!-- NAVBAR (same as index, only Products is active + links adjusted) -->
      <header class="site-header" id="navbar">
        <nav class="nav-bar">
          <!-- Logo -->
          <div class="nav-logo">
            <a href="index.php">
              <img src="img/LOGO.webp" alt="UX Pacific" />
            </a>
          </div>

          <!-- Desktop Menu -->
          <ul class="nav-links">
            <li><a href="index.php" class="nav-link">Home</a></li>
            <li><a href="index.php#story" class="nav-link">About Us</a></li>
            <li><a href="index.php#products" class="nav-link">New</a></li>
            <li>
              <a href="shopAll.php" class="nav-link active">Buy Now</a>
            </li>
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
          <a href="cart.php" class="nav-mobile-link">Cart</a>
          <a href="signin.php" class="nav-mobile-link nav-mobile-cta">
            Sign in
          </a>
        </div>
      </header>

      <!-- MAIN CONTENT – SHOP ALL PAGE -->
      <main class="main shop-all-main">
        <!-- Page heading -->
        <section class="shop-all-header">
          <h1 class="shop-all-title">
            Design &nbsp;<span>Resources & Products </span>&nbsp;
          </h1>
          <h2 class="shop-all-subtitle">
            Design Resources for UX/UI Designers | Digital & Physical
          </h2>
          <p class="shop-all-subtitle">
            Explore premium UX/UI design resources including digital assets and
            physical products. Buy directly on UXPACIFIC or via trusted partner
            platforms.
          </p>
        </section>

        <!-- Layout: sidebar filters + product grid -->
        <section class="shop-all-layout">
          <!-- FILTER SIDEBAR (uses same .filter-pill class so JS filtering works) -->
          <aside class="shop-all-filters">
            <button class="filter-pill active" data-filter="all">
              All Products
            </button>
            <button class="filter-pill" data-filter="T-Shirts">T-Shirts</button>
            <button class="filter-pill" data-filter="Stickers">Stickers</button>
            <button class="filter-pill" data-filter="Booklet">Booklet</button>
            <button class="filter-pill" data-filter="workbook">Workbook</button>
            <button class="filter-pill" data-filter="Mockup">Mockup</button>
            <button class="filter-pill" data-filter="Badges">Badges</button>
            <button class="filter-pill" data-filter="template">
              UI Template
            </button>
          </aside>

          <!-- PRODUCT GRID (reuses existing .product-grid / .product-card styles) -->
          <div class="product-grid shop-all-grid">
            <!-- 1 -->
            <article class="product-card" data-category="Stickers">
              <div class="product-img">
                <img src="img/Template/high10.webp" alt="Designer Sticker Pack" />
                <span class="product-tag">Stickers</span>
              </div>
              <div class="product-body">
                <h3 class="product-title">Designer Sticker Pack</h3>
                <p>
                  A fun mix of UX, UI, and product stickers for laptops,
                  notebooks, and workspace decor.
                </p>

                <p>Size : A5 / A4 printable</p>
                <div class="product-meta">
                  <div class="product-price">$499 <span>$899</span></div>
                  <div class="product-rating">★ 4.5</div>
                </div>
                <div class="product-actions">
                  <button onclick="addToCart('sticker-pack-001')" class="btn-primary small">Add to Cart</button>
                  <a href="product.php" class="btn-ghost small">View Details</a>
                </div>
              </div>
            </article>

            <article class="product-card" data-category="Stickers">
              <div class="product-img">
                <img src="img/UXP-sticker.webp" alt="Designer Sticker Pack" />
                <span class="product-tag">Stickers</span>
              </div>
              <div class="product-body">
                <h3>Designer Sticker Pack</h3>
                <p>
                  A fun mix of UX, UI, and product stickers for laptops,
                  notebooks, and workspace decor.
                </p>

                <p>Size : A5 / A4 printable</p>
                <div class="product-meta">
                  <div class="product-price">$499 <span>$899</span></div>
                  <div class="product-rating">★ 4.5</div>
                </div>
                <div class="product-actions">
                  <button onclick="addToCart('sticker-pack-001')" class="btn-primary small">Add to Cart</button>
                  <a href="product.php" class="btn-ghost small">View Details</a>
                </div>
              </div>
            </article>

            <article class="product-card" data-category="Stickers">
              <div class="product-img">
                <img src="img/UXP2-sticker.webp" alt="Designer Sticker Pack" />
                <span class="product-tag">Stickers</span>
              </div>
              <div class="product-body">
                <h3>Designer Sticker Pack</h3>
                <p>
                  A fun mix of UX, UI, and product stickers for laptops,
                  notebooks, and workspace decor.
                </p>

                <p>Size : A5 / A4 printable</p>
                <div class="product-meta">
                  <div class="product-price">$499 <span>$899</span></div>
                  <div class="product-rating">★ 4.5</div>
                </div>
                <div class="product-actions">
                  <button onclick="addToCart('sticker-pack-001')" class="btn-primary small">Add to Cart</button>
                  <a href="product.php" class="btn-ghost small">View Details</a>
                </div>
              </div>
            </article>

            <!-- 2 -->

            <article class="product-card" data-category="T-Shirts">
              <div class="product-img">
                <img src="img/together.webp" alt="UXPacific Classic Hoodie" />
                <span class="product-tag">T-Shirts</span>
              </div>
              <div class="product-body">
                <h3>UXPacific Classic Hoodie</h3>
                <p>
                  Premium hoodie mockup with clean branding and soft fabric
                  shadows. Perfect for merch & drops.
                </p>
                <p>Size : S / M / L / XL</p>
                <div class="product-meta">
                  <div class="product-price">$499 <span>$899</span></div>
                  <div class="product-rating">★ 4.5</div>
                </div>
                <div class="product-actions">
                  <button onclick="addToCart('sticker-pack-001')" class="btn-primary small">Add to Cart</button>
                  <a href="product.php" class="btn-ghost small">View Details</a>
                </div>
              </div>
            </article>

            <article class="product-card" data-category="T-Shirts">
              <div class="product-img">
                <img src="img/white.webp" alt="UXPacific Classic Hoodie" />
                <span class="product-tag">T-Shirts</span>
              </div>
              <div class="product-body">
                <h3>UXPacific Classic Hoodie</h3>
                <p>
                  Premium hoodie mockup with clean branding and soft fabric
                  shadows. Perfect for merch & drops.
                </p>
                <p>Size : S / M / L / XL</p>
                <div class="product-meta">
                  <div class="product-price">$499 <span>$899</span></div>
                  <div class="product-rating">★ 4.5</div>
                </div>
                <div class="product-actions">
                  <button onclick="addToCart('sticker-pack-001')" class="btn-primary small">Add to Cart</button>
                  <a href="product.php" class="btn-ghost small">View Details</a>
                </div>
              </div>
            </article>

            <article class="product-card" data-category="T-Shirts">
              <div class="product-img">
                <img src="img/tule4.webp" alt="UXPacific Classic Hoodie" />
                <span class="product-tag">T-Shirts</span>
              </div>
              <div class="product-body">
                <h3>UXPacific Classic Hoodie</h3>
                <p>
                  Premium hoodie mockup with clean branding and soft fabric
                  shadows. Perfect for merch & drops.
                </p>
                <p>Size : S / M / L / XL</p>
                <div class="product-meta">
                  <div class="product-price">$499 <span>$899</span></div>
                  <div class="product-rating">★ 4.5</div>
                </div>
                <div class="product-actions">
                  <button onclick="addToCart('sticker-pack-001')" class="btn-primary small">Add to Cart</button>
                  <a href="product.php" class="btn-ghost small">View Details</a>
                </div>
              </div>
            </article>

            <article class="product-card" data-category="T-Shirts">
              <div class="product-img">
                <img src="img/tule3.webp" alt="UXPacific Classic Hoodie" />
                <span class="product-tag">T-Shirts</span>
              </div>
              <div class="product-body">
                <h3>UXPacific Classic Hoodie</h3>
                <p>
                  Premium hoodie mockup with clean branding and soft fabric
                  shadows. Perfect for merch & drops.
                </p>
                <p>Size : S / M / L / XL</p>
                <div class="product-meta">
                  <div class="product-price">$499 <span>$899</span></div>
                  <div class="product-rating">★ 4.5</div>
                </div>
                <div class="product-actions">
                  <button onclick="addToCart('sticker-pack-001')" class="btn-primary small">Add to Cart</button>
                  <a href="product.php" class="btn-ghost small">View Details</a>
                </div>
              </div>
            </article>
<!-- 
            <article class="product-card" data-category="T-Shirts">
              <div class="product-img">
                <img src="img/tule4.webp" alt="UXPacific Classic Hoodie" />
                <span class="product-tag">T-Shirts</span>
              </div>
              <div class="product-body">
                <h3>UXPacific Classic Hoodie</h3>
                <p>
                  Premium hoodie mockup with clean branding and soft fabric
                  shadows. Perfect for merch & drops.
                </p>
                <p>Size : S / M / L / XL</p>
                <div class="product-meta">
                  <div class="product-price">$499 <span>$899</span></div>
                  <div class="product-rating">★ 4.5</div>
                </div>
                <div class="product-actions">
                  <button onclick="addToCart('sticker-pack-001')" class="btn-primary small">Add to Cart</button>
                  <a href="product.php" class="btn-ghost small">View Details</a>
                </div>
              </div>
            </article>

            <article class="product-card" data-category="T-Shirts">
              <div class="product-img">
                <img src="img/coffee.webp" alt="UXPacific Classic Hoodie" />
                <span class="product-tag">T-Shirts</span>
              </div>
              <div class="product-body">
                <h3>UXPacific Classic Hoodie</h3>
                <p>
                  Premium hoodie mockup with clean branding and soft fabric
                  shadows. Perfect for merch & drops.
                </p>
                <p>Size : S / M / L / XL</p>
                <div class="product-meta">
                  <div class="product-price">$499 <span>$899</span></div>
                  <div class="product-rating">★ 4.5</div>
                </div>
                <div class="product-actions">
                  <button onclick="addToCart('sticker-pack-001')" class="btn-primary small">Add to Cart</button>
                  <a href="product.php" class="btn-ghost small">View Details</a>
                </div>
              </div>
            </article> -->

            <!-- 3 -->
            <article class="product-card" data-category="Booklet">
              <div class="product-img">
                <img src="img/bk.webp" alt="UXPacific Booklet" />
                <span class="product-tag">Booklet</span>
              </div>
              <div class="product-body">
                <h3>UX Case Study Booklet</h3>
                <p>
                  A clean booklet template to present UX case studies and design
                  projects.
                </p>
                <p>Size : A4 / Digital PDF</p>
                <div class="product-meta">
                  <div class="product-price">$499 <span>$899</span></div>
                  <div class="product-rating">★ 4.6</div>
                </div>
                <div class="product-actions">
                  <button onclick="addToCart('sticker-pack-001')" class="btn-primary small">Add to Cart</button>
                  <a href="product.php" class="btn-ghost small">View Details</a>
                </div>
              </div>
            </article>

            <!-- 4 -->
            <article class="product-card" data-category="Mockup">
              <div class="product-img">
                <img src="img/mockup.webp" alt="UXPacific Mockup" />
                <span class="product-tag">Mockup</span>
              </div>
              <div class="product-body">
                <h3>UXPacific Device Mockup</h3>
                <p>
                  High-resolution device mockups for presenting digital product
                  designs in context.
                </p>
                <p>Size : PNG / PSD</p>
                <div class="product-meta">
                  <div class="product-price">$499 <span>$899</span></div>
                  <div class="product-rating">★ 4.5</div>
                </div>
                <div class="product-actions">
                  <button onclick="addToCart('sticker-pack-001')" class="btn-primary small">Add to Cart</button>
                  <a href="product.php" class="btn-ghost small">View Details</a>
                </div>
              </div>
            </article>

            <article class="product-card" data-category="Mockup">
              <div class="product-img">
                <img src="img/mockup.webp" alt="UXPacific Mockup" />
                <span class="product-tag">Mockup</span>
              </div>
              <div class="product-body">
                <h3>UXPacific Device Mockup</h3>
                <p>
                  High-resolution device mockups for presenting digital product
                  designs in context.
                </p>
                <p>Size : PNG / PSD</p>
                <div class="product-meta">
                  <div class="product-price">$499 <span>$899</span></div>
                  <div class="product-rating">★ 4.5</div>
                </div>
                <div class="product-actions">
                  <button onclick="addToCart('sticker-pack-001')" class="btn-primary small">Add to Cart</button>
                  <a href="product.php" class="btn-ghost small">View Details</a>
                </div>
              </div>
            </article>

            <!-- 5 -->
            <article class="product-card" data-category="Badges">
              <div class="product-img">
                <img src="img/b11.webp" alt="Badge Pack" />
                <span class="product-tag">Badges</span>
              </div>
              <div class="product-body">
                <h3>UXPacific Badge Pack</h3>
                <p>
                  A clean badge pack for communities, profiles, and achievement
                  systems.
                </p>
                <p>Size : PNG / SVG / 1024px</p>
                <div class="product-meta">
                  <div class="product-price">$499 <span>$899</span></div>
                  <div class="product-rating">★ 4.5</div>
                </div>
                <div class="product-actions">
                  <button onclick="addToCart('sticker-pack-001')" class="btn-primary small">Add to Cart</button>
                  <a href="product.php" class="btn-ghost small">View Details</a>
                </div>
              </div>
            </article>

            <article class="product-card" data-category="Badges">
              <div class="product-img">
                <img src="img/budge1.webp" alt="UXPacific Classic Hoodie" />
                <span class="product-tag">Badges</span>
              </div>
              <div class="product-body">
                <h3>UXPacific Badge Pack</h3>
                <p>
                  A clean badge pack for communities, profiles, and achievement
                  systems.
                </p>
                <p>Size : PNG / SVG / 1024px</p>
                <div class="product-meta">
                  <div class="product-price">$499 <span>$899</span></div>
                  <div class="product-rating">★ 4.5</div>
                </div>
                <div class="product-actions">
                  <button onclick="addToCart('sticker-pack-001')" class="btn-primary small">Add to Cart</button>
                  <a href="product.php" class="btn-ghost small">View Details</a>
                </div>
              </div>
            </article>

            <!-- 6 -->
            <article class="product-card" data-category="template">
              <div class="product-img">
                <img src="img/template.webp" alt="UI Template" />
                <span class="product-tag">Template</span>
              </div>
              <div class="product-body">
                <h3>UXPacific UI Template</h3>
                <p>
                  Figma-based UI template with Auto Layout , ready for case
                  studies and real products &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; .
                </p>
                <p>Size : Figma / Auto Layout</p>
                <div class="product-meta">
                  <div class="product-price">$499 <span>$899</span></div>
                  <div class="product-rating">★ 4.7</div>
                </div>
                <div class="product-actions">
                  <button onclick="addToCart('sticker-pack-001')" class="btn-primary small">Add to Cart</button>
                  <a href="product.php" class="btn-ghost small">View Details</a>
                </div>
              </div>
            </article>

            <article class="product-card" data-category="template">
              <div class="product-img">
                <img src="img/template.webp" alt="UI Template" />
                <span class="product-tag">Template</span>
              </div>
              <div class="product-body">
                <h3>UXPacific UI Template</h3>
                <p>
                  Figma-based UI template with Auto Layout , ready for case
                  studies and real products &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; .
                </p>
                <p>Size : Figma / Auto Layout</p>
                <div class="product-meta">
                  <div class="product-price">$499 <span>$899</span></div>
                  <div class="product-rating">★ 4.7</div>
                </div>
                <div class="product-actions">
                  <button onclick="addToCart('sticker-pack-001')" class="btn-primary small">Add to Cart</button>
                  <a href="product.php" class="btn-ghost small">View Details</a>
                </div>
              </div>
            </article>

            <!-- 7 -->
            <article class="product-card" data-category="T-Shirts">
              <div class="product-img">
                <img src="img/tule.webp" alt="UXPacific Classic Hoodie" />
                <span class="product-tag">T-Shirts</span>
              </div>
              <div class="product-body">
                <h3>UXPacific Classic Hoodie</h3>
                <p>
                  Premium hoodie mockup with clean branding and soft fabric
                  shadows. Perfect for merch & drops.
                </p>
                <p>Size : S / M / L / XL</p>
                <div class="product-meta">
                  <div class="product-price">$499 <span>$899</span></div>
                  <div class="product-rating">★ 4.5</div>
                </div>
                <div class="product-actions">
                  <button onclick="addToCart('sticker-pack-001')" class="btn-primary small">Add to Cart</button>
                  <a href="product.php" class="btn-ghost small">View Details</a>
                </div>
              </div>
            </article>

            <!-- 8 -->

            <article class="product-card" data-category="workbook">
              <div class="product-img">
                <img src="img/tule.webp" alt="UXPacific Classic Hoodie" />
                <span class="product-tag">T-Shirts</span>
              </div>
              <div class="product-body">
                <h3>UXPacific Classic Hoodie</h3>
                <p>
                  Premium hoodie mockup with clean branding and soft fabric
                  shadows. Perfect for merch & drops.
                </p>
                <p>Size : S / M / L / XL</p>
                <div class="product-meta">
                  <div class="product-price">$499 <span>$899</span></div>
                  <div class="product-rating">★ 4.5</div>
                </div>
                <div class="product-actions">
                  <button onclick="addToCart('sticker-pack-001')" class="btn-primary small">Add to Cart</button>
                  <a href="product.php" class="btn-ghost small">View Details</a>
                </div>
              </div>
            </article>

            <article class="product-card" data-category="workbook">
              <div class="product-img">
                <img src="img/workbk.webp" alt="UXPacific Mockup" />
                <span class="product-tag">workbook</span>
              </div>
              <div class="product-body">
                <h3>UXPacific Device Mockup</h3>
                <p>
                  High-resolution device mockups for presenting digital product
                  designs in context.
                </p>
                <p>Size : PNG / PSD</p>
                <div class="product-meta">
                  <div class="product-price">$499 <span>$899</span></div>
                  <div class="product-rating">★ 4.5</div>
                </div>
                <div class="product-actions">
                  <button onclick="addToCart('sticker-pack-001')" class="btn-primary small">Add to Cart</button>
                  <a href="product.php" class="btn-ghost small">View Details</a>
                </div>
              </div>
            </article>
          </div>
        </section>

        <!-- CTA SECTION (same style as index) -->
        <section class="cta-section">
          <div class="cta-card">
            <h2 class="section-title">
              Ready to Explore <span class="title-accent">More Products?</span>
            </h2>
            <p class="section-subtitle">
              Explore the complete UXPacific Shop collection and discover
              high-quality merch, mockups, UI templates, workbooks, badge packs,
              and creative digital assets designed especially for modern
              creators.
            </p>

            <div class="cta-actions">
              <a href="shopAll.php" class="btn-primary btn-shop"
                >Buy All Products</a
              >
              <!-- <a href="contact.php" class="btn-ghost">Join Our Community</a> -->
            </div>
          </div>
        </section>
      </main>

      <!-- FOOTER (exact copy from index) -->
      <footer id="" class="site-footer">
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
      
    </div>

    <script src="script.js"></script>
  </body>
</html>

