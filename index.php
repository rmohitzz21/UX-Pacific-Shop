<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="description"
    content="UX Pacific Shop - Premium UX/UI design resources, merchandise, and digital products for designers and creators" />
  <meta name="keywords" content="UX design, UI templates, design resources, merchandise, design tools, UX Pacific" />
  <meta name="author" content="UX Pacific" />
  <meta property="og:title" content="UX Pacific – Premium Design Resources & Merchandise" />
  <meta property="og:description"
    content="Explore premium UX/UI design resources including digital assets and physical products" />
  <meta property="og:type" content="website" />
  <meta property="og:url" content="https://uxpacific.com/" />
  <meta property="og:image" content="https://uxpacific.com/img/LOGO.webp" />
  <meta name="twitter:card" content="summary_large_image" />
  <title>UX Pacific – Merchandise</title>
  <!-- Google Font -->
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap"
    rel="stylesheet" />
  <link rel="stylesheet" href="style.css" />
</head>

<body>
  <!-- Skip to main content link for accessibility -->
  <a href="#home" class="sr-only"
    style="position: absolute; top: 0; left: 0; z-index: 10000; padding: 1rem; background: var(--accent); color: white; text-decoration: none;"
    onfocus="this.style.position='fixed'; this.style.top='0'; this.style.left='0';"
    onblur="this.style.position='absolute';">Skip to main content</a>
  <div class="page">
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
          <li><a href="index.php" class="nav-link active">Home</a></li>
          <li><a href="#story" class="nav-link">About Us</a></li>
          <li><a href="#products" class="nav-link">New</a></li>
          <li><a href="shopAll.php" class="nav-link">Buy Now</a></li>
        </ul>

        <!-- Search Bar -->
        <div class="nav-search" role="search">
          <label for="header-search-input" class="sr-only">Search products</label>
          <input type="text" class="nav-search-input" placeholder="Search products..." id="header-search-input"
            autocomplete="off" aria-label="Search products" />
          <button class="nav-search-button" onclick="performHeaderSearch()" aria-label="Search" type="button">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
              <circle cx="11" cy="11" r="8"></circle>
              <path d="m21 21-4.35-4.35"></path>
            </svg>
          </button>
        </div>

        <div class="nav-actions">
          <a href="cart.php" class="nav-cart" aria-label="Shopping cart">
            <img src="img/cart.webp" alt="Shopping cart" />
            <span id="cart-count">0</span>
          </a>
          <a href="signin.php" class="nav-cta" aria-label="Sign in">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"
              class="nav-cta-icon">
              <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
              <circle cx="12" cy="7" r="4"></circle>
            </svg>
            <span class="nav-cta-text">Sign in</span>
          </a>
          <div class="nav-user" role="button" tabindex="0" aria-label="User menu" aria-expanded="false"
            aria-haspopup="true">
            <div class="user-avatar" aria-hidden="true">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                <circle cx="12" cy="7" r="4"></circle>
              </svg>
            </div>
            <div class="user-info">
              <span class="user-name">User</span>
              <span class="user-role">Customer</span>
            </div>
            <div class="user-dropdown" role="menu">
              <a href="account.php" class="user-dropdown-item" role="menuitem">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                  <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                  <circle cx="12" cy="7" r="4"></circle>
                </svg>
                <span>My Account</span>
              </a>
              <a href="cart.php" class="user-dropdown-item" role="menuitem">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                  <circle cx="9" cy="21" r="1"></circle>
                  <circle cx="20" cy="21" r="1"></circle>
                  <path d="M1 1h4l2.68 13.39a2 2 0 0 0 2 1.61h9.72a2 2 0 0 0 2-1.61L23 6H6"></path>
                </svg>
                <span>My Cart</span>
              </a>
              <a href="orders.php" class="user-dropdown-item" role="menuitem">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                  <path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"></path>
                  <rect x="8" y="2" width="8" height="4" rx="1" ry="1"></rect>
                </svg>
                <span>My Orders</span>
              </a>
              <div class="user-dropdown-divider"></div>
              <a href="#" onclick="handleSignOut(); return false;" class="user-dropdown-item logout" role="menuitem"
                aria-label="Sign out">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
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
        <button id="mobile-menu-btn" class="nav-toggle" aria-label="Toggle navigation menu" aria-expanded="false"
          aria-controls="mobile-menu" type="button">
          <span></span>
          <span></span>
          <span></span>
        </button>
      </nav>

      <!-- Mobile Menu -->
      <nav id="mobile-menu" class="nav-mobile-menu" role="navigation" aria-label="Mobile navigation">
        <a href="index.php" class="nav-mobile-link">Home</a>
        <a href="#story" class="nav-mobile-link">About Us</a>
        <a href="#products" class="nav-mobile-link">New</a>
        <a href="shopAll.php" class="nav-mobile-link">Buy Now</a>
        <a href="signin.php" class="nav-mobile-link nav-mobile-cta">
          Sign in
        </a>
      </nav>
    </header>

    <!-- MAIN CONTENT -->
    <main id="home" class="main">
      <!-- HERO SECTION -->
      <!-- <section class="hero">
       
        <div class="hero-left">
          <h1 class="hero-title">
            Explore UXPacific
            <span class="hero-title-secondary">Merchandise</span>
          </h1>

          <p class="hero-text">
            View products on UXPacific Shop and purchase safely on partner
            platforms like Freepik, Behance, and Gumroad.
          </p>

          <a href="#products" class="btn-primary" style="width: 150px; height: 41px; text-align: c;">Shop Now</a>

          <div class="hero-note">
            UXPacific does not process payments — you will be redirected to
            official platforms.
          </div>
        </div>

        <div class="hero-right">
          <div class="hero-main-img">
            <img src="img/cat.webp" alt="Pocket cat tee" />
          </div>

          <div class="hero-side-imgs">
            <div class="hero-side-img">
              <img src="img/img3.webp" alt="Gradient phone mockup" />
            </div>
            <div class="hero-side-img">
              <img src="img/img2.webp" alt="Model with tote bag" />
            </div>
          </div>
        </div>

      </section> -->

      <!-- ANIMATED HERO WITH SCROLL CONTAINER -->
      <div class="hero-scroll-container">
        <div class="sticky-viewport">
          <div class="hero-glass-box">
            <!-- Text Content -->
            <div class="cards-hero-content">
              <h1 class="cards-hero-title">
                High-Quality <span> UX/UI </span><br />
                resources <span style="font-weight: 300">for</span>
                <span style="font-weight: 100"> Designers </span>
              </h1>
              <p class="cards-hero-subtitle">
                Design kits, UI assets, and learning resources — available on
                UXPACIFIC and partner platforms.
              </p>
              <a href="shopAll.php" class="nav-cta new">Buy Now</a>
            </div>
            <style>
              @media (max-width: 640px) {
                .nav-cta.new {
                  padding: 8px;
                  font-size: 14px;
                  width: 80px;
                  height: 40px;
                  min-width: 40px;
                }
              }
            </style>
            <!-- Card 1 -->
            <div class="hero-card card-1">
              <img src="img/poster.webp" alt="Merch" onerror="this.style.opacity='0.5'" />
            </div>

            <!-- Card 2 -->
            <div class="hero-card card-2">
              <img src="img/poster1.webp" alt="Booklet" onerror="this.style.opacity='0.5'" />
            </div>

            <!-- Card 3 -->
            <div class="hero-card card-3">
              <img src="img/poster2.webp" alt="Sticker" onerror="this.style.opacity='0.5'" />
            </div>

            <!-- Card 4 -->
            <div class="hero-card card-4">
              <img src="img/poster3.webp" alt="Template" onerror="this.style.opacity='0.5'" />
            </div>

            <!-- Card 5 (Top of deck) -->
            <div class="hero-card card-5">
              <img src="img/poster4.webp" alt="Mockup" onerror="this.style.opacity='0.5'" />
            </div>
          </div>
        </div>
      </div>

      <!-- OUR STORY -->
      <section id="story" class="story">
        <div class="story-card">
          <h2 class="section-title">About UXPACIFIC Shop</h2>
          <p class="story-text">
            UXPACIFIC Shop is a curated marketplace for designers, creators,
            and modern teams. We bring together thoughtfully designed physical
            merchandise and high-quality digital resources — built to inspire
            creativity, elevate workflows, and reflect the UXPACIFIC design
            mindset.<br /><br />
            From apparel and stickers to UI templates, workbooks, and creative
            tools, every product is crafted with purpose, quality, and
            real-world usability in mind.<br /><br />
            <b>Designed for creators who value clarity, quality, and
              thoughtful design.</b>
          </p>
          <a href="https://www.uxpacific.com/" class="btn-primary small" target="_blank">Know more</a>
        </div>
      </section>

      <!-- HOW IT WORKS -->
      <section class="how-it-works">
        <h2 class="section-title">
          How UXPacific <span class="title-accent">Shop Works</span>
        </h2>

        <div class="how-cards">
          <article class="how-card">
            <div class="how-icon">
              <img src="img/AboutSection.webp" alt="Browse products icon" />
            </div>
            <h3>Browse</h3>
            <p>
              Explore premium UXPACIFIC products — apparel, design tools, and
              resources crafted for creators.
            </p>
          </article>

          <article class="how-card">
            <div class="how-icon">
              <img src="img/basket.webp" alt="Shopping cart icon" />
            </div>
            <h3>Select & Buy</h3>
            <p>
              Choose what you love and place your order in just a few clicks —
              digital or physical.
            </p>
          </article>

          <article class="how-card">
            <div class="how-icon">
              <img src="img/shop.webp" alt="Secure checkout icon" />
            </div>
            <h3>Secure Checkout</h3>
            <p>
              Pay safely with trusted payment gateways. Instant access for
              digital items, fast shipping for physical products.
            </p>
          </article>
        </div>
      </section>

      <!-- SHOP BY CATEGORY -->
      <!-- <section id="category" class="shop-category">
          <h2 class="section-title">
            Shop by <span class="title-accent">Category</span>
          </h2>
          <p class="section-subtitle">
            Explore merch, mockups, and design assets made for creators. Buy
            safely on trusted partner platforms.
          </p>

          
          <div class="filter-row">
            
            <div class="filter-pill" data-filter="tshirts">T-Shirts</div>
            <button class="filter-pill" data-filter="stickers">Stickers</button>
            <button class="filter-pill" data-filter="booklet">Booklet</button>
            <button class="filter-pill" data-filter="workbook">Workbook</button>
            <button class="filter-pill" data-filter="mockup">Mockup</button>
            <button class="filter-pill" data-filter="badges">Badges</button>
            <button class="filter-pill" data-filter="template">
              UI Template
            </button>
          </div>

          <div class="category-grid">
    
            <article class="category-card">
              <div class="category-img">
                <img src="img/bag.jpg" alt="T-shirts & Tote Bags" />
                <span class="category-pill">Apparel</span>
              </div>
              <div class="category-body">
                <h3>T-shirts &amp; Tote Bags</h3>
                <p>
                  Minimal tees, hoodies, and tote bags with clean UX-centric
                  designs for daily use.
                </p>
                <div class="category-actions">
                  <a href="#" class="btn-outline">View Templates</a>
                  <a href="#" class="btn-ghost">Buy Now</a>
                </div>
              </div>
            </article>

            <article class="category-card">
              <div class="category-img">
                <img src="img/img3.webp" alt="Stickers & Badges" />
                <span class="category-pill">Stickers</span>
              </div>
              <div class="category-body">
                <h3>Stickers &amp; Badges</h3>
                <p>
                  Vinyl stickers, logo badges, and desk swag designed for your
                  laptop, notebook, and workspace.
                </p>
                <div class="category-actions">
                  <a href="#" class="btn-outline">View Templates</a>
                  <a href="#" class="btn-ghost">Buy Now</a>
                </div>
              </div>
            </article>

            <article class="category-card">
              <div class="category-img">
                <img src="img/img2.webp" alt="Workbooks & Booklets" />
                <span class="category-pill">Learning</span>
              </div>
              <div class="category-body">
                <h3>Workbooks &amp; Booklets</h3>
                <p>
                  Learning design workbooks, project booklets, and guided UX
                  exercises for modern teams.
                </p>
                <div class="category-actions">
                  <a href="#" class="btn-outline">View Templates</a>
                  <a href="#" class="btn-ghost">Buy Now</a>
                </div>
              </div>
            </article>

            <article class="category-card">
              <div class="category-img">
                <img src="img/mockup.webp" alt="Digital Assets" />
                <span class="category-pill">Digital Assets</span>
              </div>
              <div class="category-body">
                <h3>Digital Assets</h3>
                <p>
                  Downloadable templates, UI kits, icon packs, and slide decks
                  for your next UX case study.
                </p>
                <div class="category-actions">
                  <a href="#" class="btn-outline">View Templates</a>
                  <a href="#" class="btn-ghost">Buy Now</a>
                </div>
              </div>
            </article>
          </div>
        </section> -->
      <!-- Just Launched at UXPACIFIC Shop -->
      <!-- SHOP TOP PRODUCTS -->
      <section id="products" class="top-products">
        <h2 class="section-title">
          Just
          <span class="title-accent">Launched
            <span style="font-weight: bold; font-weight: 600"> at </span>
            Shop</span>
        </h2>
        <p class="section-subtitle">
          Explore newly added products designed to inspire creativity, elevate
          your workflow, and represent the UXPACIFIC design mindset — both
          physical and digital.
        </p>

        <!-- Horizontal Line -->
        <!-- <div class="top-products-line"></div> -->

        <div class="category-box">
          <span>T-Shirts</span>
          <span>Badges</span>
          <span>Sticker</span>
          <span>Workbook</span>
          <span>Booklet</span>
          <span>Mockup</span>
          <span>UI Template</span>
        </div>

        <div class="glass-card-frame"></div>

        <!-- Product grid -->
        <div class="product-grid">
          <!-- 1 product example – duplicate / customize as needed -->
          <article class="product-card" data-category="stickers">
            <div class="product-img">
              <img src="img/sticker.webp" alt="Designer Sticker Pack" />
              <span class="product-tag">Stickers</span>
            </div>
            <div class="product-body">
              <h3>Designer Sticker Pack</h3>
              <p>
                A fun set of UX, UI, and product stickers for laptops,
                notebooks, and desk decor.
              </p>
              <p>Size : A5 / A4 printable</p>
              <div class="product-meta">
                <div class="product-price">$349 <span>$899</span></div>
                <div class="product-rating">★ 4.8</div>
              </div>
              <div class="product-actions">
                <button onclick="addToCart('sticker-pack-001')" class="btn-primary small"
                  aria-label="Add Designer Sticker Pack to cart">Add to Cart</button>
                <a href="product.php" class="btn-ghost small">View Details</a>
              </div>
            </div>
          </article>

          <article class="product-card" data-category="stickers">
            <div class="product-img">
              <img src="img/white.webp" alt="UXPacific Classic Hoodie" />
              <span class="product-tag">T-Shirts</span>
            </div>
            <div class="product-body">
              <h3>UXPacific Classic T-Shirt</h3>
              <p>
                Premium cotton-blend T-Shirt with understated branding &
                minimalist front print.
              </p>
              <p>Size : S / M / L / Xl</p>
              <div class="product-meta">
                <div class="product-price">$349 <span>$899</span></div>
                <div class="product-rating">★ 4.7</div>
              </div>
              <div class="product-actions">
                <button onclick="addToCart('tshirt-001')" class="btn-primary small" aria-label="Add to cart">Add to
                  Cart</button>
                <a href="product.php" class="btn-ghost small">View Details</a>
              </div>
            </div>
          </article>

          <article class="product-card" data-category="stickers">
            <div class="product-img">
              <img src="img/tule.webp" alt="UXPacific Classic Hoodie" />
              <span class="product-tag">T-Shirts</span>
            </div>
            <div class="product-body">
              <h3>UXPacific Classic T-Shirt</h3>
              <p>
                Premium cotton-blend T-Shirt with understated branding &
                minimalist front print.
              </p>
              <p>Size : S / M / L / Xl</p>
              <div class="product-meta">
                <div class="product-price">$349 <span>$899</span></div>
                <div class="product-rating">★ 4.7</div>
              </div>
              <div class="product-actions">
                <button onclick="addToCart('tshirt-001')" class="btn-primary small" aria-label="Add to cart">Add to
                  Cart</button>
                <a href="product.php" class="btn-ghost small">View Details</a>
              </div>
            </div>
          </article>

          <article class="product-card">
            <div class="product-img">
              <img src="img/bk.webp" alt="UXPacific Booklet" />
              <span class="product-tag">Booklet</span>
            </div>
            <div class="product-body">
              <h3>UXPacific Booklet</h3>
              <p>
                A curated booklet template to showcase your UX case studies
                and portfolio projects.
              </p>
              <p>Size : A4 / Digital PDF</p>
              <div class="product-meta">
                <div class="product-price">$349 <span>$899</span></div>
                <div class="product-rating">★ 4.6</div>
              </div>
              <div class="product-actions">
                <button onclick="addToCart('tshirt-001')" class="btn-primary small" aria-label="Add to cart">Add to
                  Cart</button>
                <a href="product.php" class="btn-ghost small">View Details</a>
              </div>
            </div>
          </article>

          <article class="product-card">
            <div class="product-img">
              <img src="img/mockup.webp" alt="UXPacific Mockup" />
              <span class="product-tag">Mockup</span>
            </div>
            <div class="product-body">
              <h3>UXPacific Mockup</h3>
              <p>
                A detailed, responsive mockup template for presenting digital
                product designs.
              </p>
              <p>Size : High-Resolution PNG / PSD</p>
              <div class="product-meta">
                <div class="product-price">$349 <span>$899</span></div>
                <div class="product-rating">★ 4.5</div>
              </div>
              <div class="product-actions">
                <button onclick="addToCart('tshirt-001')" class="btn-primary small" aria-label="Add to cart">Add to
                  Cart</button>
                <a href="product.php" class="btn-ghost small">View Details</a>
              </div>
            </div>
          </article>

          <article class="product-card">
            <div class="product-img">
              <img src="img/b11.webp" alt="UXPacific Mockup" />
              <span class="product-tag">Badge Pack</span>
            </div>
            <div class="product-body">
              <h3>UXPacific Badge Pack</h3>
              <p>
                A clean badge pack designed for communities, profiles, and
                achievements.
              </p>
              <p>Size : PNG / SVG / 1024px</p>

              <div class="product-meta">
                <div class="product-price">$349 <span>$899</span></div>
                <div class="product-rating">★ 4.5</div>
              </div>
              <div class="product-actions">
                <button onclick="addToCart('tshirt-001')" class="btn-primary small" aria-label="Add to cart">Add to
                  Cart</button>
                <a href="product.php" class="btn-ghost small">View Details</a>
              </div>
            </div>
          </article>

          <article class="product-card">
            <div class="product-img">
              <img src="img/template.webp" alt="UXPacific Mockup" />
              <span class="product-tag">Template</span>
            </div>
            <div class="product-body">
              <h3>UXPacific UI Template</h3>
              <p>
                A detailed, responsive mockup template for presenting digital
                product designs.
              </p>
              <p>Size : Figma / Auto-Layout-Ready</p>
              <div class="product-meta">
                <div class="product-price">$349 <span>$899</span></div>
                <div class="product-rating">★ 4.5</div>
              </div>
              <div class="product-actions">
                <button onclick="addToCart('tshirt-001')" class="btn-primary small" aria-label="Add to cart">Add to
                  Cart</button>
                <a href="product.php" class="btn-ghost small">View Details</a>
              </div>
            </div>
          </article>

          <article class="product-card">
            <div class="product-img">
              <img src="img/workbk.webp" alt="UXPacific Mockup" />
              <span class="product-tag">Workbook</span>
            </div>
            <div class="product-body">
              <h3>UXPacific Mockup</h3>
              <p>
                A detailed, responsive mockup template for presenting digital
                product designs.
              </p>
              <p>Size : A4 / Digital PDF</p>
              <div class="product-meta">
                <div class="product-price">$349 <span>$899</span></div>
                <div class="product-rating">★ 4.5</div>
              </div>
              <div class="product-actions">
                <button onclick="addToCart('tshirt-001')" class="btn-primary small" aria-label="Add to cart">Add to
                  Cart</button>
                <a href="product.php" class="btn-ghost small">View Details</a>
              </div>
            </div>
          </article>

          <!-- <article>
              <a href="shopAll.php" class="">
                <img src="img/arrow.webp" class="shop-image" alt="View all products arrow" />
              </a>
            </article> -->

          <!-- Add more cards as needed to fill the grid -->
        </div>

        <!-- View All Products Button -->
        <!-- <div class="top-products-btn-wrapper" style="margin-top: 50px;">
            <a href="shopAll.php" class="view-all-btn">View All Products</a>
          </div> -->
      </section>

      <!-- CTA / READY SECTION -->
      <section class="cta-section">
        <div class="cta-card">
          <h2 class="section-title">
            Explore the
            <span class="title-accent">Full UXPACIFIC Collection</span>
          </h2>
          <p class="section-subtitle">
            Looking for more than just the latest drops? Browse our complete
            range of physical and digital products — from apparel and creative
            merchandise to UI templates, workbooks, and design resources.
          </p>

          <div class="cta-actions">
            <a href="shopAll.php" class="btn-primary btn-shop">Buy All Products</a>
            <!-- <a href="#" class="btn-ghost">Join Our Community</a> -->
          </div>
        </div>
      </section>
    </main>

    <!-- FOOTER -->
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
    </footer>
  </div>

  <script src="script.js"></script>
</body>

</html>
