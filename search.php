<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="description" content="Search for UX/UI design resources, merchandise, and products at UX Pacific Shop" />
    <meta name="keywords" content="UX design, UI templates, design resources, search products" />
    <title>Search Products – UX Pacific Shop</title>
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
        <section class="search-section">
          <div class="search-container">
            <!-- Search Bar -->
            <div class="search-header">
              <h1 class="search-title">Search Products</h1>
              <div class="search-bar-wrapper">
                <input
                  type="text"
                  id="search-input"
                  class="search-input"
                  placeholder="Search for products, categories, or keywords..."
                  autocomplete="off"
                />
                <button class="search-button" onclick="performSearch()">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="11" cy="11" r="8"></circle>
                    <path d="m21 21-4.35-4.35"></path>
                  </svg>
                </button>
              </div>
              <div id="search-suggestions" class="search-suggestions"></div>
            </div>

            <!-- Filters and Sort -->
            <div class="search-filters">
              <div class="filter-group">
                <label>Category:</label>
                <select id="category-filter" class="filter-select">
                  <option value="">All Categories</option>
                  <option value="T-Shirts">T-Shirts</option>
                  <option value="Stickers">Stickers</option>
                  <option value="Booklet">Booklet</option>
                  <option value="workbook">Workbook</option>
                  <option value="Mockup">Mockup</option>
                  <option value="Badges">Badges</option>
                  <option value="template">UI Template</option>
                </select>
              </div>
              <div class="filter-group">
                <label>Sort by:</label>
                <select id="sort-filter" class="filter-select">
                  <option value="relevance">Relevance</option>
                  <option value="price-low">Price: Low to High</option>
                  <option value="price-high">Price: High to Low</option>
                  <option value="rating">Highest Rated</option>
                  <option value="newest">Newest First</option>
                </select>
              </div>
              <div class="filter-group">
                <label>Price Range:</label>
                <select id="price-filter" class="filter-select">
                  <option value="">All Prices</option>
                  <option value="0-500">$0 - $500</option>
                  <option value="500-1000">$500 - $1000</option>
                  <option value="1000-2000">$1000 - $2000</option>
                  <option value="2000+">$2000+</option>
                </select>
              </div>
            </div>

            <!-- Search Results -->
            <div class="search-results">
              <div id="search-results-header" class="results-header">
                <h2 id="results-count">0 results found</h2>
                <p id="search-query-display"></p>
              </div>

              <div id="search-results-grid" class="product-grid">
                <!-- Results will be loaded here -->
              </div>

              <div id="no-results" class="no-results" style="display: none;">
                <img src="img/cart-icon.webp" alt="No search results" />
                <h3>No products found</h3>
                <p>Try adjusting your search or filters</p>
                <a href="shopAll.php" class="btn-primary">Browse All Products</a>
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
            <a href="policies.php">Our Policies</a>
          </div>
        </div>
      </footer>
    </div>

    <script src="script.js"></script>
    <script>
      // Search functionality
      let allProducts = [];
      let searchHistory = JSON.parse(localStorage.getItem('searchHistory')) || [];

      // Load products from localStorage or use default products
      function loadProducts() {
        const savedProducts = localStorage.getItem('products');
        if (savedProducts) {
          allProducts = JSON.parse(savedProducts);
        } else {
          // Default products (can be replaced with API call)
          allProducts = [
            { id: 'sticker-1', name: 'Designer Sticker Pack', category: 'Stickers', price: 499, oldPrice: 899, rating: 4.5, image: 'img/sticker.webp', description: 'A fun mix of UX, UI, and product stickers' },
            { id: 'tshirt-1', name: 'UXPacific Classic T-Shirt', category: 'T-Shirts', price: 499, oldPrice: 899, rating: 4.7, image: 'img/tule.webp', description: 'Premium cotton-blend T-Shirt' },
            { id: 'booklet-1', name: 'UX Case Study Booklet', category: 'Booklet', price: 499, oldPrice: 899, rating: 4.6, image: 'img/bk.webp', description: 'A clean booklet template' },
            { id: 'mockup-1', name: 'UXPacific Device Mockup', category: 'Mockup', price: 499, oldPrice: 899, rating: 4.5, image: 'img/mockup.webp', description: 'High-resolution device mockups' },
            { id: 'badge-1', name: 'UXPacific Badge Pack', category: 'Badges', price: 499, oldPrice: 899, rating: 4.5, image: 'img/badg.webp', description: 'A clean badge pack' },
            { id: 'template-1', name: 'UXPacific UI Template', category: 'template', price: 499, oldPrice: 899, rating: 4.7, image: 'img/template.webp', description: 'Figma-based UI template' },
            { id: 'workbook-1', name: 'UXPacific Workbook', category: 'workbook', price: 499, oldPrice: 899, rating: 4.5, image: 'img/workbk.webp', description: 'Learning design workbook' }
          ];
          localStorage.setItem('products', JSON.stringify(allProducts));
        }
      }

      function performSearch() {
        const query = document.getElementById('search-input').value.trim().toLowerCase();
        if (!query) {
          document.getElementById('search-results-grid').innerHTML = '';
          document.getElementById('results-count').textContent = '0 results found';
          return;
        }

        // Save to search history
        if (!searchHistory.includes(query)) {
          searchHistory.unshift(query);
          searchHistory = searchHistory.slice(0, 10); // Keep last 10
          localStorage.setItem('searchHistory', JSON.stringify(searchHistory));
        }

        // Get filters
        const category = document.getElementById('category-filter').value;
        const priceFilter = document.getElementById('price-filter').value;
        const sortBy = document.getElementById('sort-filter').value;

        // Filter products
        let results = allProducts.filter(product => {
          const matchesQuery = product.name.toLowerCase().includes(query) ||
                              product.description.toLowerCase().includes(query) ||
                              product.category.toLowerCase().includes(query);
          
          const matchesCategory = !category || product.category === category;
          
          let matchesPrice = true;
          if (priceFilter) {
            const [min, max] = priceFilter.split('-').map(p => p.replace('+', ''));
            if (max) {
              matchesPrice = product.price >= parseInt(min) && product.price <= parseInt(max);
            } else {
              matchesPrice = product.price >= parseInt(min);
            }
          }
          
          return matchesQuery && matchesCategory && matchesPrice;
        });

        // Sort results
        if (sortBy === 'price-low') {
          results.sort((a, b) => a.price - b.price);
        } else if (sortBy === 'price-high') {
          results.sort((a, b) => b.price - a.price);
        } else if (sortBy === 'rating') {
          results.sort((a, b) => b.rating - a.rating);
        }

        // Display results
        displayResults(results, query);
      }

      function displayResults(results, query) {
        const grid = document.getElementById('search-results-grid');
        const count = document.getElementById('results-count');
        const queryDisplay = document.getElementById('search-query-display');
        const noResults = document.getElementById('no-results');

        count.textContent = `${results.length} result${results.length !== 1 ? 's' : ''} found`;
        queryDisplay.textContent = query ? `for "${query}"` : '';

        if (results.length === 0) {
          grid.innerHTML = '';
          noResults.style.display = 'block';
          return;
        }

        noResults.style.display = 'none';
        grid.innerHTML = results.map(product => `
          <article class="product-card" data-category="${product.category}">
            <div class="product-img">
              <img src="${product.image}" alt="${product.name}" />
              <span class="product-tag">${product.category}</span>
            </div>
            <div class="product-body">
              <h3>${product.name}</h3>
              <p>${product.description}</p>
              <div class="product-meta">
                <div class="product-price">$${product.price} <span>$${product.oldPrice}</span></div>
                <div class="product-rating">★ ${product.rating}</div>
              </div>
              <div class="product-actions">
                <button onclick="addToCart('${product.id}')" class="btn-primary small">Add to Cart</button>
                <a href="product.php" class="btn-ghost small">View Details</a>
              </div>
            </div>
          </article>
        `).join('');
      }

      // Event listeners
      document.addEventListener('DOMContentLoaded', function() {
        loadProducts();
        
        // Check for URL parameter
        const urlParams = new URLSearchParams(window.location.search);
        const query = urlParams.get('q');
        if (query) {
          document.getElementById('search-input').value = query;
          performSearch();
        }

        // Search on input
        document.getElementById('search-input').addEventListener('keypress', function(e) {
          if (e.key === 'Enter') {
            performSearch();
          }
        });

        // Auto-suggestions
        document.getElementById('search-input').addEventListener('input', function() {
          const query = this.value.trim().toLowerCase();
          const suggestions = document.getElementById('search-suggestions');
          
          if (query.length > 0) {
            const matches = searchHistory.filter(h => h.includes(query)).slice(0, 5);
            if (matches.length > 0) {
              suggestions.innerHTML = matches.map(m => `
                <div class="suggestion-item" onclick="selectSuggestion('${m}')">${m}</div>
              `).join('');
              suggestions.style.display = 'block';
            } else {
              suggestions.style.display = 'none';
            }
          } else {
            suggestions.style.display = 'none';
          }
        });

        // Filter changes
        document.getElementById('category-filter').addEventListener('change', performSearch);
        document.getElementById('price-filter').addEventListener('change', performSearch);
        document.getElementById('sort-filter').addEventListener('change', performSearch);
      });

      function selectSuggestion(text) {
        document.getElementById('search-input').value = text;
        document.getElementById('search-suggestions').style.display = 'none';
        performSearch();
      }

      window.performSearch = performSearch;
      window.selectSuggestion = selectSuggestion;
    </script>
  </body>
</html>


