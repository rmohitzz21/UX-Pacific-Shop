// Mobile nav toggle with accessibility support
const mobileBtn = document.getElementById("mobile-menu-btn");
const mobileMenu = document.getElementById("mobile-menu");

if (mobileBtn && mobileMenu) {
  mobileBtn.addEventListener("click", () => {
    const isOpen = mobileMenu.classList.toggle("open");
    mobileBtn.setAttribute("aria-expanded", isOpen);
  });
  
  // Close menu when clicking outside
  document.addEventListener("click", (e) => {
    if (!mobileBtn.contains(e.target) && !mobileMenu.contains(e.target)) {
      mobileMenu.classList.remove("open");
      mobileBtn.setAttribute("aria-expanded", "false");
    }
  });
  
  // Close menu on Escape key
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && mobileMenu.classList.contains("open")) {
      mobileMenu.classList.remove("open");
      mobileBtn.setAttribute("aria-expanded", "false");
      mobileBtn.focus();
    }
  });
}



// Active state for desktop nav links
const navLinks = document.querySelectorAll(".nav-link");

navLinks.forEach((link) => {
  link.addEventListener("click", () => {
    navLinks.forEach((l) => l.classList.remove("active"));
    link.classList.add("active");
  });
});





// ---------- PRODUCT FILTERING ----------
// const filterPills = document.querySelectorAll(".filter-pill");
// const productCards = document.querySelectorAll(".product-card");

// filterPills.forEach((pill) => {
//   pill.addEventListener("click", () => {
//     const filter = pill.dataset.filter; // e.g. "tshirts", "mockup", "all"

//     // active pill UI
//     filterPills.forEach((p) => p.classList.remove("active"));
//     pill.classList.add("active");

//     // show/hide products
//     productCards.forEach((card) => {
//       const categories = (card.dataset.category || "").split(","); // array

//       const match =
//         filter === "all" || categories.map((c) => c.trim()).includes(filter);

//       card.style.display = match ? "" : "none";
//     });
//   });
// });




 // --- MOBILE MENU LOGIC ---
    // const mobileBtn2 = document.getElementById('mobile-menu-btn');
    // const mobileMenu2 = document.getElementById('mobile-menu');
    
    // if (mobileBtn2 && mobileMenu2) {
    //     mobileBtn2.addEventListener('click', () => {
    //       mobileMenu2.classList.toggle('open');
    //     });
    // }

    // --- SMOOTH SCROLL ANIMATION LOGIC (Vanilla JS) ---
    const scrollContainer = document.querySelector('.hero-scroll-container');
    const cards = document.querySelectorAll('.hero-card');
    
    // Variables for smoothing (Linear Interpolation)
    let currentProgress = 0;
    let targetProgress = 0;
    const ease = 0.08; // 0.08 gives a heavy, professional, smooth feel

    function lerp(start, end, t) {
      return start * (1 - t) + end * t;
    }

    // Update target progress based on scroll position
    function handleScroll() {
      if(!scrollContainer) return;
      
      const viewportHeight = window.innerHeight;
      const rect = scrollContainer.getBoundingClientRect();
      
      // Calculate raw progress 0 to 1
      const totalScrollDistance = scrollContainer.offsetHeight - viewportHeight;
      let rawProgress = -rect.top / totalScrollDistance;
      
      // Clamp
      if (rawProgress < 0) rawProgress = 0;
      if (rawProgress > 1) rawProgress = 1;
      
      targetProgress = rawProgress;
    }

    // Animation Loop (Runs every frame for smoothness)
    function animate() {
      // Lerp current value towards target value
      // This creates the "buttery smooth" delay effect
      currentProgress = lerp(currentProgress, targetProgress, ease);
      
      const width = window.innerWidth;
      const height = window.innerHeight;

      // --- CONFIGURATION ---
      
      // START POSITIONS (Deck at Bottom - Half Visible)
      // anchored at top: 100% (bottom of screen).
      // y: -100 means the center of the card is 100px above bottom.
      // Since cards are ~300px tall, this makes them look like a deck peeking up.
      const startPositions = [
        { x: -60, y: -70, r: -15 },  // Card 1 (Left fan)
        { x: 60,  y: -70, r: 15 },   // Card 2 (Right fan)
        { x: -120, y: -40, r: -25 }, // Card 3 (Far Left fan)
        { x: 120,  y: -40, r: 25 },  // Card 4 (Far Right fan)
        { x: 0,   y: -100, r: 0 },   // Card 5 (Middle - Top of stack)
      ];

      // END POSITIONS (Spread Out)
      const endPositions = [
          { x: -width * 0.35, y: -height * 0.85, r: -20, s: 1.0 }, // Top Left 
          { x: width * 0.35,  y: -height * 0.85, r: 20,  s: 1.0 }, // Top Right 
          { x: -width * 0.35, y: -height * 0.25, r: -10, s: 1.0 }, // Bottom Left 
          { x: width * 0.35,  y: -height * 0.25, r: 10,  s: 1.0 }, // Bottom Right 
          { x: 0,             y: 0,              r: 0,   s: 1.3 }, // CENTER (Big & Centered)
      ];

      cards.forEach((card, index) => {
        if (!startPositions[index] || !endPositions[index]) return;

        const start = startPositions[index];
        const end = endPositions[index];

        const currentX = lerp(start.x, end.x, currentProgress);
        const currentY = lerp(start.y, end.y, currentProgress);
        const currentR = lerp(start.r, end.r, currentProgress);
        
        // Scale logic: Start smallish (0.7), go to specific end scale
        // Card 5 ends at 1.3, others at 1.0
        const startScale = 0.7;
        const endScale = end.s || 1.0;
        const currentScale = lerp(startScale, endScale, currentProgress);
        
        card.style.transform = `translate(calc(-50% + ${currentX}px), calc(-50% + ${currentY}px)) rotate(${currentR}deg) scale(${currentScale})`;
      });

      // NOTE: Text animation removed so it stays STATIC as requested.

      requestAnimationFrame(animate);
    }

    window.addEventListener('scroll', handleScroll);
    window.addEventListener('resize', handleScroll);
    
    // Kick off animation loop
    animate();



    document.addEventListener("DOMContentLoaded", function () {
  // only run on shopAll page
  if (!document.body.classList.contains("shopAll")) return;

  const filterButtons = Array.from(document.querySelectorAll(".shop-all-filters .filter-pill"));
  const productCards = Array.from(document.querySelectorAll(".product-card"));

  if (!filterButtons.length || !productCards.length) return; // nothing to do

  // Normalize text helper
  const norm = (s) => (s || "").toString().trim().toLowerCase();

  const ANIM_DURATION = 380; // ms
  const STAGGER = 65; // ms between cards entering
  let isFiltering = false;
  let queuedFilter = null;

  // Utility to test if card matches filter - IMPROVED CATEGORY MATCHING
  function cardMatchesFilter(card, filterValue) {
    if (!filterValue || filterValue === "all") return true;
    
    // Normalize filter value
    const normalizedFilter = norm(filterValue);
    
    // Get card categories - handle multiple categories separated by comma
    const cardCategory = norm(card.dataset.category || "");
    const cardCats = cardCategory
      .split(",")
      .map(c => c.trim())
      .filter(Boolean);
    
    // Also check the product-tag text content as fallback
    const productTag = card.querySelector(".product-tag");
    const tagText = productTag ? norm(productTag.textContent.trim()) : "";
    
    // Match against:
    // 1. Direct category match
    // 2. Tag text match
    // 3. Handle special cases like "UI Template" vs "template"
    const matchesCategory = cardCats.some(cat => {
      const normalizedCat = norm(cat);
      return normalizedCat === normalizedFilter || 
             normalizedCat.includes(normalizedFilter) ||
             normalizedFilter.includes(normalizedCat);
    });
    
    const matchesTag = tagText && (
      tagText === normalizedFilter ||
      tagText.includes(normalizedFilter) ||
      normalizedFilter.includes(tagText)
    );
    
    // Special handling for "UI Template" / "template" / "Template"
    if (normalizedFilter === "template" || normalizedFilter === "ui template") {
      return matchesCategory || matchesTag || 
             cardCats.some(cat => norm(cat).includes("template"));
    }
    
    // Special handling for "Badges" / "Badge"
    if (normalizedFilter === "badges" || normalizedFilter === "badge") {
      return matchesCategory || matchesTag ||
             cardCats.some(cat => norm(cat).includes("badge"));
    }
    
    return matchesCategory || matchesTag;
  }

  // Capture the original labels so we can append counts cleanly
  const baseLabels = new Map();
  filterButtons.forEach(btn => {
    baseLabels.set(btn, btn.textContent.trim());
  });

  // Pre-compute category counts for badge display
  const categoryCounts = productCards.reduce((acc, card) => {
    const cats = norm(card.dataset.category || "")
      .split(",")
      .map(c => c.trim())
      .filter(Boolean);
    cats.forEach(cat => {
      acc.set(cat, (acc.get(cat) || 0) + 1);
    });
    return acc;
  }, new Map());

  // Insert / update count badge on each pill
  function renderPillCounts() {
    filterButtons.forEach(btn => {
      const baseLabel = baseLabels.get(btn) || btn.textContent.trim();
      const key = norm(btn.dataset.filter || "all");
      const count = key === "all" ? productCards.length : (categoryCounts.get(key) || 0);

      // Reset text then append a count badge span for consistent layout
      btn.textContent = baseLabel;
      let badge = btn.querySelector(".pill-count");
      if (!badge) {
        badge = document.createElement("span");
        badge.className = "pill-count";
      }
      badge.textContent = count;
      btn.appendChild(badge);
    });
  }

  // Ensure all cards start visible and clean - INITIAL STATE
  productCards.forEach(card => {
    card.style.display = "";
    card.style.visibility = "visible";
    card.classList.remove("is-hidden", "is-exiting", "will-show");
    card.style.removeProperty("--card-delay");
    // Ensure card is in normal state
    card.style.opacity = "";
    card.style.transform = "";
  });

  renderPillCounts();

  // Animate cards out before removing from the grid - SMOOTH EXIT
  function animateOut(cards) {
    if (!cards.length) return Promise.resolve();
    return Promise.all(
      cards.map((card, idx) => new Promise(resolve => {
        // Remove any entrance classes
        card.classList.remove("will-show");
        // Add exit class for animation
        card.classList.add("is-exiting");
        card.style.setProperty("--card-delay", `${idx * STAGGER * 0.3}ms`);

        const finalize = () => {
          // Mark as hidden and remove from layout
          card.classList.add("is-hidden");
          card.classList.remove("is-exiting");
          card.style.display = "none";
          card.style.removeProperty("--card-delay");
          card.style.visibility = "hidden";
          resolve();
        };

        // Wait for transition to complete
        card.addEventListener("transitionend", (evt) => {
          if (evt.target !== card || evt.propertyName !== "opacity") return;
          finalize();
        }, { once: true });

        // Fallback timeout
        setTimeout(finalize, ANIM_DURATION + 100);
      }))
    );
  }

  // Animate cards into view with staggered delays - SMOOTH ENTRANCE
  function animateIn(cards) {
    if (!cards.length) return Promise.resolve();

    // Prepare cards for entrance animation
    cards.forEach((card, idx) => {
      // Remove hidden/exiting states
      card.classList.remove("is-hidden", "is-exiting");
      // Make visible in layout
      card.style.display = "";
      card.style.visibility = "visible";
      // Start with will-show class (hidden state)
      card.classList.add("will-show");
      // Set staggered delay
      card.style.setProperty("--card-delay", `${idx * STAGGER}ms`);
    });

    // Use double rAF to ensure styles are applied before animation
    return new Promise(resolve => {
      requestAnimationFrame(() => {
        requestAnimationFrame(() => {
          // Remove will-show to trigger entrance animation
          cards.forEach((card, idx) => {
            card.classList.remove("will-show");
            // Clean up delay after animation completes
            card.addEventListener("transitionend", (evt) => {
              if (evt.target !== card || evt.propertyName !== "opacity") return;
              card.style.removeProperty("--card-delay");
            }, { once: true });
          });
          // Resolve after all animations should be complete
          setTimeout(resolve, ANIM_DURATION + cards.length * STAGGER + 50);
        });
      });
    });
  }

  // Main filter handler with graceful animation + layout stability
  function applyFilter(filterValue, clickedBtn) {
    // If a filter is already mid-animation, queue the latest request
    if (isFiltering) {
      queuedFilter = { filterValue, clickedBtn };
      return;
    }
    isFiltering = true;

    // Update active state on buttons
    filterButtons.forEach(b => b.classList.toggle("active", b === clickedBtn));

    // Find matching cards using improved matching logic
    const matchingCards = productCards.filter(card => cardMatchesFilter(card, filterValue));
    
    // Cards that should exit (currently visible but don't match)
    const exiting = productCards.filter(card => {
      const isCurrentlyVisible = !card.classList.contains("is-hidden") && 
                                  card.style.display !== "none";
      const shouldBeVisible = matchingCards.includes(card);
      return isCurrentlyVisible && !shouldBeVisible;
    });
    
    // Cards that should enter (currently hidden but should match)
    const entering = matchingCards.filter(card => {
      const isCurrentlyHidden = card.classList.contains("is-hidden") || 
                                 card.style.display === "none";
      return isCurrentlyHidden;
    });

    // Animate out first, then animate in
    animateOut(exiting)
      .then(() => {
        // Small delay to ensure DOM updates
        return new Promise(resolve => setTimeout(resolve, 50));
      })
      .then(() => animateIn(entering))
      .then(() => {
        isFiltering = false;
        if (queuedFilter) {
          const { filterValue: queuedValue, clickedBtn: queuedBtn } = queuedFilter;
          queuedFilter = null;
          applyFilter(queuedValue, queuedBtn);
        }
      })
      .catch(err => {
        console.error("Filter animation error:", err);
        isFiltering = false;
      });

    // Optional: scroll first visible card into view on mobile
    setTimeout(() => {
      const firstVisible = matchingCards.find(c => {
        return !c.classList.contains("is-hidden") && 
               c.style.display !== "none";
      });
      if (firstVisible && window.innerWidth <= 900) {
        firstVisible.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    }, ANIM_DURATION + 100);
  }

  // attach listeners
  filterButtons.forEach(btn => {
    btn.addEventListener("click", function (e) {
      e.preventDefault();
      const filterVal = btn.dataset.filter ? btn.dataset.filter.trim() : "all";
      applyFilter(filterVal, btn);
    });
  });

  // Optional: support URL query like ?filter=Stickers
  const urlParams = new URLSearchParams(window.location.search);
  const initialFilter = urlParams.get("filter");
  if (initialFilter) {
    const matchingBtn = filterButtons.find(b => norm(b.dataset.filter) === norm(initialFilter));
    if (matchingBtn) {
      matchingBtn.click();
    }
  } else if (filterButtons.length) {
    // Default to the first pill being active to avoid "no active" flicker
    filterButtons[0].classList.add("active");
  }
});


document.querySelectorAll(".sizes button").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".sizes button")
      .forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
  });
});

// Qty selector logic

 let count = 1;
  const countEl = document.getElementById("count");

  function qty(change) {
    count += change;

    // Prevent quantity from going below 1
    if (count < 1) {
      count = 1;
    }

    countEl.textContent = count;
  }



  
  const tabButtons = document.querySelectorAll(".tab-btn");
  const tabBoxes = document.querySelectorAll(".tab-box");

  tabButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      const target = btn.dataset.tab;

      // Remove active state from all tabs
      tabButtons.forEach((b) => b.classList.remove("active"));
      tabBoxes.forEach((box) => box.classList.remove("active"));

      // Activate clicked tab + content
      btn.classList.add("active");
      document.getElementById(target).classList.add("active");
    });
  });

// Image Slider for Product Page
(function() {
  const mainImage = document.getElementById("mainProductImage");
  const slideCount = document.getElementById("slideCount");
  const dotsContainer = document.getElementById("sliderDots");
  
  // Only run if we're on the product page
  if (!mainImage || !dotsContainer) return;
  
  const images = ["img/t1.webp", "img/t2.webp", "img/t3.webp", "img/t4.webp"];
  const thumbs = document.querySelectorAll(".thumb");
  let currentIndex = 0; // Start with first image (matches active thumbnail)
  
  // Create dots
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
  
  window.setImage = function(i) {
    currentIndex = i;
    updateSlider();
  };
  
  window.changeImage = function(s) {
    currentIndex = (currentIndex + s + images.length) % images.length;
    updateSlider();
  };
  
  updateSlider();
})();

// ==================== CART FUNCTIONALITY ====================

// Cart storage (localStorage for now, will sync with backend later)
let cart = JSON.parse(localStorage.getItem('cart')) || [];

// Product database (temporary - replace with API call later)
const products = {
  'sticker-pack-001': { id: 'sticker-pack-001', name: 'Designer Sticker Pack', price: 499, oldPrice: 899, image: 'img/sticker.webp', category: 'Stickers' },
  'tshirt-001': { id: 'tshirt-001', name: 'UXPacific Classic T-Shirt', price: 349, oldPrice: 899, image: 'img/tule.webp', category: 'T-Shirts' },
  'booklet-001': { id: 'booklet-001', name: 'UXPacific Booklet', price: 349, oldPrice: 899, image: 'img/bk.webp', category: 'Booklet' },
  'mockup-001': { id: 'mockup-001', name: 'UXPacific Mockup', price: 349, oldPrice: 899, image: 'img/mockup.webp', category: 'Mockup' },
  'badge-001': { id: 'badge-001', name: 'UXPacific Badge Pack', price: 349, oldPrice: 899, image: 'img/badg.webp', category: 'Badges' },
  'template-001': { id: 'template-001', name: 'UXPacific UI Template', price: 349, oldPrice: 899, image: 'img/template.webp', category: 'Template' },
  'workbook-001': { id: 'workbook-001', name: 'UXPacific Workbook', price: 349, oldPrice: 899, image: 'img/workbk.webp', category: 'Workbook' }
};

// Add to cart
// Frontend-only: Includes product_type from localStorage
// Backend PHP logic will replace this condition
function addToCart(productId, size = null, quantity = 1) {
  const product = products[productId] || { id: productId, name: 'Product', price: 0, image: 'img/sticker.webp' };
  
  // Get product_type from localStorage (set on product page)
  const product_type = localStorage.getItem('product_type') || 'physical';
  
  const existingIndex = cart.findIndex(
    item => item.id === productId && item.size === size
  );
  
  if (existingIndex > -1) {
    cart[existingIndex].quantity += quantity;
    // Update product_type if changed
    cart[existingIndex].product_type = product_type;
  } else {
    cart.push({
      id: productId,
      name: product.name,
      price: product.price,
      image: product.image,
      size: size,
      quantity: quantity,
      product_type: product_type // Store product type with cart item
    });
  }
  
  saveCart();
  updateCartCount();
  showToast('Item added to cart!', 'success');
  
  // If on cart page, refresh it
  if (window.location.pathname.includes('cart.php')) {
    loadCartPage();
  }
}

// Remove from cart
function removeFromCart(productId, size = null) {
  cart = cart.filter(item => !(item.id === productId && item.size === size));
  saveCart();
  updateCartCount();
  showToast('Item removed from cart', 'success');
  
  if (window.location.pathname.includes('cart.php')) {
    loadCartPage();
  }
}

// Update cart item quantity
function updateCartQuantity(productId, size, newQuantity) {
  const item = cart.find(item => item.id === productId && item.size === size);
  if (item) {
    if (newQuantity <= 0) {
      removeFromCart(productId, size);
    } else {
      item.quantity = newQuantity;
      saveCart();
      updateCartCount();
      if (window.location.pathname.includes('cart.php')) {
        loadCartPage();
      }
    }
  }
}

// Save cart to localStorage
function saveCart() {
  localStorage.setItem('cart', JSON.stringify(cart));
}

// Update cart count badge
function updateCartCount() {
  const count = cart.reduce((sum, item) => sum + item.quantity, 0);
  const badges = document.querySelectorAll('#cart-count');
  badges.forEach(badge => {
    if (badge) {
      badge.textContent = count;
      badge.style.display = count > 0 ? 'flex' : 'none';
      if (count > 0) {
        badge.style.display = 'flex';
      } else {
        badge.style.display = 'none';
      }
    }
  });
}

// Calculate cart total
function getCartTotal() {
  return cart.reduce((sum, item) => sum + (item.price * item.quantity), 0);
}

// Load cart page
function loadCartPage() {
  const cartItemsContainer = document.getElementById('cart-items');
  const cartEmpty = document.getElementById('cart-empty');
  const checkoutBtn = document.getElementById('checkout-btn');
  
  if (!cartItemsContainer) return;
  
  if (cart.length === 0) {
    cartEmpty.style.display = 'block';
    if (checkoutBtn) checkoutBtn.style.display = 'none';
    return;
  }
  
  cartEmpty.style.display = 'none';
  
  // Check if user is signed in before showing checkout button
  const userSession = getUserSession();
  if (checkoutBtn) {
    if (userSession) {
      checkoutBtn.style.display = 'block';
      checkoutBtn.href = 'checkout.php';
    } else {
      checkoutBtn.style.display = 'block';
      checkoutBtn.href = 'signin.php?redirect=checkout.php';
      checkoutBtn.textContent = 'Sign in to Checkout';
      checkoutBtn.classList.add('checkout-signin-prompt');
    }
  }
  
  cartItemsContainer.innerHTML = cart.map(item => `
    <div class="cart-item">
      <img src="${item.image}" alt="${item.name}" class="cart-item-image" />
      <div class="cart-item-details">
        <h3 class="cart-item-title">${item.name}</h3>
        <p class="cart-item-meta">${item.size ? `Size: ${item.size} • ` : ''}Quantity: ${item.quantity}</p>
        <p class="cart-item-price">$${item.price * item.quantity}</p>
      </div>
      <div class="cart-item-actions">
        <div class="cart-item-qty">
          <button onclick="updateCartQuantity('${item.id}', '${item.size || ''}', ${item.quantity - 1})">−</button>
          <span>${item.quantity}</span>
          <button onclick="updateCartQuantity('${item.id}', '${item.size || ''}', ${item.quantity + 1})">+</button>
        </div>
        <button class="remove-item" onclick="removeFromCart('${item.id}', '${item.size || ''}')">Remove</button>
      </div>
    </div>
  `).join('');
  
  // Update totals
  const subtotal = getCartTotal();
  const shipping = subtotal > 0 ? 50 : 0;
  const tax = Math.round(subtotal * 0.18);
  const total = subtotal + shipping + tax;
  
  document.getElementById('cart-subtotal').textContent = `$${subtotal}`;
  document.getElementById('cart-shipping').textContent = shipping > 0 ? `$${shipping}` : 'Free';
  document.getElementById('cart-tax').textContent = `$${tax}`;
  document.getElementById('cart-total').textContent = `$${total}`;
}

// Load checkout page
function loadCheckoutPage() {
  const checkoutItemsContainer = document.getElementById('checkout-items');
  
  if (!checkoutItemsContainer) return;
  
  if (cart.length === 0) {
    window.location.href = 'cart.php';
    return;
  }
  
  checkoutItemsContainer.innerHTML = cart.map(item => `
    <div class="checkout-item">
      <img src="${item.image}" alt="${item.name}" class="checkout-item-image" />
      <div class="checkout-item-info">
        <div class="checkout-item-name">${item.name}</div>
        <div class="checkout-item-details">${item.size ? `Size: ${item.size} • ` : ''}Qty: ${item.quantity}</div>
      </div>
      <div class="checkout-item-price">$${item.price * item.quantity}</div>
    </div>
  `).join('');
  
  // Update totals
  const subtotal = getCartTotal();
  const shipping = 50;
  const tax = Math.round(subtotal * 0.18);
  const total = subtotal + shipping + tax;
  
  document.getElementById('checkout-subtotal').textContent = `$${subtotal}`;
  document.getElementById('checkout-shipping').textContent = `$${shipping}`;
  document.getElementById('checkout-tax').textContent = `$${tax}`;
  document.getElementById('checkout-total').textContent = `$${total}`;
}

// Toast notification with improved accessibility
function showToast(message, type = 'success') {
  // Remove existing toasts to prevent stacking
  const existingToasts = document.querySelectorAll('.toast');
  existingToasts.forEach(t => t.remove());
  
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  toast.setAttribute('role', 'alert');
  toast.setAttribute('aria-live', 'polite');
  toast.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    background: ${type === 'success' ? '#4caf50' : '#ff4444'};
    color: white;
    padding: 16px 24px;
    border-radius: 12px;
    z-index: 10000;
    animation: slideIn 0.3s ease;
    max-width: 90vw;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
  `;
  
  document.body.appendChild(toast);
  
  // Focus management for screen readers
  toast.focus();
  
  setTimeout(() => {
    toast.style.animation = 'slideOut 0.3s ease';
    setTimeout(() => {
      toast.remove();
    }, 300);
  }, 3000);
}

// Initialize cart on page load
document.addEventListener('DOMContentLoaded', function() {
  updateCartCount();
  updateUserMenu();
  
  // Initialize user dropdown
  document.querySelectorAll('.nav-user').forEach(menu => {
    menu.addEventListener('click', toggleUserDropdown);
  });
  
  if (window.location.pathname.includes('cart.php')) {
    loadCartPage();
  }
  
  if (window.location.pathname.includes('checkout.php')) {
    // Check if user is signed in
    const userSession = getUserSession();
    if (!userSession) {
      showToast('Please sign in to proceed to checkout', 'error');
      setTimeout(() => {
        window.location.href = 'signin.php?redirect=checkout.php';
      }, 1500);
      return;
    }
    
    // Check if cart is empty
    if (cart.length === 0) {
      showToast('Your cart is empty!', 'error');
      setTimeout(() => {
        window.location.href = 'cart.php';
      }, 1500);
      return;
    }
    
    loadCheckoutPage();
    
    // Handle payment method change
    document.querySelectorAll('input[name="paymentMethod"]').forEach(radio => {
      radio.addEventListener('change', function() {
        const cardDetails = document.getElementById('card-details');
        if (this.value === 'card') {
          cardDetails.style.display = 'block';
        } else {
          cardDetails.style.display = 'none';
        }
      });
    });
  }
  
  // Load order confirmation page
  if (window.location.pathname.includes('order-confirmation.php')) {
    loadOrderConfirmationPage();
  }
});

// ==================== FORM HANDLERS ====================

// User Session Management
function getUserSession() {
  return JSON.parse(localStorage.getItem('userSession')) || null;
}

function setUserSession(userData) {
  localStorage.setItem('userSession', JSON.stringify(userData));
  updateUserMenu();
}

function clearUserSession() {
  localStorage.removeItem('userSession');
  updateUserMenu();
}

function updateUserMenu() {
  const userSession = getUserSession();
  const userMenus = document.querySelectorAll('.nav-user');
  const signInButtons = document.querySelectorAll('.nav-cta[href="signin.php"]');
  
  if (userSession) {
    // Show user menu, hide sign in button
    userMenus.forEach(menu => {
      menu.style.display = 'flex';
      const userName = menu.querySelector('.user-name');
      const userAvatar = menu.querySelector('.user-avatar');
      
      if (userName) {
        userName.textContent = userSession.firstName || userSession.name || 'User';
      }
      
      if (userAvatar) {
        const initial = (userSession.firstName || userSession.name || 'U').charAt(0).toUpperCase();
        userAvatar.textContent = initial;
      }
    });
    
    signInButtons.forEach(btn => {
      btn.style.display = 'none';
    });
  } else {
    // Hide user menu, show sign in button
    userMenus.forEach(menu => {
      menu.style.display = 'none';
    });
    
    signInButtons.forEach(btn => {
      btn.style.display = 'inline-flex';
    });
  }
}

// User dropdown toggle with accessibility support
function toggleUserDropdown(event) {
  event.stopPropagation();
  const userMenu = event.currentTarget.closest('.nav-user');
  if (!userMenu) return;
  
  const isActive = userMenu.classList.contains('active');
  
  // Close all other dropdowns
  document.querySelectorAll('.nav-user').forEach(menu => {
    menu.classList.remove('active');
    menu.setAttribute('aria-expanded', 'false');
  });
  
  // Toggle current dropdown
  if (!isActive) {
    userMenu.classList.add('active');
    userMenu.setAttribute('aria-expanded', 'true');
  } else {
    userMenu.setAttribute('aria-expanded', 'false');
  }
}

// Close dropdown when clicking outside
document.addEventListener('click', function(event) {
  if (!event.target.closest('.nav-user')) {
    document.querySelectorAll('.nav-user').forEach(menu => {
      menu.classList.remove('active');
      menu.setAttribute('aria-expanded', 'false');
    });
  }
});

// Keyboard navigation for user menu
document.addEventListener('DOMContentLoaded', function() {
  document.querySelectorAll('.nav-user').forEach(menu => {
    menu.addEventListener('keydown', function(e) {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        toggleUserDropdown(e);
      } else if (e.key === 'Escape') {
        menu.classList.remove('active');
        menu.setAttribute('aria-expanded', 'false');
      }
    });
  });
});

// ==================== VALIDATION FUNCTIONS ====================

// Email validation
function validateEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

// Phone validation (supports international formats)
function validatePhone(phone) {
  const phoneRegex = /^[\d\s\-\+\(\)]{10,}$/;
  return phoneRegex.test(phone.replace(/\s/g, ''));
}

// Password validation
function validatePassword(password) {
  // At least 8 characters, 1 uppercase, 1 lowercase, 1 number
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$/;
  return passwordRegex.test(password);
}

// Show field error (supports both old and new format)
function showFieldError(field, message) {
  if (!field) return;
  
  // Try to find error span (supports both .field-error and .field-error-modern)
  const errorSpan = field.parentElement?.querySelector('.field-error-modern') || 
                   field.parentElement?.querySelector('.field-error') ||
                   field.closest('.form-field-modern')?.querySelector('.field-error-modern') ||
                   field.closest('.form-field')?.querySelector('.field-error');
  
  if (errorSpan) {
    errorSpan.textContent = message;
    errorSpan.style.display = 'block';
  }
  
  // Update field border
  field.style.borderColor = '#ef4444';
}

// Clear field error (supports both old and new format)
function clearFieldError(field) {
  if (!field) return;
  
  // Try to find error span (supports both .field-error and .field-error-modern)
  const errorSpan = field.parentElement?.querySelector('.field-error-modern') || 
                   field.parentElement?.querySelector('.field-error') ||
                   field.closest('.form-field-modern')?.querySelector('.field-error-modern') ||
                   field.closest('.form-field')?.querySelector('.field-error');
  
  if (errorSpan) {
    errorSpan.textContent = '';
    errorSpan.style.display = 'none';
  }
  
  // Reset field border
  field.style.borderColor = '';
}

// Real-time validation
function setupRealTimeValidation() {
  // Email fields
  document.querySelectorAll('input[type="email"]').forEach(field => {
    field.addEventListener('blur', function() {
      if (this.value && !validateEmail(this.value)) {
        showFieldError(this, 'Please enter a valid email address');
      } else {
        clearFieldError(this);
      }
    });
    
    field.addEventListener('input', function() {
      if (this.value && validateEmail(this.value)) {
        clearFieldError(this);
      }
    });
  });
  
  // Phone fields
  document.querySelectorAll('input[type="tel"]').forEach(field => {
    field.addEventListener('blur', function() {
      if (this.value && !validatePhone(this.value)) {
        showFieldError(this, 'Please enter a valid phone number');
      } else {
        clearFieldError(this);
      }
    });
    
    field.addEventListener('input', function() {
      if (this.value && validatePhone(this.value)) {
        clearFieldError(this);
      }
    });
  });
  
  // Password fields
  document.querySelectorAll('input[type="password"]').forEach(field => {
    if (field.name === 'password' || field.name === 'newPassword') {
      field.addEventListener('blur', function() {
        if (this.value && this.value.length < 8) {
          showFieldError(this, 'Password must be at least 8 characters');
        } else if (this.value && !validatePassword(this.value)) {
          showFieldError(this, 'Password must contain uppercase, lowercase, and number');
        } else {
          clearFieldError(this);
        }
      });
    }
    
    if (field.name === 'confirmPassword' || field.name === 'confirmNewPassword') {
      field.addEventListener('blur', function() {
        const passwordField = this.form.querySelector('input[name="password"], input[name="newPassword"]');
        if (passwordField && this.value !== passwordField.value) {
          showFieldError(this, 'Passwords do not match');
        } else {
          clearFieldError(this);
        }
      });
    }
  });
  
  // Card number formatting
  document.querySelectorAll('input[name="cardNumber"]').forEach(field => {
    field.addEventListener('input', function(e) {
      let value = e.target.value.replace(/\s/g, '');
      let formattedValue = value.match(/.{1,4}/g)?.join(' ') || value;
      if (formattedValue.length <= 19) {
        e.target.value = formattedValue;
      }
    });
  });
  
  // Expiry date formatting
  document.querySelectorAll('input[name="expiry"]').forEach(field => {
    field.addEventListener('input', function(e) {
      let value = e.target.value.replace(/\D/g, '');
      if (value.length >= 2) {
        value = value.substring(0, 2) + '/' + value.substring(2, 4);
      }
      e.target.value = value;
    });
  });
  
  // CVV validation
  document.querySelectorAll('input[name="cvv"]').forEach(field => {
    field.addEventListener('input', function(e) {
      e.target.value = e.target.value.replace(/\D/g, '');
    });
  });
  
  // ZIP code validation
  document.querySelectorAll('input[name="zip"]').forEach(field => {
    field.addEventListener('input', function(e) {
      e.target.value = e.target.value.replace(/\D/g, '');
    });
  });
}

// Initialize real-time validation on page load
document.addEventListener('DOMContentLoaded', function() {
  setupRealTimeValidation();
});

// Sign in handler with enhanced validation
function handleSignIn(event) {
  event.preventDefault();
  
  const form = event.target;
  const email = form.email.value.trim();
  const password = form.password.value;
  const btn = document.getElementById('signin-btn');
  const btnText = document.getElementById('signin-text');
  const btnLoader = document.getElementById('signin-loader');
  const errorDiv = document.getElementById('auth-error');
  const successDiv = document.getElementById('auth-success');
  
  // Clear previous errors
  errorDiv.style.display = 'none';
  successDiv.style.display = 'none';
  
  // Validation
  let isValid = true;
  
  if (!email) {
    showFieldError(form.email, 'Email is required');
    isValid = false;
  } else if (!validateEmail(email)) {
    showFieldError(form.email, 'Please enter a valid email address');
    isValid = false;
  } else {
    clearFieldError(form.email);
  }
  
  if (!password) {
    showFieldError(form.password, 'Password is required');
    isValid = false;
  } else if (password.length < 6) {
    showFieldError(form.password, 'Password must be at least 6 characters');
    isValid = false;
  } else {
    clearFieldError(form.password);
  }
  
  if (!isValid) {
    return;
  }
  
  // Show loading
  btn.disabled = true;
  btnText.style.display = 'none';
  btnLoader.style.display = 'inline';
  
  // TODO: Replace with actual API call
  setTimeout(() => {
    // Simulate API call
    if (email && password.length >= 6) {
      // Create user session
      const userData = {
        email: email,
        firstName: email.split('@')[0].split('.')[0],
        name: email.split('@')[0],
        loginTime: new Date().toISOString()
      };
      setUserSession(userData);
      
      successDiv.textContent = 'Sign in successful! Redirecting...';
      successDiv.style.display = 'block';
      handleSignInRedirect();
    } else {
      errorDiv.textContent = 'Invalid email or password';
      errorDiv.style.display = 'block';
      btn.disabled = false;
      btnText.style.display = 'inline';
      btnLoader.style.display = 'none';
    }
  }, 1000);
}

// Sign out handler
function handleSignOut() {
  clearUserSession();
  showToast('Signed out successfully', 'success');
  setTimeout(() => {
    window.location.href = 'index.php';
  }, 1000);
}

// Contact form handler
function handleContactSubmit(event) {
  event.preventDefault();
  
  const form = event.target;
  const formData = {
    name: form.name.value,
    email: form.email.value,
    phone: form.phone.value,
    subject: form.subject.value,
    message: form.message.value
  };
  
  // TODO: Replace with actual API call
  showToast('Thank you! We will contact you soon.', 'success');
  form.reset();
}

// Checkout handler with enhanced validation
function handleCheckout(event) {
  event.preventDefault();
  
  // Check if user is signed in
  const userSession = getUserSession();
  if (!userSession) {
    showToast('Please sign in to complete your order', 'error');
    setTimeout(() => {
      window.location.href = 'signin.php?redirect=checkout.php';
    }, 1500);
    return;
  }
  
  if (cart.length === 0) {
    showToast('Your cart is empty!', 'error');
    return;
  }
  
  const form = event.target;
  const btn = document.getElementById('place-order-btn');
  const btnText = document.getElementById('order-text');
  const btnLoader = document.getElementById('order-loader');
  
  // Validation
  let isValid = true;
  
  // Shipping information validation
  const firstName = form.firstName?.value.trim();
  const lastName = form.lastName?.value.trim();
  const email = form.email?.value.trim();
  const phone = form.phone?.value.trim();
  const address = form.address?.value.trim();
  const city = form.city?.value.trim();
  const state = form.state?.value.trim();
  const zip = form.zip?.value.trim();
  const country = form.country?.value;
  const paymentMethod = form.paymentMethod?.value;
  
  if (!firstName || firstName.length < 2) {
    if (form.firstName) showFieldError(form.firstName, 'First name must be at least 2 characters');
    isValid = false;
  } else if (form.firstName) clearFieldError(form.firstName);
  
  if (!lastName || lastName.length < 2) {
    if (form.lastName) showFieldError(form.lastName, 'Last name must be at least 2 characters');
    isValid = false;
  } else if (form.lastName) clearFieldError(form.lastName);
  
  if (!email) {
    if (form.email) showFieldError(form.email, 'Email is required');
    isValid = false;
  } else if (!validateEmail(email)) {
    if (form.email) showFieldError(form.email, 'Please enter a valid email address');
    isValid = false;
  } else if (form.email) clearFieldError(form.email);
  
  if (!phone) {
    if (form.phone) showFieldError(form.phone, 'Phone number is required');
    isValid = false;
  } else if (!validatePhone(phone)) {
    if (form.phone) showFieldError(form.phone, 'Please enter a valid phone number');
    isValid = false;
  } else if (form.phone) clearFieldError(form.phone);
  
  if (!address || address.length < 5) {
    if (form.address) showFieldError(form.address, 'Please enter a valid address');
    isValid = false;
  } else if (form.address) clearFieldError(form.address);
  
  if (!city || city.length < 2) {
    if (form.city) showFieldError(form.city, 'City is required');
    isValid = false;
  } else if (form.city) clearFieldError(form.city);
  
  if (!state || state.length < 2) {
    if (form.state) showFieldError(form.state, 'State is required');
    isValid = false;
  } else if (form.state) clearFieldError(form.state);
  
  if (!zip || zip.length < 4) {
    if (form.zip) showFieldError(form.zip, 'Please enter a valid ZIP code');
    isValid = false;
  } else if (form.zip) clearFieldError(form.zip);
  
  // Payment method validation
  if (paymentMethod === 'card') {
    const cardNumber = form.cardNumber?.value.replace(/\s/g, '');
    const expiry = form.expiry?.value;
    const cvv = form.cvv?.value;
    const cardName = form.cardName?.value.trim();
    
    if (!cardNumber || cardNumber.length < 13) {
      if (form.cardNumber) showFieldError(form.cardNumber, 'Please enter a valid card number');
      isValid = false;
    } else if (form.cardNumber) clearFieldError(form.cardNumber);
    
    if (!expiry || !/^\d{2}\/\d{2}$/.test(expiry)) {
      if (form.expiry) showFieldError(form.expiry, 'Please enter a valid expiry date (MM/YY)');
      isValid = false;
    } else if (form.expiry) clearFieldError(form.expiry);
    
    if (!cvv || cvv.length < 3) {
      if (form.cvv) showFieldError(form.cvv, 'Please enter a valid CVV');
      isValid = false;
    } else if (form.cvv) clearFieldError(form.cvv);
    
    if (!cardName || cardName.length < 2) {
      if (form.cardName) showFieldError(form.cardName, 'Cardholder name is required');
      isValid = false;
    } else if (form.cardName) clearFieldError(form.cardName);
  }
  
  if (!isValid) {
    showToast('Please fill in all required fields correctly', 'error');
    return;
  }
  
  // Show loading
  btn.disabled = true;
  btnText.style.display = 'none';
  btnLoader.style.display = 'inline';
  
  // TODO: Replace with actual payment processing
  setTimeout(() => {
    // Calculate totals
    const subtotal = getCartTotal();
    const shipping = 50;
    const tax = Math.round(subtotal * 0.18);
    const total = subtotal + shipping + tax;
    
    // Create order
    const orderNumber = 'UXP-' + new Date().getFullYear() + '-' + String(Math.floor(Math.random() * 1000000)).padStart(6, '0');
    const orderData = {
      orderNumber: orderNumber,
      date: new Date().toISOString(),
      items: cart.map(item => ({
        id: item.id,
        name: item.name,
        price: item.price,
        image: item.image,
        size: item.size,
        quantity: item.quantity
      })),
      total: total,
      subtotal: subtotal,
      shipping: shipping,
      tax: tax,
      paymentMethod: form.paymentMethod?.value || 'card',
      shipping: {
        firstName: form.firstName?.value || '',
        lastName: form.lastName?.value || '',
        email: form.email?.value || '',
        phone: form.phone?.value || '',
        address: form.address?.value || '',
        city: form.city?.value || '',
        state: form.state?.value || '',
        zip: form.zip?.value || '',
        country: form.country?.value || 'IN'
      },
      status: 'Pending'
    };
    
    // Save order
    const orders = JSON.parse(localStorage.getItem('orders')) || [];
    orders.unshift(orderData);
    localStorage.setItem('orders', JSON.stringify(orders));
    
    // Save last order for confirmation page (with items array)
    localStorage.setItem('lastOrder', JSON.stringify(orderData));
    
    // Simulate payment processing
    showToast('Order placed successfully!', 'success');
    
    // Clear cart
    cart = [];
    saveCart();
    updateCartCount();
    
    // Redirect to order confirmation
    setTimeout(() => {
      window.location.href = 'order-confirmation.php';
    }, 1500);
  }, 2000);
}

// Load order confirmation page with order details
function loadOrderConfirmationPage() {
  const orderData = JSON.parse(localStorage.getItem('lastOrder'));
  
  if (!orderData) {
    // If no order data, redirect to shop
    showToast('No order found. Redirecting to shop...', 'error');
    setTimeout(() => {
      window.location.href = 'shopAll.php';
    }, 2000);
    return;
  }
  
  // Set order number
  const orderNumberEl = document.getElementById('order-number');
  if (orderNumberEl) {
    orderNumberEl.textContent = orderData.orderNumber || '#UXP-2024-001234';
  }
  
  // Set order date
  const orderDateEl = document.getElementById('order-date');
  if (orderDateEl) {
    const orderDate = orderData.date ? new Date(orderData.date) : new Date();
    orderDateEl.textContent = orderDate.toLocaleDateString('en-US', { 
      year: 'numeric', 
      month: 'long', 
      day: 'numeric' 
    });
  }
  
  // Set order total
  const orderTotalEl = document.getElementById('order-total');
  if (orderTotalEl) {
    orderTotalEl.textContent = `$${orderData.total || 0}`;
  }
  
  // Set payment method
  const paymentMethodEl = document.getElementById('payment-method');
  if (paymentMethodEl) {
    const paymentMethods = {
      'card': 'Credit/Debit Card',
      'upi': 'UPI',
      'cod': 'Cash on Delivery'
    };
    paymentMethodEl.textContent = paymentMethods[orderData.paymentMethod] || 'Credit Card';
  }
  
  // Load order items from orderData.items (not cart, since cart is cleared)
  const itemsList = document.getElementById('confirmation-items-list');
  if (itemsList && orderData.items && orderData.items.length > 0) {
    itemsList.innerHTML = orderData.items.map(item => `
      <div class="confirmation-item">
        <img src="${item.image}" alt="${item.name}" class="item-image" />
        <div class="item-info">
          <h4>${item.name}</h4>
          <p>${item.size ? `Size: ${item.size} • ` : ''}Quantity: ${item.quantity}</p>
        </div>
        <div class="item-price">$${item.price * item.quantity}</div>
      </div>
    `).join('');
  } else if (itemsList) {
    itemsList.innerHTML = '<p class="empty-message">No items found in this order.</p>';
  }
  
  // Load shipping address
  const shippingDiv = document.getElementById('shipping-address');
  if (shippingDiv && orderData.shipping) {
    shippingDiv.innerHTML = `
      <p><strong>${orderData.shipping.firstName || ''} ${orderData.shipping.lastName || ''}</strong></p>
      <p>${orderData.shipping.address || ''}</p>
      <p>${orderData.shipping.city || ''}, ${orderData.shipping.state || ''} ${orderData.shipping.zip || ''}</p>
      <p>${orderData.shipping.country || 'India'}</p>
      ${orderData.shipping.phone ? `<p>Phone: ${orderData.shipping.phone}</p>` : ''}
      ${orderData.shipping.email ? `<p>Email: ${orderData.shipping.email}</p>` : ''}
    `;
  } else if (shippingDiv) {
    shippingDiv.innerHTML = '<p class="empty-message">Shipping address not available.</p>';
  }
}

// Sign up handler with enhanced validation
// function handleSignUp(event) {
//   event.preventDefault();
  
//   const form = event.target;
  
//   // Support both old format (firstName/lastName) and new format (fullName)
//   let firstName, lastName;
//   if (form.fullName) {
//     // New format: fullName
//     const fullName = form.fullName.value.trim();
//     if (!fullName || fullName.length < 2) {
//       const errorSpan = form.fullName.parentElement.querySelector('.field-error-modern') || 
//                        form.fullName.parentElement.querySelector('.field-error');
//       if (errorSpan) {
//         errorSpan.textContent = 'Full name must be at least 2 characters';
//         errorSpan.style.display = 'block';
//       }
//       form.fullName.style.borderColor = '#ef4444';
//       return;
//     }
//     const names = fullName.split(' ');
//     firstName = names[0] || '';
//     lastName = names.slice(1).join(' ') || '';
//   } else {
//     // Old format: firstName/lastName
//     firstName = form.firstName?.value.trim() || '';
//     lastName = form.lastName?.value.trim() || '';
//   }
  
//   const email = form.email.value.trim();
//   const phone = form.phone?.value.trim() || ''; // Phone is optional in new design
//   const password = form.password.value;
//   const confirmPassword = form.confirmPassword.value;
//   const terms = form.terms.checked;
  
//   const btn = document.getElementById('signup-btn');
//   const btnText = document.getElementById('signup-text');
//   const btnLoader = document.getElementById('signup-loader');
//   const errorDiv = document.getElementById('auth-error');
//   const successDiv = document.getElementById('auth-success');
  
//   // Clear previous errors
//   if (errorDiv) errorDiv.style.display = 'none';
//   if (successDiv) successDiv.style.display = 'none';
  
//   // Validation
//   let isValid = true;
  
//   // Validate name (either fullName or firstName/lastName)
//   if (form.fullName) {
//     const fullName = form.fullName.value.trim();
//     if (!fullName || fullName.length < 2) {
//       const errorSpan = form.fullName.parentElement.querySelector('.field-error-modern') || 
//                        form.fullName.parentElement.querySelector('.field-error');
//       if (errorSpan) {
//         errorSpan.textContent = 'Full name must be at least 2 characters';
//         errorSpan.style.display = 'block';
//       }
//       form.fullName.style.borderColor = '#ef4444';
//       isValid = false;
//     } else {
//       const errorSpan = form.fullName.parentElement.querySelector('.field-error-modern') || 
//                        form.fullName.parentElement.querySelector('.field-error');
//       if (errorSpan) errorSpan.style.display = 'none';
//       form.fullName.style.borderColor = '';
//     }
//   } else {
//     if (!firstName || firstName.length < 2) {
//       if (form.firstName) showFieldError(form.firstName, 'First name must be at least 2 characters');
//       isValid = false;
//     } else {
//       if (form.firstName) clearFieldError(form.firstName);
//     }
    
//     if (!lastName || lastName.length < 2) {
//       if (form.lastName) showFieldError(form.lastName, 'Last name must be at least 2 characters');
//       isValid = false;
//     } else {
//       if (form.lastName) clearFieldError(form.lastName);
//     }
//   }
  
//   if (!email) {
//     showFieldError(form.email, 'Email is required');
//     isValid = false;
//   } else if (!validateEmail(email)) {
//     showFieldError(form.email, 'Please enter a valid email address');
//     isValid = false;
//   } else {
//     clearFieldError(form.email);
//   }
  
//   // Phone validation (optional in new design)
//   if (form.phone) {
//     if (phone && !validatePhone(phone)) {
//       showFieldError(form.phone, 'Please enter a valid phone number');
//       isValid = false;
//     } else if (form.phone) {
//       clearFieldError(form.phone);
//     }
//   }
  
//   if (!password) {
//     const errorSpan = form.password.parentElement?.querySelector('.field-error-modern') || 
//                      form.password.parentElement?.querySelector('.field-error');
//     if (errorSpan) {
//       errorSpan.textContent = 'Password is required';
//       errorSpan.style.display = 'block';
//     }
//     form.password.style.borderColor = '#ef4444';
//     isValid = false;
//   } else if (password.length < 6) {
//     const errorSpan = form.password.parentElement?.querySelector('.field-error-modern') || 
//                      form.password.parentElement?.querySelector('.field-error');
//     if (errorSpan) {
//       errorSpan.textContent = 'Password must be at least 6 characters';
//       errorSpan.style.display = 'block';
//     }
//     form.password.style.borderColor = '#ef4444';
//     isValid = false;
//   } else if (!validatePassword(password)) {
//     const errorSpan = form.password.parentElement?.querySelector('.field-error-modern') || 
//                      form.password.parentElement?.querySelector('.field-error');
//     if (errorSpan) {
//       errorSpan.textContent = 'Password must contain uppercase, lowercase, and number';
//       errorSpan.style.display = 'block';
//     }
//     form.password.style.borderColor = '#ef4444';
//     isValid = false;
//   } else {
//     const errorSpan = form.password.parentElement?.querySelector('.field-error-modern') || 
//                      form.password.parentElement?.querySelector('.field-error');
//     if (errorSpan) errorSpan.style.display = 'none';
//     form.password.style.borderColor = '';
//   }
  
//   if (!confirmPassword) {
//     const errorSpan = form.confirmPassword.parentElement?.querySelector('.field-error-modern') || 
//                      form.confirmPassword.parentElement?.querySelector('.field-error');
//     if (errorSpan) {
//       errorSpan.textContent = 'Please confirm your password';
//       errorSpan.style.display = 'block';
//     }
//     form.confirmPassword.style.borderColor = '#ef4444';
//     isValid = false;
//   } else if (password !== confirmPassword) {
//     const errorSpan = form.confirmPassword.parentElement?.querySelector('.field-error-modern') || 
//                      form.confirmPassword.parentElement?.querySelector('.field-error');
//     if (errorSpan) {
//       errorSpan.textContent = 'Passwords do not match';
//       errorSpan.style.display = 'block';
//     }
//     form.confirmPassword.style.borderColor = '#ef4444';
//     isValid = false;
//   } else {
//     const errorSpan = form.confirmPassword.parentElement?.querySelector('.field-error-modern') || 
//                      form.confirmPassword.parentElement?.querySelector('.field-error');
//     if (errorSpan) errorSpan.style.display = 'none';
//     form.confirmPassword.style.borderColor = '';
//   }
  
//   if (!terms) {
//     if (errorDiv) {
//       errorDiv.textContent = 'Please agree to the Terms & Conditions';
//       errorDiv.style.display = 'block';
//     }
//     isValid = false;
//   }
  
//   if (!isValid) {
//     return;
//   }
  
//   // Show loading
//   if (btn) {
//     btn.disabled = true;
//     if (btnText) btnText.style.display = 'none';
//     if (btnLoader) btnLoader.style.display = 'inline';
//   }
  
//   // Call actual API
//   fetch('api/auth/signup.php', {
//     method: 'POST',
//     headers: {
//       'Content-Type': 'application/json'
//     },
//     body: JSON.stringify({
//       firstName: firstName,
//       lastName: lastName,
//       fullName: form.fullName ? form.fullName.value.trim() : null,
//       email: email,
//       phone: phone,
//       password: password
//     })
//   })
//   .then(response => response.json())
//   .then(data => {
//     if (data.status === 'success') {
//       const user = data.user;
      
//       const userData = {
//         email: user.email,
//         firstName: user.firstName,
//         lastName: user.lastName,
//         name: `${user.firstName} ${user.lastName}`.trim(),
//         phone: phone || '',
//         loginTime: new Date().toISOString()
//       };
      
//       // Store Session
//       setUserSession(userData);
      
//       // Tokens removed as per request
//       // localStorage.setItem('accessToken', tokens.access_token);
//       // localStorage.setItem('refreshToken', tokens.refresh_token);
      
//       if (successDiv) {
//         successDiv.textContent = 'Account created successfully! Redirecting...';
//         successDiv.style.display = 'block';
//       }
//       setTimeout(() => {
//         window.location.href = 'index.php';
//       }, 1500);
//     } else {
//       if (errorDiv) {
//         errorDiv.textContent = data.message || 'Registration failed';
//         errorDiv.style.display = 'block';
//       }
//       if (btn) {
//         btn.disabled = false;
//         if (btnText) btnText.style.display = 'inline';
//         if (btnLoader) btnLoader.style.display = 'none';
//       }
//     }
//   })
//   .catch(error => {
//     console.error('Signup error:', error);
//     if (errorDiv) {
//       errorDiv.textContent = 'An error occurred. Please try again.';
//       errorDiv.style.display = 'block';
//     }
//     if (btn) {
//       btn.disabled = false;
//       if (btnText) btnText.style.display = 'inline';
//       if (btnLoader) btnLoader.style.display = 'none';
//     }
//   });
// }

async function handleSignUp(event) {
  event.preventDefault();

  // --- UI Elements ---
  const form = event.target;
  const errorBox = document.getElementById("auth-error");
  const successBox = document.getElementById("auth-success");
  const btn = document.getElementById("signup-btn");
  const loader = document.getElementById("signup-loader");
  const text = document.getElementById("signup-text");

  errorBox.style.display = "none";
  successBox.style.display = "none";

  // --- Collect data ---
  const fullName = form.fullName.value.trim();
  const names = fullName.split(" ");

  const payload = {
    firstName: names[0],
    lastName: names.slice(1).join(" "),
    email: form.email.value.trim(),
    phone: form.phone.value.trim(),
    password: form.password.value
  };

  // --- Loading state ---
  btn.disabled = true;
  loader.style.display = "inline";
  text.style.display = "none";

  try {
    // 🔥 FETCH + JSON
    const response = await fetch("api/auth/signup.php", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.message || "Signup failed");
    }

    successBox.textContent = data.message;
    successBox.style.display = "block";

    form.reset();

    // Optional redirect
    // setTimeout(() => window.location.href = "signin.php", 1500);

  } catch (err) {
    errorBox.textContent = err.message;
    errorBox.style.display = "block";
  } finally {
    btn.disabled = false;
    loader.style.display = "none";
    text.style.display = "inline";
  }
}


// Forgot password handler - Step 1: Send reset link
function handleForgotPassword(event) {
  event.preventDefault();
  
  const form = event.target;
  const email = form.email.value;
  const btn = document.getElementById('reset-btn');
  const btnText = document.getElementById('reset-text');
  const btnLoader = document.getElementById('reset-loader');
  const errorDiv = document.getElementById('auth-error');
  const successDiv = document.getElementById('auth-success');
  
  // Show loading
  btn.disabled = true;
  btnText.style.display = 'none';
  btnLoader.style.display = 'inline';
  errorDiv.style.display = 'none';
  successDiv.style.display = 'none';
  
  // TODO: Replace with actual API call
  setTimeout(() => {
    successDiv.textContent = 'Reset link sent to your email! Please check your inbox.';
    successDiv.style.display = 'block';
    
    // Show verification code form
    form.style.display = 'none';
    document.getElementById('verify-code-form').style.display = 'block';
    
    btn.disabled = false;
    btnText.style.display = 'inline';
    btnLoader.style.display = 'none';
  }, 1500);
}

// Forgot password handler - Step 2: Verify code
function handleVerifyCode(event) {
  event.preventDefault();
  
  const form = event.target;
  const code = form.code.value;
  const btn = document.getElementById('verify-btn');
  const btnText = document.getElementById('verify-text');
  const btnLoader = document.getElementById('verify-loader');
  const errorDiv = document.getElementById('verify-error');
  
  // Show loading
  btn.disabled = true;
  btnText.style.display = 'none';
  btnLoader.style.display = 'inline';
  errorDiv.style.display = 'none';
  
  // TODO: Replace with actual API call
  setTimeout(() => {
    if (code.length === 6) {
      // Show new password form
      form.style.display = 'none';
      document.getElementById('new-password-form').style.display = 'block';
      
      btn.disabled = false;
      btnText.style.display = 'inline';
      btnLoader.style.display = 'none';
    } else {
      errorDiv.textContent = 'Invalid verification code';
      errorDiv.style.display = 'block';
      btn.disabled = false;
      btnText.style.display = 'inline';
      btnLoader.style.display = 'none';
    }
  }, 1000);
}

// Forgot password handler - Step 3: Set new password
function handleNewPassword(event) {
  event.preventDefault();
  
  const form = event.target;
  const newPassword = form.newPassword.value;
  const confirmNewPassword = form.confirmNewPassword.value;
  const btn = document.getElementById('save-password-btn');
  const btnText = document.getElementById('save-text');
  const btnLoader = document.getElementById('save-loader');
  const errorDiv = document.getElementById('password-error');
  
  // Validation
  if (newPassword !== confirmNewPassword) {
    errorDiv.textContent = 'Passwords do not match';
    errorDiv.style.display = 'block';
    return;
  }
  
  if (newPassword.length < 8) {
    errorDiv.textContent = 'Password must be at least 8 characters';
    errorDiv.style.display = 'block';
    return;
  }
  
  // Show loading
  btn.disabled = true;
  btnText.style.display = 'none';
  btnLoader.style.display = 'inline';
  errorDiv.style.display = 'none';
  
  // TODO: Replace with actual API call
  setTimeout(() => {
    // Show success message
    form.style.display = 'none';
    document.getElementById('reset-success').style.display = 'block';
  }, 1500);
}

// Resend verification code
function resendCode() {
  showToast('Verification code resent to your email!', 'success');
  // TODO: Implement resend code API call
}

// Social sign in
function signInWithGoogle() {
  showToast('Google sign in coming soon!', 'success');
  // TODO: Implement Google OAuth
}

// Social sign up
function signUpWithGoogle() {
  showToast('Google sign up coming soon!', 'success');
  // TODO: Implement Google OAuth
}

// Make functions globally available
window.addToCart = addToCart;
window.removeFromCart = removeFromCart;
window.updateCartQuantity = updateCartQuantity;
window.handleSignIn = handleSignIn;
window.handleSignUp = handleSignUp;
window.handleForgotPassword = handleForgotPassword;
window.handleVerifyCode = handleVerifyCode;
window.handleNewPassword = handleNewPassword;
window.resendCode = resendCode;
window.handleContactSubmit = handleContactSubmit;
window.handleCheckout = handleCheckout;

// ==================== WISHLIST FUNCTIONALITY ====================

// Add to wishlist
function addToWishlist(productId, productName, productPrice, productImage, productCategory, productDescription, productRating) {
  let wishlist = JSON.parse(localStorage.getItem('wishlist')) || [];
  
  // Check if already in wishlist
  if (wishlist.find(item => item.id === productId)) {
    showToast('Already in wishlist', 'info');
    return;
  }
  
  wishlist.push({
    id: productId,
    name: productName,
    price: productPrice,
    image: productImage,
    category: productCategory,
    description: productDescription,
    rating: productRating || 4.5
  });
  
  localStorage.setItem('wishlist', JSON.stringify(wishlist));
  updateWishlistCount();
  showToast('Added to wishlist', 'success');
}

// Remove from wishlist
function removeFromWishlist(productId) {
  let wishlist = JSON.parse(localStorage.getItem('wishlist')) || [];
  wishlist = wishlist.filter(item => item.id !== productId);
  localStorage.setItem('wishlist', JSON.stringify(wishlist));
  updateWishlistCount();
  showToast('Removed from wishlist', 'success');
}

// Check if product is in wishlist
function isInWishlist(productId) {
  const wishlist = JSON.parse(localStorage.getItem('wishlist')) || [];
  return wishlist.find(item => item.id === productId) !== undefined;
}

// Update wishlist count in header
function updateWishlistCount() {
  const wishlist = JSON.parse(localStorage.getItem('wishlist')) || [];
  const wishlistCount = document.getElementById('wishlist-count');
  if (wishlistCount) {
    wishlistCount.textContent = wishlist.length;
    wishlistCount.style.display = wishlist.length > 0 ? 'flex' : 'none';
  }
}

// Initialize wishlist count on page load
if (typeof document !== 'undefined') {
  document.addEventListener('DOMContentLoaded', function() {
    updateWishlistCount();
  });
}

// Export functions
window.addToWishlist = addToWishlist;
window.removeFromWishlist = removeFromWishlist;
window.isInWishlist = isInWishlist;
window.updateWishlistCount = updateWishlistCount;

// Header search functionality
function performHeaderSearch() {
  const query = document.getElementById('header-search-input')?.value.trim();
  if (query) {
    window.location.href = `search.php?q=${encodeURIComponent(query)}`;
  }
}

// Search on Enter key
if (typeof document !== 'undefined') {
  document.addEventListener('DOMContentLoaded', function() {
    const searchInput = document.getElementById('header-search-input');
    if (searchInput) {
      searchInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
          performHeaderSearch();
        }
      });
    }
  });
}

window.performHeaderSearch = performHeaderSearch;

// Buy Now function - adds to cart and redirects to checkout
function buyNow(productId, size, quantity) {
  // Check if user is signed in
  const userSession = getUserSession();
  if (!userSession) {
    // Add to cart first
    addToCart(productId, size, quantity);
    showToast('Please sign in to complete your purchase', 'error');
    // Redirect to sign in with redirect to checkout
    setTimeout(() => {
      window.location.href = 'signin.php?redirect=checkout.php';
    }, 1500);
    return;
  }
  
  // Add to cart first
  addToCart(productId, size, quantity);
  
  // Redirect to checkout after a short delay
  setTimeout(() => {
    window.location.href = 'checkout.php';
  }, 500);
}

// Check authentication before proceeding to checkout
function checkAuthBeforeCheckout(event) {
  const userSession = getUserSession();
  if (!userSession) {
    event.preventDefault();
    showToast('Please sign in to proceed to checkout', 'error');
    setTimeout(() => {
      window.location.href = 'signin.php?redirect=checkout.php';
    }, 1500);
    return false;
  }
  return true;
}

// Handle redirect after sign in
function handleSignInRedirect() {
  const urlParams = new URLSearchParams(window.location.search);
  const redirect = urlParams.get('redirect');
  if (redirect) {
    setTimeout(() => {
      window.location.href = redirect;
    }, 1500);
  } else {
    setTimeout(() => {
      window.location.href = 'index.php';
    }, 1500);
  }
}

window.buyNow = buyNow;
window.handleSignOut = handleSignOut;
window.signInWithGoogle = signInWithGoogle;
window.signUpWithGoogle = signUpWithGoogle;
window.checkAuthBeforeCheckout = checkAuthBeforeCheckout;
window.loadOrderConfirmationPage = loadOrderConfirmationPage;




