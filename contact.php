<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <!-- <meta name="viewport" content="width=device-width, initial-scale=1.0"> -->
    <title>UX Pacific – Merchandise</title>
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <!-- Google Font -->
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
              <li><a href="#category" class="nav-link">New</a></li>
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
            <a href="#story" class="nav-mobile-link">About Us</a>
            <a href="#category" class="nav-mobile-link">New</a>
            <a href="shopAll.php" class="nav-mobile-link">Buy Now</a>
            <a href="signin.php" class="nav-mobile-link nav-mobile-cta">
              Sign in
            </a>
          </div>
        </header>
      </div>

      <!-- CONTACT SECTION -->
      <main id="home" class="main">
        <section id="contact" class="contact-section">
          <h2 class="section-title contact-title">Contact Us</h2>  
          <p class="section-subtitle contact-subtitle">
            Have a question or want to learn more about UX Pacific Community?
            We’d love to hear from you. Send us a message and we’ll respond as
            soon as possible.
          </p>

          <div class="contact-grid">
            <!-- LEFT: Image card -->
            <div class="contact-image">
              <img src="img/ct.webp" alt="Contact screen mockup" />
            </div>

            <!-- RIGHT: Form (no card background) -->
            <form class="contact-form" id="contact-form" onsubmit="handleContactSubmit(event)">
              <div class="contact-row">
                <div class="contact-field">
                  <label for="name">Name</label>
                  <input
                    id="name"
                    name="name"
                    type="text"
                    placeholder="Enter your name here"
                    required
                    minlength="2"
                    maxlength="50"
                  />
                </div>
                <div class="contact-field">
                  <label for="email">Email</label>
                  <input
                    id="email"
                    name="email"
                    type="email"
                    placeholder="Enter your email address"
                    required
                    pattern="[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$"
                  />
                </div>
              </div>

              <div class="contact-row">
                <div class="contact-field">
                  <label for="phone">Phone Number</label>
                  <input
                    id="phone"
                    name="phone"
                    type="tel"
                    placeholder="+91 xxxxx- xxxxx"
                    required
                    pattern="[\d\s\-\+\(\)]+"
                  />
                </div>
                <div class="contact-field">
                  <label for="subject">Subject</label>
                  <input
                    id="subject"
                    name="subject"
                    type="text"
                    placeholder="Write your Subject"
                  />
                </div>
              </div>

              <div class="contact-field">
                <label for="message">Message</label>
                <textarea
                  id="message"
                  name="message"
                  rows="5"
                  placeholder="Enter your message here...."
                  required
                  minlength="10"
                  maxlength="1000"
                ></textarea>
              </div>

              <div class="contact-footer">
                <label class="contact-checkbox">
                  <input type="checkbox" />
                  <span>
                    I Agree to
                    <a href="policies.php#terms" class="contact-link">Terms &amp; Condition</a>
                    of UXPacific
                  </span>
                </label>
              </div>

              <button type="submit" class="btn-primary contact-submit">
                Submit
              </button>
            </form>
          </div>
        </section>

        <!-- CTA / READY SECTION -->
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
                >Shop All Products</a
              >
              <!-- <a href="#contact" class="btn-ghost">Join Our Community</a> -->
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
      </footer>
    </div>
    <script src="script.js"></script>
  </body>
</html>

