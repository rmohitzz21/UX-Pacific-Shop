<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <title>Forgot Password – UX Pacific Shop</title>
    <meta name="viewport" content="width=device-width, initial-scale=1" />
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
          <a href="signin.php" class="nav-mobile-link nav-mobile-cta">
            Sign in
          </a>
        </div>
      </header>

      <!-- MAIN CONTENT -->
      <main class="main">
        <section class="auth-section">
          <div class="auth-container">
            <div class="auth-card">
              <h1 class="auth-title">Reset Password</h1>
              <p class="auth-subtitle">
                Enter your email address and we'll send you a link to reset your password.
              </p>

              <!-- Step 1: Email Input -->
              <form class="auth-form" id="forgot-password-form" onsubmit="handleForgotPassword(event)" style="display: block;">
                <div id="auth-error" class="error-message" style="display: none;"></div>
                <div id="auth-success" class="success-message" style="display: none;"></div>

                <div class="form-field">
                  <label for="email">Email Address *</label>
                  <input
                    id="email"
                    name="email"
                    type="email"
                    placeholder="Enter your email"
                    required
                    autocomplete="email"
                    pattern="[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$"
                  />
                  <span class="field-error"></span>
                </div>

                <button type="submit" class="btn-primary auth-submit" id="reset-btn">
                  <span id="reset-text">Send Reset Link</span>
                  <span id="reset-loader" style="display:none;">Sending...</span>
                </button>
              </form>

              <!-- Step 2: Code Verification (hidden initially) -->
              <form class="auth-form" id="verify-code-form" onsubmit="handleVerifyCode(event)" style="display: none;">
                <div id="verify-error" class="error-message" style="display: none;"></div>
                
                <p class="auth-subtitle" style="text-align: left; margin-bottom: 20px;">
                  We've sent a verification code to your email. Please enter it below.
                </p>

                <div class="form-field">
                  <label for="verification-code">Verification Code *</label>
                  <input
                    id="verification-code"
                    name="code"
                    type="text"
                    placeholder="Enter 6-digit code"
                    required
                    maxlength="6"
                    pattern="[0-9]{6}"
                  />
                  <span class="field-error"></span>
                </div>

                <div class="form-options">
                  <a href="#" onclick="resendCode(); return false;" class="forgot-link">Resend Code</a>
                </div>

                <button type="submit" class="btn-primary auth-submit" id="verify-btn">
                  <span id="verify-text">Verify Code</span>
                  <span id="verify-loader" style="display:none;">Verifying...</span>
                </button>
              </form>

              <!-- Step 3: New Password (hidden initially) -->
              <form class="auth-form" id="new-password-form" onsubmit="handleNewPassword(event)" style="display: none;">
                <div id="password-error" class="error-message" style="display: none;"></div>
                
                <p class="auth-subtitle" style="text-align: left; margin-bottom: 20px;">
                  Create a new password for your account.
                </p>

                <div class="form-field">
                  <label for="new-password">New Password *</label>
                  <input
                    id="new-password"
                    name="newPassword"
                    type="password"
                    placeholder="Enter new password"
                    required
                    minlength="8"
                    autocomplete="new-password"
                  />
                  <span class="field-hint">Must be at least 8 characters</span>
                  <span class="field-error"></span>
                </div>

                <div class="form-field">
                  <label for="confirm-new-password">Confirm New Password *</label>
                  <input
                    id="confirm-new-password"
                    name="confirmNewPassword"
                    type="password"
                    placeholder="Confirm new password"
                    required
                    minlength="8"
                    autocomplete="new-password"
                  />
                  <span class="field-error"></span>
                </div>

                <button type="submit" class="btn-primary auth-submit" id="save-password-btn">
                  <span id="save-text">Save New Password</span>
                  <span id="save-loader" style="display:none;">Saving...</span>
                </button>
              </form>

              <!-- Success Message (hidden initially) -->
              <div id="reset-success" style="display: none;">
                <div class="success-message" style="margin-bottom: 24px;">
                  <strong>Password reset successful!</strong><br />
                  You can now sign in with your new password.
                </div>
                <a href="signin.php" class="btn-primary" style="width: 100%; text-align: center; display: block;">
                  Go to Sign In
                </a>
              </div>

              <div class="auth-divider" style="margin-top: 24px;"></div>

              <p class="auth-footer">
                Remember your password?
                <a href="signin.php" class="auth-link">Sign In</a>
              </p>
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
  </body>
</html>


