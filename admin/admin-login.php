<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <title>Admin Login – UX Pacific Shop</title>
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <link
      href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap"
      rel="stylesheet"
    />
    <link rel="stylesheet" href="../style.css" />
    <style>
      .admin-login-container {
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 2rem;
      }
      .admin-login-card {
        background: #01010d;
        border-radius: 16px;
        padding: 3rem;
        max-width: 450px;
        width: 100%;
        box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
      }
      .admin-login-title {
        font-size: 2rem;
        font-weight: 700;
        margin-bottom: 0.5rem;
        color: #fff;
      }
      .admin-login-subtitle {
        color: #666;
        margin-bottom: 2rem;
      }
      .admin-warning {
        background: #fff3cd;
        border: 1px solid #ffc107;
        color: #856404;
        padding: 1rem;
        border-radius: 8px;
        margin-bottom: 1.5rem;
        font-size: 0.9rem;
      }
    </style>
  </head>

  <body>
    <div class="admin-login-container">
      <div class="admin-login-card">
        <h1 class="admin-login-title">Admin Login</h1>
        <p class="admin-login-subtitle">Access the admin dashboard</p>
        
        <div class="admin-warning">
          ⚠️ This is a restricted area. Only authorized administrators can access.
        </div>

        <form class="auth-form" id="admin-login-form" onsubmit="handleAdminLogin(event)">
          <div id="admin-error" class="error-message" style="display: none;"></div>
          <div id="admin-success" class="success-message" style="display: none;"></div>

          <div class="form-field">
            <label for="admin-email">Admin Email *</label>
            <input
              id="admin-email"
              name="email"
              type="email"
              placeholder="admin@uxpacific.com"
              required
              autocomplete="email"
            />
            <span class="field-error"></span>
          </div>

          <div class="form-field">
            <label for="admin-password">Password *</label>
            <input
              id="admin-password"
              name="password"
              type="password"
              placeholder="Enter admin password"
              required
              minlength="6"
              autocomplete="current-password"
            />
            <span class="field-error"></span>
          </div>

          <button type="submit" class="btn-primary auth-submit" id="admin-login-btn" style="width: 100%;">
            <span id="admin-login-text">Sign In as Admin</span>
            <span id="admin-login-loader" style="display:none;">Signing in...</span>
          </button>
        </form>

        <div style="margin-top: 2rem; text-align: center;">
          <a href="../index.php" class="auth-link">← Back to Shop</a>
        </div>
      </div>
    </div>

    <script src="../script.js"></script>
    <script>
      // Admin login handler
      function handleAdminLogin(event) {
        event.preventDefault();
        
        const form = event.target;
        const email = form.email.value.trim();
        const password = form.password.value;
        const btn = document.getElementById('admin-login-btn');
        const btnText = document.getElementById('admin-login-text');
        const btnLoader = document.getElementById('admin-login-loader');
        const errorDiv = document.getElementById('admin-error');
        const successDiv = document.getElementById('admin-success');
        
        // Clear previous messages
        errorDiv.style.display = 'none';
        successDiv.style.display = 'none';
        
        // Basic validation
        if (!email || !password) {
          errorDiv.textContent = 'Please fill in all fields';
          errorDiv.style.display = 'block';
          return;
        }
        
        // Show loading
        btn.disabled = true;
        btnText.style.display = 'none';
        btnLoader.style.display = 'inline';
        
        // Admin credentials (in production, this should be handled by backend)
        // Default admin: admin@uxpacific.com / admin123
        const adminCredentials = {
          email: 'Hello@uxpacific.com',
          password: 'admin123'
        };
        
        // Simulate API call
        setTimeout(() => {
          if (email === adminCredentials.email && password === adminCredentials.password) {
            // Create admin session
            const adminSession = {
              email: email,
              role: 'admin',
              loginTime: new Date().toISOString(),
              isAdmin: true
            };
            localStorage.setItem('adminSession', JSON.stringify(adminSession));
            
            successDiv.textContent = 'Login successful! Redirecting...';
            successDiv.style.display = 'block';
            
            setTimeout(() => {
              window.location.href = 'admin-dashboard.php';
            }, 1000);
          } else {
            errorDiv.textContent = 'Invalid admin credentials. Access denied.';
            errorDiv.style.display = 'block';
            btn.disabled = false;
            btnText.style.display = 'inline';
            btnLoader.style.display = 'none';
          }
        }, 1000);
      }
      
      window.handleAdminLogin = handleAdminLogin;
      
      // Check if already logged in as admin
      document.addEventListener('DOMContentLoaded', function() {
        const adminSession = JSON.parse(localStorage.getItem('adminSession'));
        if (adminSession && adminSession.isAdmin) {
          window.location.href = 'admin-dashboard.php';
        }
      });
    </script>
  </body>
</html>


