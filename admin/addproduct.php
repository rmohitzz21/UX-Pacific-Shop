<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8" />
  <title>Add Product – UX Pacific Shop</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap"
    rel="stylesheet" />
  <link rel="stylesheet" href="../style.css" />
  <style>
    /* ==================== ADD PRODUCT PAGE STYLES ==================== */

    :root {
      --admin-bg-light: #f5f7fa;
      --admin-bg-dark: #0f172a;
      --admin-card-light: #ffffff;
      --admin-card-dark: #1e293b;
      --admin-text-light: #1a1a1a;
      --admin-text-dark: #f1f5f9;
      --admin-border-light: #e5e7eb;
      --admin-border-dark: #334155;
      --admin-accent: #667eea;
    }

    [data-theme="dark"] {
      --admin-bg: var(--admin-bg-dark);
      --admin-card: var(--admin-card-dark);
      --admin-text: var(--admin-text-dark);
      --admin-border: var(--admin-border-dark);
    }

    [data-theme="light"] {
      --admin-bg: var(--admin-bg-light);
      --admin-card: var(--admin-card-light);
      --admin-text: var(--admin-text-light);
      --admin-border: var(--admin-border-light);
    }

    body {
      margin: 0;
      padding: 0;
      font-family: 'Inter', sans-serif;
      background: var(--admin-bg);
      color: var(--admin-text);
      transition: background 0.3s ease, color 0.3s ease;
    }

    .add-product-container {
      min-height: 100vh;
      padding: 2rem;
      max-width: 1200px;
      margin: 0 auto;
    }

    .page-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 2rem;
      flex-wrap: wrap;
      gap: 1rem;
    }

    .page-header h1 {
      font-size: 2rem;
      font-weight: 700;
      color: var(--admin-text);
      margin: 0;
    }

    .back-button {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.75rem 1.5rem;
      background: var(--admin-card);
      border: 1px solid var(--admin-border);
      border-radius: 8px;
      color: var(--admin-text);
      text-decoration: none;
      font-weight: 500;
      transition: all 0.2s;
    }

    .back-button:hover {
      background: var(--admin-bg);
      border-color: var(--admin-accent);
    }

    .back-button svg {
      width: 18px;
      height: 18px;
    }

    .form-card {
      background: var(--admin-card);
      border-radius: 12px;
      padding: 2rem;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
      border: 1px solid var(--admin-border);
    }

    .form-section {
      margin-bottom: 2rem;
    }

    .form-section-title {
      font-size: 1.25rem;
      font-weight: 600;
      color: var(--admin-text);
      margin-bottom: 1.5rem;
      padding-bottom: 0.75rem;
      border-bottom: 2px solid var(--admin-border);
    }

    .form-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
      gap: 1.5rem;
    }

    .form-group {
      display: flex;
      flex-direction: column;
    }

    .form-group.full-width {
      grid-column: 1 / -1;
    }

    .form-label {
      font-size: 0.875rem;
      font-weight: 600;
      color: var(--admin-text);
      margin-bottom: 0.5rem;
    }

    .form-label .required {
      color: #ef4444;
      margin-left: 0.25rem;
    }

    .form-input,
    .form-select,
    .form-textarea {
      padding: 0.75rem;
      border: 1px solid var(--admin-border);
      border-radius: 8px;
      font-size: 0.875rem;
      background: var(--admin-bg);
      color: var(--admin-text);
      font-family: 'Inter', sans-serif;
      transition: all 0.2s;
    }

    .form-input:focus,
    .form-select:focus,
    .form-textarea:focus {
      outline: none;
      border-color: var(--admin-accent);
      box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
    }

    .form-textarea {
      min-height: 120px;
      resize: vertical;
    }

    .form-input[type="file"] {
      padding: 0.5rem;
      cursor: pointer;
    }

    .file-upload-area {
      border: 2px dashed var(--admin-border);
      border-radius: 8px;
      padding: 2rem;
      text-align: center;
      background: var(--admin-bg);
      transition: all 0.2s;
      cursor: pointer;
    }

    .file-upload-area:hover {
      border-color: var(--admin-accent);
      background: rgba(102, 126, 234, 0.05);
    }

    .file-upload-area.dragover {
      border-color: var(--admin-accent);
      background: rgba(102, 126, 234, 0.1);
    }

    .file-upload-icon {
      width: 48px;
      height: 48px;
      margin: 0 auto 1rem;
      color: var(--admin-text);
      opacity: 0.5;
    }

    .file-upload-text {
      color: var(--admin-text);
      font-size: 0.875rem;
      margin-bottom: 0.5rem;
    }

    .file-upload-hint {
      color: var(--admin-text);
      opacity: 0.6;
      font-size: 0.75rem;
    }

    .file-preview {
      margin-top: 1rem;
      display: none;
    }

    .file-preview img {
      max-width: 200px;
      max-height: 200px;
      border-radius: 8px;
      border: 1px solid var(--admin-border);
    }

    .form-actions {
      display: flex;
      gap: 1rem;
      justify-content: flex-end;
      margin-top: 2rem;
      padding-top: 2rem;
      border-top: 1px solid var(--admin-border);
      flex-wrap: wrap;
    }

    .btn-secondary {
      padding: 0.75rem 1.5rem;
      background: var(--admin-bg);
      border: 1px solid var(--admin-border);
      border-radius: 8px;
      color: var(--admin-text);
      font-weight: 500;
      cursor: pointer;
      transition: all 0.2s;
      text-decoration: none;
      display: inline-block;
    }

    .btn-secondary:hover {
      background: var(--admin-card);
      border-color: var(--admin-accent);
    }

    .form-help-text {
      font-size: 0.75rem;
      color: var(--admin-text);
      opacity: 0.6;
      margin-top: 0.5rem;
    }

    .checkbox-group {
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .checkbox-group input[type="checkbox"] {
      width: 18px;
      height: 18px;
      cursor: pointer;
    }

    .checkbox-group label {
      cursor: pointer;
      margin: 0;
    }

    /* Mobile Responsive */
    @media (max-width: 768px) {
      .add-product-container {
        padding: 1rem;
      }

      .page-header h1 {
        font-size: 1.5rem;
      }

      .form-card {
        padding: 1.5rem;
      }

      .form-grid {
        grid-template-columns: 1fr;
      }

      .form-actions {
        flex-direction: column-reverse;
      }

      .form-actions button,
      .form-actions a {
        width: 100%;
      }
    }
  </style>
</head>

<body data-theme="light">
  <div class="add-product-container">
    <!-- Page Header -->
    <div class="page-header">
      <h1>Add New Product</h1>
      <a href="admin-dashboard.php" class="back-button">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Back to Dashboard
      </a>
    </div>

    <!-- Form Card -->
    <div class="form-card">
      <form id="add-product-form" onsubmit="handleAddProduct(event)">
        <!-- Basic Information -->
        <div class="form-section">
          <h2 class="form-section-title">Basic Information</h2>
          <div class="form-grid">
            <div class="form-group">
              <label class="form-label" for="product-name">
                Product Name
                <span class="required">*</span>
              </label>
              <input type="text" id="product-name" name="name" class="form-input" required
                placeholder="e.g., UXPacific Classic T-Shirt" />
            </div>

            <div class="form-group">
              <label class="form-label" for="product-category">
                Category
                <span class="required">*</span>
              </label>
              <select id="product-category" name="category" class="form-select" required>
                <option value="">Select Category</option>
                <option value="T-Shirts">T-Shirts</option>
                <option value="Stickers">Stickers</option>
                <option value="Booklet">Booklet</option>
                <option value="Workbook">Workbook</option>
                <option value="Mockup">Mockup</option>
                <option value="Badges">Badges</option>
                <option value="Template">UI Template</option>
              </select>
            </div>

            <div class="form-group full-width">
              <label class="form-label" for="product-description">
                Description
                <span class="required">*</span>
              </label>
              <textarea id="product-description" name="description" class="form-textarea" required
                placeholder="Enter detailed product description..."></textarea>
              <p class="form-help-text">Provide a detailed description of the product features and benefits.</p>
            </div>
          </div>
        </div>

        <!-- Pricing & Inventory -->
        <div class="form-section">
          <h2 class="form-section-title">Pricing & Inventory</h2>
          <div class="form-grid">
            <div class="form-group">
              <label class="form-label" for="product-price">
                Price
                <span class="required">*</span>
              </label>
              <input type="number" id="product-price" name="price" class="form-input" step="0.01" min="0" required
                placeholder="0.00" />
              <p class="form-help-text">Enter the selling price in USD.</p>
            </div>

            <div class="form-group">
              <label class="form-label" for="product-old-price">
                Old Price (Optional)
              </label>
              <input type="number" id="product-old-price" name="old_price" class="form-input" step="0.01" min="0"
                placeholder="0.00" />
              <p class="form-help-text">Enter the original price to show discount.</p>
            </div>

            <div class="form-group">
              <label class="form-label" for="product-stock">
                Stock Quantity
                <span class="required">*</span>
              </label>
              <input type="number" id="product-stock" name="stock" class="form-input" min="0" required
                placeholder="0" value="0" />
              <p class="form-help-text">Enter the available quantity in stock.</p>
            </div>

            <div class="form-group">
              <label class="form-label" for="product-rating">
                Rating (Optional)
              </label>
              <input type="number" id="product-rating" name="rating" class="form-input" step="0.1" min="0" max="5"
                placeholder="0.0" />
              <p class="form-help-text">Enter initial rating (0.0 to 5.0).</p>
            </div>
          </div>
        </div>

        <!-- Product Image -->
        <div class="form-section">
          <h2 class="form-section-title">Product Image</h2>
          <div class="form-group">
            <label class="form-label" for="product-image">
              Product Image
              <span class="required">*</span>
            </label>
            <div class="file-upload-area" id="file-upload-area" onclick="document.getElementById('product-image').click()">
              <svg class="file-upload-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                <polyline points="17 8 12 3 7 8"></polyline>
                <line x1="12" y1="3" x2="12" y2="15"></line>
              </svg>
              <p class="file-upload-text">Click to upload or drag and drop</p>
              <p class="file-upload-hint">PNG, JPG, WEBP up to 5MB</p>
            </div>
            <input type="file" id="product-image" name="image" class="form-input" accept="image/*" required
              style="display: none;" onchange="handleFileSelect(event)" />
            <div class="file-preview" id="file-preview">
              <img id="preview-image" src="" alt="Preview" />
            </div>
          </div>
        </div>

        <!-- Additional Options -->
        <div class="form-section">
          <h2 class="form-section-title">Additional Options</h2>
          <div class="form-grid">
            <div class="form-group">
              <div class="checkbox-group">
                <input type="checkbox" id="product-featured" name="featured" value="1" />
                <label class="form-label" for="product-featured" style="margin: 0;">
                  Featured Product
                </label>
              </div>
              <p class="form-help-text">Show this product in featured section on homepage.</p>
            </div>
          </div>
        </div>

        <!-- Form Actions -->
        <div class="form-actions">
          <a href="admin-dashboard.php" class="btn-secondary">Cancel</a>
          <button type="submit" class="btn-primary">Add Product</button>
        </div>
      </form>
    </div>
  </div>

  <script>
    // File upload handling
    function handleFileSelect(event) {
      const file = event.target.files[0];
      if (file) {
        const reader = new FileReader();
        reader.onload = function (e) {
          const preview = document.getElementById('file-preview');
          const previewImage = document.getElementById('preview-image');
          previewImage.src = e.target.result;
          preview.style.display = 'block';
        };
        reader.readAsDataURL(file);
      }
    }

    // Drag and drop handling
    const fileUploadArea = document.getElementById('file-upload-area');
    const fileInput = document.getElementById('product-image');

    fileUploadArea.addEventListener('dragover', (e) => {
      e.preventDefault();
      fileUploadArea.classList.add('dragover');
    });

    fileUploadArea.addEventListener('dragleave', () => {
      fileUploadArea.classList.remove('dragover');
    });

    fileUploadArea.addEventListener('drop', (e) => {
      e.preventDefault();
      fileUploadArea.classList.remove('dragover');
      const files = e.dataTransfer.files;
      if (files.length > 0) {
        fileInput.files = files;
        handleFileSelect({ target: { files: files } });
      }
    });

    // Form submission handler
    async function handleAddProduct(event) {
      event.preventDefault();
      
      const form = event.target;
      const submitBtn = form.querySelector('button[type="submit"]');
      const originalBtnText = submitBtn.innerText;
      
      // Disable button and show loading state
      submitBtn.disabled = true;
      submitBtn.innerText = 'Adding Product...';
      
      try {
        const formData = new FormData(form);
        
        const response = await fetch('../api/admin/product/create.php', {
          method: 'POST',
          body: formData
        });

        const result = await response.json();

        if (response.ok && result.status === 'success') {
          alert('Product added successfully!');
          form.reset();
          document.getElementById('file-preview').style.display = 'none';
          document.getElementById('preview-image').src = '';
          // redirect to dashboard or products list if needed
          // window.location.href = 'admin-dashboard.php';
        } else {
          throw new Error(result.message || 'Failed to add product');
        }
      } catch (error) {
        console.error('Error:', error);
        alert('Error adding product: ' + error.message);
      } finally {
        // Reset button state
        submitBtn.disabled = false;
        submitBtn.innerText = originalBtnText;
      }
    }

    // Theme toggle (if needed)
    function toggleTheme() {
      const body = document.body;
      const currentTheme = body.getAttribute('data-theme');
      const newTheme = currentTheme === 'light' ? 'dark' : 'light';
      body.setAttribute('data-theme', newTheme);
      localStorage.setItem('admin-theme', newTheme);
    }

    // Load saved theme
    document.addEventListener('DOMContentLoaded', function () {
      const savedTheme = localStorage.getItem('admin-theme') || 'light';
      document.body.setAttribute('data-theme', savedTheme);
    });
  </script>
</body>

</html>

