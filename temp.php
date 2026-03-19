<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <title>Premium UI Design System</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <link
      href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap"
      rel="stylesheet"
    />

    <style>
      /* ================= BASE ================= */
      body {
        font-family: Inter, sans-serif;
        background: #0d0d10;
        color: #fff;
        margin: 0;
      }
      img {
        max-width: 100%;
        display: block;
      }
      button,
      select {
        font-family: inherit;
        cursor: pointer;
      }

      /* ================= LAYOUT ================= */
      .product-page {
        max-width: 1200px;
        margin: auto;
        padding: 40px 20px;
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 50px;
      }
      @media (max-width: 900px) {
        .product-page {
          grid-template-columns: 1fr;
        }
      }

      /* ================= GALLERY ================= */
      .product-gallery {
        position: relative;
      }
      .main-image {
        position: relative;
        border-radius: 18px;
        overflow: hidden;
      }
      .main-image img {
        width: 100%;
        border-radius: 18px;
      }

      .nav {
        position: absolute;
        top: 50%;
        transform: translateY(-50%);
        background: rgba(0, 0, 0, 0.6);
        color: #fff;
        border: none;
        font-size: 26px;
        width: 40px;
        height: 40px;
        border-radius: 50%;
      }
      .nav.prev {
        left: 15px;
      }
      .nav.next {
        right: 15px;
      }

      .thumbnail-row {
        display: flex;
        gap: 12px;
        margin-top: 15px;
      }
      .thumb {
        width: 70px;
        height: 70px;
        border-radius: 12px;
        opacity: 0.5;
        cursor: pointer;
      }
      .thumb.active {
        opacity: 1;
        outline: 2px solid #7c5cff;
      }

      /* Counter + dots */
      .slider-indicator {
        margin-top: 10px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        font-size: 14px;
        color: #aaa;
      }
      .dots {
        display: flex;
        gap: 6px;
      }
      .dots span {
        width: 8px;
        height: 8px;
        background: #555;
        border-radius: 50%;
      }
      .dots span.active {
        background: #7c5cff;
      }

      /* ================= PRODUCT INFO ================= */
      .product-info h1 {
        font-size: 32px;
        margin-bottom: 10px;
      }
      .description {
        color: #bbb;
        line-height: 1.6;
      }

      .price {
        margin: 20px 0;
        display: flex;
        gap: 15px;
        align-items: center;
      }
      .price .current {
        font-size: 28px;
        font-weight: 700;
      }
      .price .old {
        color: #777;
        text-decoration: line-through;
      }
      .price .badge {
        background: #7c5cff;
        padding: 5px 10px;
        border-radius: 20px;
        font-size: 13px;
      }

      /* ================= OPTIONS ================= */
      .option,
      .block {
        margin-top: 20px;
      }
      label {
        display: block;
        margin-bottom: 8px;
        font-weight: 500;
      }
      select {
        width: 100%;
        padding: 12px;
        background: #1a1a22;
        color: #fff;
        border-radius: 12px;
        border: 1px solid #333;
      }

      /* Size */
      .sizes button {
        background: #1a1a22;
        color: #fff;
        border: 1px solid #333;
        padding: 8px 14px;
        border-radius: 10px;
        margin-right: 8px;
      }
      .sizes .active {
        background: #7c5cff;
      }

      /* Quantity */
      .qty {
        display: flex;
        align-items: center;
        gap: 15px;
      }
      .qty button {
        width: 32px;
        height: 32px;
        border-radius: 50%;
        border: none;
        font-size: 18px;
      }

      /* Buy Button */
      .buy-btn {
        width: 100%;
        margin-top: 30px;
        padding: 14px;
        border-radius: 14px;
        background: #7c5cff;
        color: #fff;
        border: none;
        font-size: 18px;
        font-weight: 600;
      }

      /* Hide UXPacific options initially */
      #uxOptions {
        display: none;
      }

      .main-image {
  position: relative;
}

/* Dots inside image */
.image-dots {
  position: absolute;
  bottom: 14px;
  left: 50%;
  transform: translateX(-50%);
  display: flex;
  gap: 8px;
  z-index: 5;
}

.image-dots span {
  width: 9px;
  height: 9px;
  border-radius: 50%;
  background: rgba(255,255,255,0.4);
  cursor: pointer;
  transition: 0.3s;
}

.image-dots span.active {
  background: #7c5cff;
  transform: scale(1.2);
}

    </style>
  </head>

  <body>
    <div class="product-page">
      <!-- ================= LEFT ================= -->
      <div class="product-gallery">
        <div class="main-image">
          <img id="mainProductImage" src="img/t2.webp" />
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

      <!-- ================= RIGHT ================= -->
      <div class="product-info">
        <h1>Premium UI Design System</h1>
        <p class="description">
          A complete UI/UX system with professional components and layouts.
        </p>

        <div class="price">
          <span class="current">$29</span>
          <span class="old">$99</span>
          <span class="badge">71% OFF</span>
        </div>

        

        <!-- UXPacific Options -->
        <div id="uxOptions">
          <div class="option">
            <label>License Type</label>
            <select>
              <option>Personal</option>
              <option>Commercial</option>
            </select>
          </div>

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

        <button class="buy-btn">Buy Now</button>
      </div>
    </div>

    <!-- ================= JS ================= -->
    <script>
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
    </script>
  </body>
</html>

