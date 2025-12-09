// DOM Ready
document.addEventListener('DOMContentLoaded', function() {
    // Mobile Menu Toggle
    const mobileMenu = document.querySelector('.mobile-menu');
    const navLinks = document.querySelector('.nav-links');
    
    if (mobileMenu) {
        mobileMenu.addEventListener('click', function() {
            mobileMenu.classList.toggle('active');
            navLinks.style.display = navLinks.style.display === 'flex' ? 'none' : 'flex';
        });
    }
    
    // Tab Switching for Login/Register
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    
    tabBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            const tabId = this.getAttribute('data-tab');
            
            // Update active tab button
            tabBtns.forEach(b => b.classList.remove('active'));
            this.classList.add('active');
            
            // Show active tab content
            tabContents.forEach(content => {
                content.classList.remove('active');
                if (content.id === tabId) {
                    content.classList.add('active');
                }
            });
        });
    });
    
    // Check URL for register parameter
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('register') === 'true') {
        const registerTab = document.querySelector('[data-tab="register"]');
        if (registerTab) registerTab.click();
    }
    
    // Load featured products
    loadFeaturedProducts();
    
    // OTP Input Handling
    setupOTPInputs();
    
    // Login Form Submission
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }
    
    // Register Form Submission
    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        registerForm.addEventListener('submit', handleRegister);
    }
    
    // OTP Form Submission
    const otpForm = document.getElementById('otpForm');
    if (otpForm) {
        otpForm.addEventListener('submit', handleOTPSubmit);
    }
    
    // Google OAuth
    initializeGoogleOAuth();
});

// Load Featured Products
function loadFeaturedProducts() {
    const productsGrid = document.querySelector('.products-grid');
    if (!productsGrid) return;
    
    // In a real app, this would be an API call
    const products = [
        { id: 1, name: "Liquid Glass Pro Max", desc: "Pelindung premium dengan kekuatan 9H", price: "Rp 199.000", color: "#ff69b4" },
        { id: 2, name: "Liquid Glass Ultra", desc: "Pelindung anti gores nano coating", price: "Rp 179.000", color: "#ff1493" },
        { id: 3, name: "Liquid Glass Matte", desc: "Anti sidik jari dengan finishing matte", price: "Rp 149.000", color: "#db0a93" },
        { id: 4, name: "Liquid Glass Privacy", desc: "Pelindung privacy dari sisi samping", price: "Rp 219.000", color: "#ff69b4" }
    ];
    
    let html = '';
    products.forEach(product => {
        html += `
            <div class="product-card">
                <div class="product-img" style="background-color: ${product.color}20;">
                    <i class="fas fa-mobile-alt" style="color: ${product.color};"></i>
                </div>
                <div class="product-info">
                    <h3>${product.name}</h3>
                    <p>${product.desc}</p>
                    <div class="product-price">${product.price}</div>
                    <a href="products.html" class="product-btn">Lihat Detail</a>
                </div>
            </div>
        `;
    });
    
    productsGrid.innerHTML = html;
}

// Setup OTP Inputs
function setupOTPInputs() {
    const otpInputs = document.querySelectorAll('.otp-input');
    
    otpInputs.forEach((input, index) => {
        input.addEventListener('input', function() {
            if (this.value.length === 1 && index < otpInputs.length - 1) {
                otpInputs[index + 1].focus();
            }
        });
        
        input.addEventListener('keydown', function(e) {
            if (e.key === 'Backspace' && this.value.length === 0 && index > 0) {
                otpInputs[index - 1].focus();
            }
        });
    });
}

// Handle Login
function handleLogin(e) {
    e.preventDefault();
    
    const email = document.getElementById('loginEmail').value;
    const password = document.getElementById('loginPassword').value;
    const remember = document.getElementById('remember').checked;
    
    // Simple validation
    if (!email || !password) {
        showMessage('error', 'Email dan password harus diisi!');
        return;
    }
    
    // Show loading
    const submitBtn = e.target.querySelector('.btn-submit');
    const originalText = submitBtn.innerHTML;
    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Memproses...';
    submitBtn.disabled = true;
    
    // Simulate API call
    setTimeout(() => {
        // In real app, this would be a fetch to your PHP backend
        if (email.includes('@') && password.length >= 6) {
            showMessage('success', 'Login berhasil! Mengalihkan...');
            setTimeout(() => {
                window.location.href = 'dashboard.html';
            }, 1500);
        } else {
            showMessage('error', 'Email atau password salah!');
            submitBtn.innerHTML = originalText;
            submitBtn.disabled = false;
        }
    }, 1500);
}

// Handle Register
function handleRegister(e) {
    e.preventDefault();
    
    const username = document.getElementById('regUsername').value;
    const email = document.getElementById('regEmail').value;
    const password = document.getElementById('regPassword').value;
    const confirmPassword = document.getElementById('regConfirmPassword').value;
    
    // Validation
    if (!username || !email || !password || !confirmPassword) {
        showMessage('error', 'Semua field harus diisi!');
        return;
    }
    
    if (password !== confirmPassword) {
        showMessage('error', 'Password dan konfirmasi password tidak cocok!');
        return;
    }
    
    if (password.length < 6) {
        showMessage('error', 'Password minimal 6 karakter!');
        return;
    }
    
    // Show loading
    const submitBtn = e.target.querySelector('.btn-submit');
    const originalText = submitBtn.innerHTML;
    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Mendaftarkan...';
    submitBtn.disabled = true;
    
    // Simulate API call
    setTimeout(() => {
        // In real app, this would be a fetch to register.php
        showMessage('success', 'Pendaftaran berhasil! Silakan login.');
        setTimeout(() => {
            document.querySelector('[data-tab="login"]').click();
            submitBtn.innerHTML = originalText;
            submitBtn.disabled = false;
            e.target.reset();
        }, 1500);
    }, 2000);
}

// Handle OTP Submit
function handleOTPSubmit(e) {
    e.preventDefault();
    
    const otpInputs = document.querySelectorAll('.otp-input');
    let otp = '';
    otpInputs.forEach(input => {
        otp += input.value;
    });
    
    if (otp.length !== 6) {
        showMessage('error', 'OTP harus 6 digit!');
        return;
    }
    
    // Show loading
    const submitBtn = e.target.querySelector('.btn-submit');
    const originalText = submitBtn.innerHTML;
    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Memverifikasi...';
    submitBtn.disabled = true;
    
    // Simulate OTP verification
    setTimeout(() => {
        if (otp === '123456') { // Default OTP for demo
            showMessage('success', 'OTP berhasil diverifikasi! Mengalihkan...');
            setTimeout(() => {
                window.location.href = 'dashboard.html';
            }, 1500);
        } else {
            showMessage('error', 'OTP salah! Coba lagi.');
            submitBtn.innerHTML = originalText;
            submitBtn.disabled = false;
        }
    }, 1500);
}

// Request OTP via Email
function requestEmailOTP() {
    const email = document.getElementById('loginEmail')?.value || 
                  document.getElementById('regEmail')?.value;
    
    if (!email || !email.includes('@')) {
        showMessage('error', 'Masukkan email yang valid!');
        return;
    }
    
    showMessage('info', `Mengirim OTP ke ${email}...`);
    
    // Simulate sending OTP
    setTimeout(() => {
        showMessage('success', 'OTP telah dikirim ke email Anda!');
        showOTPSection();
        startOTPTimer();
    }, 2000);
}

// Request OTP via WhatsApp
function requestWhatsAppOTP() {
    const phone = prompt('Masukkan nomor WhatsApp (contoh: 6281234567890):');
    
    if (!phone || phone.length < 10) {
        showMessage('error', 'Nomor WhatsApp tidak valid!');
        return;
    }
    
    showMessage('info', `Mengirim OTP ke WhatsApp ${phone}...`);
    
    // Simulate sending OTP
    setTimeout(() => {
        showMessage('success', 'OTP telah dikirim ke WhatsApp Anda!');
        showOTPSection();
        startOTPTimer();
    }, 2000);
}

// Show OTP Section
function showOTPSection() {
    document.getElementById('loginForm').style.display = 'none';
    document.getElementById('otpSection').style.display = 'block';
    
    // Auto-fill demo OTP for testing
    const otpInputs = document.querySelectorAll('.otp-input');
    if (otpInputs.length > 0) {
        otpInputs[0].focus();
    }
}

// Start OTP Timer
function startOTPTimer() {
    let timeLeft = 120; // 2 minutes
    
    const timerElement = document.getElementById('otpTimer');
    if (!timerElement) return;
    
    const timerInterval = setInterval(() => {
        const minutes = Math.floor(timeLeft / 60);
        const seconds = timeLeft % 60;
        
        timerElement.textContent = `Kode berlaku: ${minutes}:${seconds.toString().padStart(2, '0')}`;
        
        if (timeLeft <= 0) {
            clearInterval(timerInterval);
            timerElement.textContent = 'Kode OTP telah kedaluwarsa';
            timerElement.style.color = 'red';
        }
        
        timeLeft--;
    }, 1000);
}

// Initialize Google OAuth
function initializeGoogleOAuth() {
    const googleLoginBtn = document.getElementById('google-login-btn');
    
    if (googleLoginBtn) {
        googleLoginBtn.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Simulate Google OAuth
            showMessage('info', 'Mengarahkan ke Google Login...');
            
            setTimeout(() => {
                // In real app, this would redirect to Google OAuth
                // For demo, simulate successful login
                const user = {
                    name: 'Demo User',
                    email: 'demo@liviaashop.com'
                };
                
                showMessage('success', `Login berhasil sebagai ${user.name}!`);
                setTimeout(() => {
                    window.location.href = 'dashboard.html';
                }, 1500);
            }, 1000);
        });
    }
}

// Show Message
function showMessage(type, text) {
    // Remove existing messages
    const existingMsg = document.querySelector('.message-alert');
    if (existingMsg) existingMsg.remove();
    
    // Create message element
    const message = document.createElement('div');
    message.className = `message-alert message-${type}`;
    message.innerHTML = `
        <span>${text}</span>
        <button class="message-close">&times;</button>
    `;
    
    // Style the message
    message.style.cssText = `
        position: fixed;
        top: 100px;
        right: 20px;
        padding: 15px 20px;
        background: ${type === 'error' ? '#d32f2f' : type === 'success' ? '#388e3c' : '#1976d2'};
        color: white;
        border-radius: 10px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        min-width: 300px;
        max-width: 400px;
        z-index: 10000;
        box-shadow: 0 5px 15px rgba(0,0,0,0.3);
        animation: slideInRight 0.3s ease-out;
    `;
    
    // Add close button functionality
    const closeBtn = message.querySelector('.message-close');
    closeBtn.style.cssText = `
        background: transparent;
        border: none;
        color: white;
        font-size: 20px;
        cursor: pointer;
        margin-left: 15px;
    `;
    
    closeBtn.addEventListener('click', () => {
        message.style.animation = 'slideOutRight 0.3s ease-out';
        setTimeout(() => message.remove(), 300);
    });
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        if (message.parentNode) {
            message.style.animation = 'slideOutRight 0.3s ease-out';
            setTimeout(() => message.remove(), 300);
        }
    }, 5000);
    
    document.body.appendChild(message);
    
    // Add animations
    const style = document.createElement('style');
    style.textContent = `
        @keyframes slideInRight {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        @keyframes slideOutRight {
            from { transform: translateX(0); opacity: 1; }
            to { transform: translateX(100%); opacity: 0; }
        }
    `;
    document.head.appendChild(style);
}

// Dashboard functionality
function loadDashboardStats() {
    // In real app, load from API
    const stats = {
        totalProducts: 10,
        totalOrders: 24,
        totalVisitors: 156,
        revenue: 'Rp 4.250.000'
    };
    
    // Update stats cards
    document.getElementById('totalProducts').textContent = stats.totalProducts;
    document.getElementById('totalOrders').textContent = stats.totalOrders;
    document.getElementById('totalVisitors').textContent = stats.totalVisitors;
    document.getElementById('totalRevenue').textContent = stats.revenue;
}

// Simulate user logout
function logoutUser() {
    showMessage('info', 'Logging out...');
    setTimeout(() => {
        window.location.href = 'index.html';
    }, 1000);
}
