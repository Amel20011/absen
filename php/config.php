<?php
// Database configuration
define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_NAME', 'liviaa_shop');

// Google OAuth configuration
define('GOOGLE_CLIENT_ID', 'YOUR_GOOGLE_CLIENT_ID');
define('GOOGLE_CLIENT_SECRET', 'YOUR_GOOGLE_CLIENT_SECRET');
define('GOOGLE_REDIRECT_URI', 'http://localhost/liviaa-shop/php/google-login.php');

// Email configuration for OTP
define('SMTP_HOST', 'smtp.gmail.com');
define('SMTP_PORT', 587);
define('SMTP_USER', 'your-email@gmail.com');
define('SMTP_PASS', 'your-email-password');

// WhatsApp API configuration
define('WHATSAPP_API_KEY', 'YOUR_WHATSAPP_API_KEY');
define('WHATSAPP_API_URL', 'https://api.whatsapp.com/send');

// Create database connection
function getDBConnection() {
    $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }
    
    return $conn;
}

// Generate secure token
function generateToken($length = 32) {
    return bin2hex(random_bytes($length));
}

// Hash password
function hashPassword($password) {
    return password_hash($password, PASSWORD_BCRYPT);
}

// Verify password
function verifyPassword($password, $hash) {
    return password_verify($password, $hash);
}

// Send OTP via Email
function sendEmailOTP($email, $otp) {
    $subject = "Kode OTP Login Liviaa Shop";
    $message = "
    <html>
    <head>
        <title>OTP Login</title>
        <style>
            body { font-family: Arial, sans-serif; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: linear-gradient(45deg, #ff69b4, #ff1493); color: white; padding: 20px; text-align: center; }
            .content { padding: 30px; background: #f9f9f9; }
            .otp-code { font-size: 32px; font-weight: bold; color: #ff1493; text-align: center; margin: 20px 0; }
            .footer { background: #333; color: white; padding: 15px; text-align: center; }
        </style>
    </head>
    <body>
        <div class='container'>
            <div class='header'>
                <h1>LIVIAA SHOP</h1>
                <p>Premium Liquid Glass</p>
            </div>
            <div class='content'>
                <h2>Kode OTP Anda</h2>
                <p>Gunakan kode OTP berikut untuk login ke akun Liviaa Shop Anda:</p>
                <div class='otp-code'>$otp</div>
                <p>Kode ini berlaku selama 10 menit.</p>
                <p>Jika Anda tidak meminta kode ini, abaikan email ini.</p>
            </div>
            <div class='footer'>
                <p>&copy; 2024 Liviaa Shop. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    ";
    
    $headers = "MIME-Version: 1.0" . "\r\n";
    $headers .= "Content-type:text/html;charset=UTF-8" . "\r\n";
    $headers .= "From: Liviaa Shop <noreply@liviaashop.com>" . "\r\n";
    
    return mail($email, $subject, $message, $headers);
}

// Send OTP via WhatsApp
function sendWhatsAppOTP($phone, $otp) {
    $message = urlencode("Kode OTP login Liviaa Shop Anda adalah: *$otp*. Kode ini berlaku 10 menit.");
    $url = WHATSAPP_API_URL . "?phone=$phone&text=$message";
    
    // In production, use WhatsApp Business API
    return $url;
}

// Generate random OTP
function generateOTP($length = 6) {
    $characters = '0123456789';
    $otp = '';
    for ($i = 0; $i < $length; $i++) {
        $otp .= $characters[rand(0, strlen($characters) - 1)];
    }
    return $otp;
}
?>
