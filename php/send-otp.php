<?php
require_once 'config.php';

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = json_decode(file_get_contents('php://input'), true);
    
    $email = filter_var($data['email'], FILTER_SANITIZE_EMAIL);
    $method = isset($data['method']) ? $data['method'] : 'email'; // email or whatsapp
    
    if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo json_encode(['success' => false, 'message' => 'Email tidak valid']);
        exit;
    }
    
    $conn = getDBConnection();
    
    // Check if user exists
    $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result();
    
    if ($stmt->num_rows === 0) {
        echo json_encode(['success' => false, 'message' => 'Email tidak terdaftar']);
        $stmt->close();
        $conn->close();
        exit;
    }
    
    // Generate OTP
    $otp = generateOTP();
    $expires = date('Y-m-d H:i:s', strtotime('+10 minutes'));
    
    // Store OTP in database
    $stmt = $conn->prepare("INSERT INTO otp_codes (email, otp_code, expires_at) VALUES (?, ?, ?)");
    $stmt->bind_param("sss", $email, $otp, $expires);
    
    if ($stmt->execute()) {
        if ($method === 'email') {
            // Send OTP via email
            if (sendEmailOTP($email, $otp)) {
                echo json_encode([
                    'success' => true, 
                    'message' => 'OTP telah dikirim ke email Anda',
                    'otp' => $otp // Only for demo, remove in production
                ]);
            } else {
                echo json_encode(['success' => false, 'message' => 'Gagal mengirim OTP. Silakan coba lagi']);
            }
        } elseif ($method === 'whatsapp') {
            // Get phone number from user
            $stmt = $conn->prepare("SELECT phone FROM users WHERE email = ?");
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $result = $stmt->get_result();
            $user = $result->fetch_assoc();
            
            if (!empty($user['phone'])) {
                $whatsappUrl = sendWhatsAppOTP($user['phone'], $otp);
                
                // Update OTP record
                $updateStmt = $conn->prepare("UPDATE otp_codes SET whatsapp_sent = TRUE WHERE email = ? AND otp_code = ?");
                $updateStmt->bind_param("ss", $email, $otp);
                $updateStmt->execute();
                $updateStmt->close();
                
                echo json_encode([
                    'success' => true, 
                    'message' => 'OTP telah dikirim ke WhatsApp Anda',
                    'whatsapp_url' => $whatsappUrl,
                    'otp' => $otp // Only for demo, remove in production
                ]);
            } else {
                echo json_encode(['success' => false, 'message' => 'Nomor WhatsApp tidak terdaftar']);
            }
        }
    } else {
        echo json_encode(['success' => false, 'message' => 'Gagal membuat OTP. Silakan coba lagi']);
    }
    
    $stmt->close();
    $conn->close();
} else {
    echo json_encode(['success' => false, 'message' => 'Method tidak diizinkan']);
}
?>
