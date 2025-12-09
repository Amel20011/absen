<?php
require_once 'config.php';

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = json_decode(file_get_contents('php://input'), true);
    
    $email = filter_var($data['email'], FILTER_SANITIZE_EMAIL);
    $otp = $data['otp'];
    
    if (empty($email) || empty($otp)) {
        echo json_encode(['success' => false, 'message' => 'Email dan OTP harus diisi']);
        exit;
    }
    
    $conn = getDBConnection();
    
    // Verify OTP
    $stmt = $conn->prepare("SELECT * FROM otp_codes WHERE email = ? AND otp_code = ? AND used = FALSE AND expires_at > NOW()");
    $stmt->bind_param("ss", $email, $otp);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 0) {
        echo json_encode(['success' => false, 'message' => 'OTP tidak valid atau telah kedaluwarsa']);
        $stmt->close();
        $conn->close();
        exit;
    }
    
    $otpRecord = $result->fetch_assoc();
    
    // Mark OTP as used
    $updateStmt = $conn->prepare("UPDATE otp_codes SET used = TRUE WHERE id = ?");
    $updateStmt->bind_param("i", $otpRecord['id']);
    $updateStmt->execute();
    $updateStmt->close();
    
    // Get user
    $userStmt = $conn->prepare("SELECT id, username, email FROM users WHERE email = ?");
    $userStmt->bind_param("s", $email);
    $userStmt->execute();
    $userResult = $userStmt->get_result();
    $user = $userResult->fetch_assoc();
    
    // Generate token
    $token = generateToken();
    
    echo json_encode([
        'success' => true,
        'message' => 'OTP berhasil diverifikasi',
        'token' => $token,
        'user' => $user
    ]);
    
    $stmt->close();
    $userStmt->close();
    $conn->close();
} else {
    echo json_encode(['success' => false, 'message' => 'Method tidak diizinkan']);
}
?>
