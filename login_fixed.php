<?php
session_start();

// Step 1: Database connection
try {
    $db = new PDO('mysql:host=localhost;dbname=iars', 'root', '');
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    $_SESSION['error'] = "Database connection failed.";
    error_log("Database connection error: " . $e->getMessage());
    header('Location: ../index.php');
    exit;
}

// Step 2: Collect input
$email = $_POST['email'] ?? '';
$password = $_POST['password'] ?? '';
$role = $_POST['role'] ?? '';

if (!$email || !$password || !$role) {
    $_SESSION['error'] = "Please fill in all fields.";
    header('Location: ../index.php');
    exit;
}

// Step 3: Tutor Login
if ($role === 'tutor') {
    try {
        // Step 3a: Authenticate tutor
        $stmt = $db->prepare("SELECT * FROM tutors WHERE email = ? LIMIT 1");
        $stmt->execute([$email]);
        $tutor = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$tutor || !password_verify($password, $tutor['password'])) {
            $_SESSION['error'] = "Invalid email or password.";
            header('Location: ../index.php');
            exit;
        }

        // Step 3b: If not confirmed, generate OTP and redirect to verify_otp
        if (!$tutor['confirmed']) {
            $otp = str_pad(rand(0, 999999), 6, '0', STR_PAD_LEFT);
            $created = date('Y-m-d H:i:s');
            $expires = date('Y-m-d H:i:s', time() + 300); // 5 minutes
            $used = 0;

            // Clean up any existing unused OTPs for this user first
            try {
                $deleteOld = $db->prepare("DELETE FROM tutor_otps WHERE user_id = ? AND used = 0");
                $deleteOld->execute([$tutor['id']]);
            } catch (PDOException $e) {
                error_log("Failed to clean up old OTPs: " . $e->getMessage());
            }

            // Insert new OTP with better error handling
            try {
                $insertOtp = $db->prepare("
                    INSERT INTO tutor_otps (user_id, otp, created_at, expires_at, used)
                    VALUES (?, ?, ?, ?, ?)
                ");

                $result = $insertOtp->execute([$tutor['id'], $otp, $created, $expires, $used]);

                if (!$result) {
                    $errorInfo = $insertOtp->errorInfo();
                    error_log("OTP insert failed with error: " . print_r($errorInfo, true));
                    $_SESSION['error'] = "Failed to generate OTP. Please try again.";
                    header('Location: ../index.php');
                    exit;
                }

                // Verify the insertion was successful
                $verify = $db->prepare("SELECT id FROM tutor_otps WHERE user_id = ? AND otp = ? AND used = 0");
                $verify->execute([$tutor['id'], $otp]);
                if (!$verify->fetch()) {
                    error_log("OTP verification failed after insertion for user ID: " . $tutor['id']);
                    $_SESSION['error'] = "Failed to generate OTP. Please try again.";
                    header('Location: ../index.php');
                    exit;
                }

            } catch (PDOException $e) {
                error_log("OTP insert exception: " . $e->getMessage() . " | Code: " . $e->getCode());
                $_SESSION['error'] = "Failed to generate OTP. Please try again.";
                header('Location: ../index.php');
                exit;
            }

            // Send OTP by email
            $subject = "IARS Login Confirmation";
            $message = "Your OTP for login verification is: $otp\n\nThis OTP will expire in 5 minutes.";
            $headers = "From: noreply@iars.com\r\n";
            
            if (!mail($tutor['email'], $subject, $message, $headers)) {
                error_log("Failed to send OTP email to: " . $tutor['email']);
                // Continue anyway as OTP is already stored
            }

            // Set session to indicate pending OTP verification
            $_SESSION['pending_user_id'] = $tutor['id'];
            $_SESSION['pending_user_role'] = 'tutor';

            header('Location: verify_otp.php');
            exit;
        }

        // Step 3c: If confirmed, set session and redirect
        $_SESSION['user_id'] = $tutor['id'];
        $_SESSION['user_name'] = $tutor['name'];
        $_SESSION['user_role'] = 'tutor';

        // Log the successful login
        try {
            $db->prepare("INSERT INTO login_logs (user_id) VALUES (?)")->execute([$tutor['id']]);
        } catch (PDOException $e) {
            error_log("Failed to log tutor login: " . $e->getMessage());
            // Continue anyway as login was successful
        }

        header('Location: ../tutor/dashboard.php');
        exit;

    } catch (PDOException $e) {
        error_log("Tutor login error: " . $e->getMessage());
        $_SESSION['error'] = "Login failed. Please try again.";
        header('Location: ../index.php');
        exit;
    }
}

// Step 4: Admin / AR Login
elseif (in_array($role, ['admin', 'ar'])) {
    try {
        $stmt = $db->prepare("SELECT * FROM users WHERE email = ? LIMIT 1");
        $stmt->execute([$email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user || !password_verify($password, $user['password'])) {
            $_SESSION['error'] = "Invalid email or password.";
            header('Location: ../index.php');
            exit;
        }

        if ($user['role'] !== $role) {
            $_SESSION['error'] = "Incorrect role selected.";
            header('Location: ../index.php');
            exit;
        }

        $_SESSION['user_id'] = $user['id'];
        $_SESSION['user_name'] = $user['name'];
        $_SESSION['user_role'] = $user['role'];

        // Log the successful login
        try {
            $db->prepare("INSERT INTO login_logs (user_id) VALUES (?)")->execute([$user['id']]);
        } catch (PDOException $e) {
            error_log("Failed to log admin login: " . $e->getMessage());
            // Continue anyway as login was successful
        }

        header('Location: ../admin/dashboard.php');
        exit;

    } catch (PDOException $e) {
        error_log("Admin login error: " . $e->getMessage());
        $_SESSION['error'] = "Login failed. Please try again.";
        header('Location: ../index.php');
        exit;
    }
}

// Step 5: Invalid Role
else {
    $_SESSION['error'] = "Unauthorized login attempt.";
    header('Location: ../index.php');
    exit;
}
?>