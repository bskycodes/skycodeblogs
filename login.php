<?php
session_start();

// Step 1: Database connection
try {
    $db = new PDO('mysql:host=localhost;dbname=iars', 'root', '');
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    $_SESSION['error'] = "Database connection failed.";
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
            // First, clean up any existing OTPs for this user
            try {
                $cleanupStmt = $db->prepare("DELETE FROM tutor_otps WHERE user_id = ?");
                $cleanupStmt->execute([$tutor['id']]);
            } catch (PDOException $e) {
                error_log("OTP cleanup failed: " . $e->getMessage());
                // Continue anyway - this is not critical
            }

            $otp = str_pad(rand(0, 999999), 6, '0', STR_PAD_LEFT);
            $created = date('Y-m-d H:i:s');
            $expires = date('Y-m-d H:i:s', time() + 300); // 5 minutes
            $used = 0;

            // Check if tutor_otps table exists and create if necessary
            try {
                $checkTable = $db->query("SHOW TABLES LIKE 'tutor_otps'");
                if ($checkTable->rowCount() == 0) {
                    // Create the table if it doesn't exist
                    $createTable = $db->exec("
                        CREATE TABLE tutor_otps (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            user_id INT NOT NULL,
                            otp VARCHAR(6) NOT NULL,
                            created_at DATETIME NOT NULL,
                            expires_at DATETIME NOT NULL,
                            used TINYINT(1) DEFAULT 0,
                            INDEX idx_user_id (user_id),
                            INDEX idx_otp (otp),
                            INDEX idx_expires (expires_at)
                        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
                    ");
                    error_log("Created tutor_otps table");
                }
            } catch (PDOException $e) {
                error_log("Table creation/check failed: " . $e->getMessage());
                $_SESSION['error'] = "System error. Please contact administrator.";
                header('Location: ../index.php');
                exit;
            }

            // Insert OTP with improved error handling
            try {
                $insertOtp = $db->prepare("
                    INSERT INTO tutor_otps (user_id, otp, created_at, expires_at, used)
                    VALUES (?, ?, ?, ?, ?)
                ");

                $insertResult = $insertOtp->execute([$tutor['id'], $otp, $created, $expires, $used]);

                if (!$insertResult) {
                    $errorInfo = $insertOtp->errorInfo();
                    error_log("OTP insert failed - Error Info: " . print_r($errorInfo, true));
                    error_log("OTP insert failed - Values: user_id={$tutor['id']}, otp=$otp, created=$created, expires=$expires, used=$used");
                    $_SESSION['error'] = "Failed to generate OTP. Please try again.";
                    header('Location: ../index.php');
                    exit;
                }

                // Verify the insertion was successful
                $lastInsertId = $db->lastInsertId();
                if (!$lastInsertId) {
                    error_log("OTP insert appeared successful but no last insert ID returned");
                    $_SESSION['error'] = "Failed to generate OTP. Please try again.";
                    header('Location: ../index.php');
                    exit;
                }

                error_log("OTP successfully inserted with ID: $lastInsertId for user: {$tutor['id']}");

            } catch (PDOException $e) {
                error_log("OTP insertion PDO exception: " . $e->getMessage());
                error_log("OTP insertion values: user_id={$tutor['id']}, otp=$otp, created=$created, expires=$expires, used=$used");
                $_SESSION['error'] = "Failed to generate OTP. Database error: " . $e->getMessage();
                header('Location: ../index.php');
                exit;
            }

            // Send OTP by email
            $emailSent = mail($tutor['email'], "IARS Login Confirmation", "Your OTP is: $otp");
            if (!$emailSent) {
                error_log("Failed to send OTP email to: " . $tutor['email']);
                // Don't fail the process, just log the error
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

        $db->prepare("INSERT INTO login_logs (user_id) VALUES (?)")->execute([$tutor['id']]);

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

        $db->prepare("INSERT INTO login_logs (user_id) VALUES (?)")->execute([$user['id']]);

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