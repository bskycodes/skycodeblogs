<?php
session_start();

// Enable error reporting for debugging
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Step 1: Database connection
try {
    $db = new PDO('mysql:host=localhost;dbname=iars', 'root', '');
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    echo "Database connection successful.<br>";
} catch (PDOException $e) {
    $_SESSION['error'] = "Database connection failed: " . $e->getMessage();
    echo "Database error: " . $e->getMessage() . "<br>";
    header('Location: ../index.php');
    exit;
}

// Step 2: Check if tutor_otps table exists and its structure
try {
    $checkTable = $db->query("DESCRIBE tutor_otps");
    echo "tutor_otps table structure:<br>";
    while ($row = $checkTable->fetch(PDO::FETCH_ASSOC)) {
        echo "Column: " . $row['Field'] . " - Type: " . $row['Type'] . " - Null: " . $row['Null'] . "<br>";
    }
} catch (PDOException $e) {
    echo "Table check error: " . $e->getMessage() . "<br>";
    // Create the table if it doesn't exist
    try {
        $createTable = "
            CREATE TABLE IF NOT EXISTS tutor_otps (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                otp VARCHAR(6) NOT NULL,
                created_at DATETIME NOT NULL,
                expires_at DATETIME NOT NULL,
                used TINYINT(1) DEFAULT 0,
                INDEX idx_user_id (user_id),
                INDEX idx_otp (otp),
                INDEX idx_expires (expires_at)
            )
        ";
        $db->exec($createTable);
        echo "Created tutor_otps table.<br>";
    } catch (PDOException $e) {
        echo "Failed to create table: " . $e->getMessage() . "<br>";
    }
}

// Step 3: Collect input
$email = $_POST['email'] ?? '';
$password = $_POST['password'] ?? '';
$role = $_POST['role'] ?? '';

echo "Input received - Email: $email, Role: $role<br>";

if (!$email || !$password || !$role) {
    $_SESSION['error'] = "Please fill in all fields.";
    echo "Missing required fields.<br>";
    header('Location: ../index.php');
    exit;
}

// Step 4: Tutor Login
if ($role === 'tutor') {
    try {
        // Step 4a: Authenticate tutor
        $stmt = $db->prepare("SELECT * FROM tutors WHERE email = ? LIMIT 1");
        $stmt->execute([$email]);
        $tutor = $stmt->fetch(PDO::FETCH_ASSOC);

        echo "Tutor query executed. Found tutor: " . ($tutor ? "Yes" : "No") . "<br>";

        if (!$tutor || !password_verify($password, $tutor['password'])) {
            $_SESSION['error'] = "Invalid email or password.";
            echo "Authentication failed.<br>";
            header('Location: ../index.php');
            exit;
        }

        echo "Tutor authenticated. Confirmed status: " . ($tutor['confirmed'] ? "Yes" : "No") . "<br>";

        // Step 4b: If not confirmed, generate OTP and redirect to verify_otp
        if (!$tutor['confirmed']) {
            $otp = str_pad(rand(0, 999999), 6, '0', STR_PAD_LEFT);
            $created = date('Y-m-d H:i:s');
            $expires = date('Y-m-d H:i:s', time() + 300); // 5 minutes
            $used = 0;

            echo "Generated OTP: $otp<br>";
            echo "Tutor ID: " . $tutor['id'] . "<br>";
            echo "Created: $created<br>";
            echo "Expires: $expires<br>";

            // First, clean up any existing OTPs for this user
            try {
                $deleteOld = $db->prepare("DELETE FROM tutor_otps WHERE user_id = ? AND used = 0");
                $deleteOld->execute([$tutor['id']]);
                echo "Cleaned up old OTPs for user.<br>";
            } catch (PDOException $e) {
                echo "Warning: Could not clean up old OTPs: " . $e->getMessage() . "<br>";
            }

            // Insert new OTP with detailed error checking
            $insertOtp = $db->prepare("
                INSERT INTO tutor_otps (user_id, otp, created_at, expires_at, used)
                VALUES (?, ?, ?, ?, ?)
            ");

            try {
                $result = $insertOtp->execute([$tutor['id'], $otp, $created, $expires, $used]);
                
                if ($result) {
                    echo "OTP inserted successfully. Last insert ID: " . $db->lastInsertId() . "<br>";
                    
                    // Verify the insertion
                    $verify = $db->prepare("SELECT * FROM tutor_otps WHERE user_id = ? AND otp = ?");
                    $verify->execute([$tutor['id'], $otp]);
                    $otpRecord = $verify->fetch(PDO::FETCH_ASSOC);
                    
                    if ($otpRecord) {
                        echo "OTP verification successful. Record ID: " . $otpRecord['id'] . "<br>";
                    } else {
                        echo "OTP verification failed - record not found after insertion.<br>";
                    }
                } else {
                    echo "OTP insertion returned false.<br>";
                    echo "Error info: " . print_r($insertOtp->errorInfo(), true) . "<br>";
                }
            } catch (PDOException $e) {
                echo "OTP insert exception: " . $e->getMessage() . "<br>";
                echo "Error Code: " . $e->getCode() . "<br>";
                $_SESSION['error'] = "Failed to generate OTP: " . $e->getMessage();
                header('Location: ../index.php');
                exit;
            }

            // Send OTP by email (commented out for debugging)
            // mail($tutor['email'], "IARS Login Confirmation", "Your OTP is: $otp");
            echo "OTP would be sent to: " . $tutor['email'] . "<br>";

            // Set session to indicate pending OTP verification
            $_SESSION['pending_user_id'] = $tutor['id'];
            $_SESSION['pending_user_role'] = 'tutor';

            echo "Session variables set. Redirecting to verify_otp.php<br>";
            // Comment out redirect for debugging
            // header('Location: verify_otp.php');
            echo '<a href="verify_otp.php">Continue to OTP verification</a><br>';
            exit;
        }

        // Step 4c: If confirmed, set session and redirect
        $_SESSION['user_id'] = $tutor['id'];
        $_SESSION['user_name'] = $tutor['name'];
        $_SESSION['user_role'] = 'tutor';

        $db->prepare("INSERT INTO login_logs (user_id) VALUES (?)")->execute([$tutor['id']]);

        header('Location: ../tutor/dashboard.php');
        exit;

    } catch (PDOException $e) {
        error_log("Tutor login error: " . $e->getMessage());
        echo "Tutor login error: " . $e->getMessage() . "<br>";
        $_SESSION['error'] = "Login failed. Please try again.";
        header('Location: ../index.php');
        exit;
    }
}

// Step 5: Admin / AR Login
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

// Step 6: Invalid Role
else {
    $_SESSION['error'] = "Unauthorized login attempt.";
    header('Location: ../index.php');
    exit;
}
?>