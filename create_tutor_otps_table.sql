-- Create tutor_otps table if it doesn't exist
-- This table stores OTP codes for tutor email verification

CREATE TABLE IF NOT EXISTS tutor_otps (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    otp VARCHAR(6) NOT NULL,
    created_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    used TINYINT(1) DEFAULT 0,
    INDEX idx_user_id (user_id),
    INDEX idx_otp (otp),
    INDEX idx_expires (expires_at),
    INDEX idx_used (used)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Optional: Clean up expired OTPs (run this periodically)
-- DELETE FROM tutor_otps WHERE expires_at < NOW();

-- Check table structure
DESCRIBE tutor_otps;