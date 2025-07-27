-- Create tutor_otps table if it doesn't exist
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
    FOREIGN KEY (user_id) REFERENCES tutors(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Clean up any expired OTPs (optional maintenance query)
-- DELETE FROM tutor_otps WHERE expires_at < NOW() OR used = 1;