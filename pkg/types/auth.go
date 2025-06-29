package types

import "time"

type CreateUser struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	FullName string `json:"full_name"`
}

type CreateVerificationTokens struct {
	UserID    string     `json:"user_id" db:"user_id"`
	TokenType string     `json:"token_type" db:"token_type"`
	ExpiresAt time.Time  `json:"expires_at" db:"expires_at"`
	UsedAt    *time.Time `json:"used_at" db:"used_at"`
}

type CreateSession struct {
	UserID     string `json:"userID" db:"user_id"`
	TokenHash  string `json:"tokenHash" db:"token_hash"`
	DeviceInfo string `json:"deviceInfo"  db:"device_info"`
	IPAddress  string `json:"ipAddress"  db:"ip_addess"`
	UserAgent  string `json:"userAgent" db:"user_agent"`
	IsActive   bool   `json:"isActive" db:"is_active"`
}
