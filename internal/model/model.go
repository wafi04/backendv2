package model

import (
	"time"
)

// User model
type User struct {
    ID              string  `json:"id" db:"id"`
    Username        string     `json:"username" db:"username"`
    Email           string     `json:"email" db:"email"`
    PasswordHash    string     `json:"-" db:"password_hash"`
    FullName        *string    `json:"full_name" db:"full_name"`
    Phone           *string    `json:"phone" db:"phone"`
    Status        string       `json:"status" db:"status"`
    EmailVerifiedAt *time.Time `json:"email_verified_at" db:"email_verified_at"`
    CreatedAt       time.Time  `json:"created_at" db:"created_at"`
    UpdatedAt       time.Time  `json:"updated_at" db:"updated_at"`
    
    // Relations
    Roles []Role `json:"roles,omitempty"`
}

// Role model
type Role struct {
    ID          int       `json:"id" db:"id"`
    Name        string    `json:"name" db:"name"`
    Description *string   `json:"description" db:"description"`
    CreatedAt   time.Time `json:"created_at" db:"created_at"`
    
    // Relations
    Permissions []Permission `json:"permissions,omitempty"`
}

// Permission model
type Permission struct {
    ID          int       `json:"id" db:"id"`
    Name        string    `json:"name" db:"name"`
    Description *string   `json:"description" db:"description"`
    Resource    string    `json:"resource" db:"resource"`
    Action      string    `json:"action" db:"action"`
    CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

// UserRole model
type UserRole struct {
    ID         int        `json:"id" db:"id"`
    UserID     string  `json:"user_id" db:"user_id"`
    RoleID     int        `json:"role_id" db:"role_id"`
    AssignedBy *string `json:"assigned_by" db:"assigned_by"`
    AssignedAt time.Time  `json:"assigned_at" db:"assigned_at"`
    ExpiresAt  *time.Time `json:"expires_at" db:"expires_at"`
    IsActive   bool       `json:"is_active" db:"is_active"`
}

// Session model
type Session struct {
    ID         string  `json:"id" db:"id"`
    UserID     string  `json:"user_id" db:"user_id"`
    TokenHash  string     `json:"-" db:"token_hash"`
    DeviceInfo *string    `json:"device_info" db:"device_info"`
    IPAddress  *string    `json:"ip_address" db:"ip_address"`
    UserAgent  *string    `json:"user_agent" db:"user_agent"`
    IsActive   bool       `json:"is_active" db:"is_active"`
    ExpiresAt  time.Time  `json:"expires_at" db:"expires_at"`
    CreatedAt  time.Time  `json:"created_at" db:"created_at"`
    LastUsedAt time.Time  `json:"last_used_at" db:"last_used_at"`
}

// VerificationToken model
type VerificationToken struct {
    ID        string  `json:"id" db:"id"`
    UserID    string  `json:"user_id" db:"user_id"`
    TokenHash string     `json:"-" db:"token_hash"`
    TokenType string     `json:"token_type" db:"token_type"`
    ExpiresAt time.Time  `json:"expires_at" db:"expires_at"`
    UsedAt    *time.Time `json:"used_at" db:"used_at"`
    CreatedAt time.Time  `json:"created_at" db:"created_at"`
}

// Product model
type Product struct {
    ID          string `json:"id" db:"id"`
    Name        string    `json:"name" db:"name"`
    Description *string   `json:"description" db:"description"`
    BasePrice   float64   `json:"base_price" db:"base_price"`
    Stock       int       `json:"stock" db:"stock"`
    IsActive    bool      `json:"is_active" db:"is_active"`
    CreatedBy   *string `json:"created_by" db:"created_by"`
    CreatedAt   time.Time `json:"created_at" db:"created_at"`
    UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
    
    // Relations
    Prices []ProductPrice `json:"prices,omitempty"`
}

// ProductPrice model (untuk different pricing per role)
type ProductPrice struct {
    ID                 int       `json:"id" db:"id"`
    ProductID          string `json:"product_id" db:"product_id"`
    RoleID             *int      `json:"role_id" db:"role_id"`
    Price              float64   `json:"price" db:"price"`
    DiscountPercentage float64   `json:"discount_percentage" db:"discount_percentage"`
    IsActive           bool      `json:"is_active" db:"is_active"`
    CreatedBy          *string `json:"created_by" db:"created_by"`
    CreatedAt          time.Time `json:"created_at" db:"created_at"`
    UpdatedAt          time.Time `json:"updated_at" db:"updated_at"`
    
    // Relations
    Role *Role `json:"role,omitempty"`
}

// Order model
type Order struct {
    ID         string `json:"id" db:"id"`
    UserID     string `json:"user_id" db:"user_id"`
    UserRoleID *int      `json:"user_role_id" db:"user_role_id"`
    TotalAmount float64  `json:"total_amount" db:"total_amount"`
    Status     string    `json:"status" db:"status"`
    CreatedAt  time.Time `json:"created_at" db:"created_at"`
    UpdatedAt  time.Time `json:"updated_at" db:"updated_at"`
}

// UserContext untuk middleware authentication
type UserContext struct {
    User        *User        `json:"user"`
    Roles       []Role       `json:"roles"`
    Permissions []Permission `json:"permissions"`
    SessionID   string    `json:"session_id"`
}

// HasPermission check if user has specific permission
func (uc *UserContext) HasPermission(permissionName string) bool {
    for _, perm := range uc.Permissions {
        if perm.Name == permissionName {
            return true
        }
    }
    return false
}

// HasRole check if user has specific role
func (uc *UserContext) HasRole(roleName string) bool {
    for _, role := range uc.Roles {
        if role.Name == roleName {
            return true
        }
    }
    return false
}

// HasAnyRole check if user has any of the specified roles
func (uc *UserContext) HasAnyRole(roleNames ...string) bool {
    for _, roleName := range roleNames {
        if uc.HasRole(roleName) {
            return true
        }
    }
    return false
}

// GetPriceForUser get product price based on user role
func (p *Product) GetPriceForUser(userRoles []Role) float64 {
    // Check if user has special pricing based on role
    for _, role := range userRoles {
        for _, price := range p.Prices {
            if price.RoleID != nil && *price.RoleID == role.ID && price.IsActive {
                return price.Price
            }
        }
    }
    
    return p.BasePrice
}
