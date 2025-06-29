package pkg

// Constants for roles
const (
	RoleAdmin    = "admin"
	RoleMember   = "member"
	RoleReseller = "reseller"
	RolePlatinum = "platinum"
)

// Constants for permissions
const (
	PermissionManageUsers    = "manage_users"
	PermissionViewUsers      = "view_users"
	PermissionEditPrices     = "edit_prices"
	PermissionViewProducts   = "view_products"
	PermissionManageProducts = "manage_products"
	PermissionViewOrders     = "view_orders"
	PermissionManageOrders   = "manage_orders"
	PermissionViewReports    = "view_reports"
)

// Constants untuk token types
const (
	TokenTypeAccess            = "access"
	TokenTypeRefresh           = "refresh"
	TokenTypeVerification      = "verification"
	TokenTypePasswordReset     = "password_reset"
	TokenTypeEmailVerification = "email_verification"
	TokenTypePhoneVerification = "phone_verification"
	TokenTypeTwoFactor         = "two_factor"
	TokenTypeInvitation        = "invitation"
	TokenTypeAPIKey            = "api_key"
	TokenTypeSessionToken      = "session"
	TokenTypeCSRF              = "csrf"
)

// Token strength levels
const (
	TokenStrengthLow    = "low"    // 6-8 chars
	TokenStrengthMedium = "medium" // 16-32 chars
	TokenStrengthHigh   = "high"   // 64+ chars
)

// Character sets for token generation
const (
	NumericCharset      = "0123456789"
	AlphaCharset        = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	AlphanumericCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	SpecialCharset      = "!@#$%^&*()_+-=[]{}|;:,.<>?"
	URLSafeCharset      = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
	Base58Charset       = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
)
