package pkg

// Constants for roles
const (
    RoleAdmin     = "admin"
    RoleMember    = "member"
    RoleReseller  = "reseller"
    RolePlatinum  = "platinum"
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

// Constants for token types
const (
    TokenTypeEmailVerification = "email_verification"
    TokenTypePasswordReset     = "password_reset"
    TokenTypeInvitation       = "invitation"
)