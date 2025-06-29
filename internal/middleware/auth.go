package middleware

// import (
// 	"net/http"
// 	"strings"

// 	"github.com/wafi04/backend/internal/model"
// 	// "github.com/wafi04/backend/internal/service"
// 	"github.com/gin-gonic/gin"
// )

// type AuthMiddleware struct {
//     authService *service.AuthService
// }

// func NewAuthMiddleware(authService *service.AuthService) *AuthMiddleware {
//     return &AuthMiddleware{
//         authService: authService,
//     }
// }

// // RequireAuth middleware untuk authentication
// func (m *AuthMiddleware) RequireAuth() gin.HandlerFunc {
//     return func(c *gin.Context) {
//         token := extractToken(c)
//         if token == "" {
//             c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing authentication token"})
//             c.Abort()
//             return
//         }

//         userContext, err := m.authService.ValidateToken(token)
//         if err != nil {
//             c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
//             c.Abort()
//             return
//         }

//         // Set user context ke gin context
//         c.Set("user", userContext)
//         c.Next()
//     }
// }

// // RequirePermission middleware untuk authorization berdasarkan permission
// func (m *AuthMiddleware) RequirePermission(permission string) gin.HandlerFunc {
//     return func(c *gin.Context) {
//         userContext, exists := c.Get("user")
//         if !exists {
//             c.JSON(http.StatusUnauthorized, gin.H{"error": "User context not found"})
//             c.Abort()
//             return
//         }

//         user := userContext.(*model.UserContext)
//         if !user.HasPermission(permission) {
//             c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
//             c.Abort()
//             return
//         }

//         c.Next()
//     }
// }

// // RequireRole middleware untuk authorization berdasarkan role
// func (m *AuthMiddleware) RequireRole(roles ...string) gin.HandlerFunc {
//     return func(c *gin.Context) {
//         userContext, exists := c.Get("user")
//         if !exists {
//             c.JSON(http.StatusUnauthorized, gin.H{"error": "User context not found"})
//             c.Abort()
//             return
//         }

//         user := userContext.(*model.UserContext)
//         if !user.HasAnyRole(roles...) {
//             c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient role"})
//             c.Abort()
//             return
//         }

//         c.Next()
//     }
// }

// // RequireAnyPermission middleware untuk authorization dengan multiple permissions (OR logic)
// func (m *AuthMiddleware) RequireAnyPermission(permissions ...string) gin.HandlerFunc {
//     return func(c *gin.Context) {
//         userContext, exists := c.Get("user")
//         if !exists {
//             c.JSON(http.StatusUnauthorized, gin.H{"error": "User context not found"})
//             c.Abort()
//             return
//         }

//         user := userContext.(*model.UserContext)
//         hasPermission := false

//         for _, permission := range permissions {
//             if user.HasPermission(permission) {
//                 hasPermission = true
//                 break
//             }
//         }

//         if !hasPermission {
//             c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
//             c.Abort()
//             return
//         }

//         c.Next()
//     }
// }

// // RequireAllPermissions middleware untuk authorization dengan multiple permissions (AND logic)
// func (m *AuthMiddleware) RequireAllPermissions(permissions ...string) gin.HandlerFunc {
//     return func(c *gin.Context) {
//         userContext, exists := c.Get("user")
//         if !exists {
//             c.JSON(http.StatusUnauthorized, gin.H{"error": "User context not found"})
//             c.Abort()
//             return
//         }

//         user := userContext.(*model.UserContext)

//         for _, permission := range permissions {
//             if !user.HasPermission(permission) {
//                 c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
//                 c.Abort()
//                 return
//             }
//         }

//         c.Next()
//     }
// }

// // OptionalAuth middleware untuk optional authentication
// func (m *AuthMiddleware) OptionalAuth() gin.HandlerFunc {
//     return func(c *gin.Context) {
//         token := extractToken(c)
//         if token != "" {
//             userContext, err := m.authService.ValidateToken(token)
//             if err == nil {
//                 c.Set("user", userContext)
//             }
//         }
//         c.Next()
//     }
// }

// // Helper function untuk extract token dari header
// func extractToken(c *gin.Context) string {
//     bearerToken := c.GetHeader("Authorization")
//     if len(strings.Split(bearerToken, " ")) == 2 {
//         return strings.Split(bearerToken, " ")[1]
//     }
//     return ""
// }

// // Helper function untuk get current user dari context
// func GetCurrentUser(c *gin.Context) (*model.UserContext, bool) {
//     userContext, exists := c.Get("user")
//     if !exists {
//         return nil, false
//     }

//     user, ok := userContext.(*model.UserContext)
//     return user, ok
// }

// // Contoh penggunaan di router
// func SetupRoutes(r *gin.Engine, authMiddleware *AuthMiddleware) {
//     api := r.Group("/api/v1")

//     // Public routes
//     api.POST("/register", registerHandler)
//     api.POST("/login", loginHandler)

//     // Protected routes
//     protected := api.Group("")
//     protected.Use(authMiddleware.RequireAuth())
//     {
//         // Basic authenticated routes
//         protected.GET("/profile", getProfileHandler)
//         protected.PUT("/profile", updateProfileHandler)

//         // Admin only routes
//         admin := protected.Group("/admin")
//         admin.Use(authMiddleware.RequireRole(model.RoleAdmin))
//         {
//             admin.GET("/users", getUsersHandler)
//             admin.POST("/users", createUserHandler)
//             admin.PUT("/users/:id/role", assignRoleHandler)
//         }

//         // Reseller routes (can edit prices)
//         reseller := protected.Group("/reseller")
//         reseller.Use(authMiddleware.RequirePermission(model.PermissionEditPrices))
//         {
//             reseller.PUT("/products/:id/price", updateProductPriceHandler)
//             reseller.GET("/products", getProductsForResellerHandler)
//         }

//         // Product routes with different permissions
//         products := protected.Group("/products")
//         {
//             // Anyone can view products
//             products.GET("", getProductsHandler)
//             products.GET("/:id", getProductHandler)

//             // Only admin and reseller can manage products
//             products.POST("",
//                 authMiddleware.RequireAnyPermission(
//                     model.PermissionManageProducts,
//                     model.PermissionEditPrices,
//                 ),
//                 createProductHandler,
//             )

//             products.PUT("/:id",
//                 authMiddleware.RequirePermission(model.PermissionManageProducts),
//                 updateProductHandler,
//             )

//             products.DELETE("/:id",
//                 authMiddleware.RequireRole(model.RoleAdmin),
//                 deleteProductHandler,
//             )
//         }

//         // Orders routes
//         orders := protected.Group("/orders")
//         {
//             orders.GET("", getOrdersHandler) // User can see their own orders
//             orders.POST("", createOrderHandler)

//             // Admin can manage all orders
//             orders.GET("/all",
//                 authMiddleware.RequirePermission(model.PermissionViewOrders),
//                 getAllOrdersHandler,
//             )

//             orders.PUT("/:id/status",
//                 authMiddleware.RequirePermission(model.PermissionManageOrders),
//                 updateOrderStatusHandler,
//             )
//         }
//     }
// }

// // Example handlers
// func updateProductPriceHandler(c *gin.Context) {
//     user, _ := GetCurrentUser(c)

//     // Logic untuk update harga product
//     // Reseller bisa set harga khusus untuk role tertentu

//     c.JSON(http.StatusOK, gin.H{
//         "message": "Price updated successfully",
//         "updated_by": user.User.Username,
//     })
// }

// func getProductsForResellerHandler(c *gin.Context) {
//     user, _ := GetCurrentUser(c)

//     // Get products dengan harga khusus untuk reseller
//     // Include pricing options yang bisa di-edit

//     c.JSON(http.StatusOK, gin.H{
//         "products": "products with editable prices",
//         "user_role": user.Roles,
//     })
// }