package handlers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/wafi04/backend/internal/services/auth"
	"github.com/wafi04/backend/pkg/types"
)

type AuthHandler struct {
	AuthService *auth.AuhtService
}

func NewAuthHandler(authService *auth.AuhtService) *AuthHandler {
	return &AuthHandler{
		AuthService: authService,
	}
}

// Register handler
func (h *AuthHandler) Register(c *fiber.Ctx) error {
	var req types.CreateUser

	// Parse JSON body
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid JSON format",
		})
	}

	// Validate request (optional)
	if req.Email == "" || req.Password == "" {
		return c.Status(400).JSON(fiber.Map{
			"error": "Email and password are required",
		})
	}

	// Call service
	user, err := h.AuthService.Register(c.Context(), req)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error":   "Failed to create user",
			"message": err.Error(),
		})
	}

	// Return response (jangan return password hash!)
	return c.Status(201).JSON(fiber.Map{
		"message": "User created successfully",
		"user": fiber.Map{
			"id":        user.ID,
			"full_name": user.FullName,
			"username":  user.Username,
			"email":     user.Email,
			"status":    user.Status,
		},
	})
}

// Login handler
func (h *AuthHandler) Login(c *fiber.Ctx) error {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid JSON",
		})
	}

	// Login logic here...
	token := "your-jwt-token" // generate JWT

	return c.JSON(fiber.Map{
		"token": token,
		"user": fiber.Map{
			"email": req.Email,
		},
	})
}
