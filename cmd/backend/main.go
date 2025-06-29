package main

import (
	"log"

	"github.com/gofiber/fiber/v2"
	_ "github.com/lib/pq"
	"github.com/wafi04/backend/internal/config"
	"github.com/wafi04/backend/internal/handlers"
	"github.com/wafi04/backend/internal/repository/session"
	"github.com/wafi04/backend/internal/repository/users"
	"github.com/wafi04/backend/internal/services/auth"
)

func Setup(app *fiber.App, authHandler *handlers.AuthHandler) {
	api := app.Group("/api/v1")

	auth := api.Group("/auth")
	auth.Post("/register", authHandler.Register)
	auth.Post("/login", authHandler.Login)
}
func SetupRoutes(app *fiber.App, authHandler *handlers.AuthHandler) {
	api := app.Group("/api/v1")

	// Auth routes
	auth := api.Group("/auth")
	auth.Post("/register", authHandler.Register)
	auth.Post("/login", authHandler.Login)

}
func main() {
	// Load config
	cfg := config.LoadConfig()

	// Setup database
	DB, err := config.NewSetupDatabase(cfg.Database)
	if err != nil {
		log.Fatal("Failed to setup database:", err)
	}
	defer DB.Close()
	sessionRepository := session.NewSessionService(DB)
	userRepository := users.NewUserService(DB)
	authService := auth.NewAuthService(*sessionRepository, *userRepository)
	authHandler := handlers.NewAuthHandler(authService)
	log.Println("Database connected successfully!")
	app := fiber.New()
	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Hello, World!")
	})

	SetupRoutes(app, authHandler)

	app.Listen(":3000")
}
