package users

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/wafi04/backend/internal/model"
	"github.com/wafi04/backend/pkg/types"
)

type UserRepository struct {
	DB *sql.DB
}

func NewUserService(db *sql.DB) *UserRepository {
	return &UserRepository{
		DB: db,
	}
}

func (s *UserRepository) Create(c context.Context, user *types.CreateUser) (*model.User, error) {
	// Implementasi logika untuk membuat user baru
	query := `
		INSERT INTO users (
			full_name,
			username,
			email,
			password_hash,
			status
		) VALUES (
			$1,
			$2,
			$3,
			$4,
			$5
		) RETURNING id, full_name, username, email, password_hash, status, created_at, updated_at
	`

	// Hash password
	password, err := HashedPassword(user.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	var createdUser model.User
	err = s.DB.QueryRowContext(c, query,
		user.FullName,
		user.Username,
		user.Email,
		password,
		"active",
	).Scan(
		&createdUser.ID,
		&createdUser.FullName,
		&createdUser.Username,
		&createdUser.Email,
		&createdUser.PasswordHash,
		&createdUser.Status,
		&createdUser.CreatedAt,
		&createdUser.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return &createdUser, nil
}

func (s *UserRepository) GetByID(c context.Context, id string) (*model.User, error) {
	return s.getUserBy(c, "id", id)
}

func (s *UserRepository) GetByEmail(c context.Context, email string) (*model.User, error) {
	return s.getUserBy(c, "email", email)
}

func (s *UserRepository) GetByUsername(c context.Context, username string) (*model.User, error) {
	return s.getUserBy(c, "username", username)
}
func (s *UserRepository) GetBlockUsers(c context.Context) (*model.User, error) {
	return s.getUserBy(c, "status", "inactive")
}

func BlockUser(c context.Context, db *sql.DB, id string) error {
	query := `
		UPDATE users
		SET status = 'inactive'
		WHERE id = $1
	`
	_, err := db.ExecContext(c, query, id)
	if err != nil {
		return fmt.Errorf("failed to block user: %w", err)
	}
	return nil
}
