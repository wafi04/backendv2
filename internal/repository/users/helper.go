package users

import (
	"context"
	"fmt"

	"github.com/wafi04/backend/internal/model"
	"golang.org/x/crypto/bcrypt"
)

func HashedPassword(pass string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}
func (s *UserRepository) getUserBy(c context.Context, field, value string) (*model.User, error) {
	query := fmt.Sprintf(`
		SELECT id, full_name, username, email, password_hash, status, created_at, updated_at
		FROM users
		WHERE %s = $1
	`, field)

	var user model.User
	err := s.DB.QueryRowContext(c, query, value).Scan(
		&user.ID,
		&user.FullName,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.Status,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to get user by %s: %w", field, err)
	}

	return &user, nil
}
