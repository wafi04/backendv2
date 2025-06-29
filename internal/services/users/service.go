package users

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/wafi04/backend/internal/model"
	"github.com/wafi04/backend/pkg"
	"golang.org/x/crypto/bcrypt"
)

type UserService struct {
	DB *sql.DB
}


func NewUserService(db *sql.DB) *UserService {
	return &UserService{
		DB: db,
	}
}


func (s *UserService) Create(c context.Context, user *pkg.CreateUser) (*model.User, error) {
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
	
	// Execute query and scan result
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

func HashedPassword(pass string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}


func (s *UserService) GetByID(c context.Context, id string) (*model.User, error) {
	// Implementasi logika untuk mendapatkan user berdasarkan ID
	query := `
		SELECT id, full_name, username, email, password_hash, status, created_at, updated_at
		FROM users
		WHERE id = $1
	`

	var user model.User
	err := s.DB.QueryRowContext(c, query, id).Scan(
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
		return nil, fmt.Errorf("failed to get user by ID: %w", err)
	}

	return &user, nil
}

func (s *UserService) GetByemail(c context.Context, email string) (*model.User, error) {
	// Implementasi logika untuk mendapatkan user berdasarkan email
	query := `
		SELECT id, full_name, username, email, password_hash, status, created_at, updated_at
		FROM users
		WHERE email = $1
	`
	var user model.User
	err := s.DB.QueryRowContext(c, query, email).Scan(
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
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	return &user, nil
}


func (s *UserService)  GetByUsername(c context.Context, username string) (*model.User, error) {
	// Implementasi logika untuk mendapatkan user berdasarkan username
	query := `
		SELECT id, full_name, username, email, password_hash, status, created_at, updated_at
		FROM users
		WHERE username = $1
	`
	var user model.User
	err := s.DB.QueryRowContext(c, query, username).Scan(
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
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	return &user, nil
}


func GetBlockUser(c context.Context, db *sql.DB) ([]model.User, error) {
	query := `
		SELECT id, full_name, username, email, password_hash, status, created_at, updated_at
		FROM users
		WHERE status = 'inactive'
	`
	rows, err := db.QueryContext(c, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get non-active users: %w", err)
	}
	defer rows.Close()
	var users []model.User
	for rows.Next() {
		var user model.User
		err := rows.Scan(
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
			return nil, fmt.Errorf("failed to scan non-active user: %w", err)
		}
		users = append(users, user)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate non-active users: %w", err)
	}

	return users, nil
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