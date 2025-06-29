package session

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/wafi04/backend/internal/config"
	"github.com/wafi04/backend/internal/model"
	"github.com/wafi04/backend/pkg"
	"github.com/wafi04/backend/pkg/types"
)

type SessionRepository struct {
	DB *sql.DB
}

func NewSessionService(DB *sql.DB) *SessionRepository {
	return &SessionRepository{
		DB: DB,
	}
}

func (s *SessionRepository) Create(c context.Context, data *types.CreateSession) (*model.Session, error) {
	query := `
		INSERT INTO sessions
		(
			id,
			user_id,
			token_hash,
			device_info,
			ip_address,
			user_agent,
			is_active,
			expires_at,
			created_at,
			last_used_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7 ,$8, $9,$10
		)
	`
	now := time.Now()
	sessionID, err := pkg.GenerateRandomString(10, "")

	if err != nil {
		return nil, fmt.Errorf("failed to create token id")
	}
	config := config.LoadConfig()
	var secret = config.JWT.SecretKey
	token := pkg.NewTokenGenerator(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to create generate token")

	}
	var session model.Session
	err = s.DB.QueryRowContext(c, query,
		sessionID,
		data.UserID,
		token,
		data.DeviceInfo,
		data.IPAddress,
		data.UserAgent,
		data.IsActive,
		now,
		now,
		now,
	).Scan(
		session.ID,
		session.UserID,
		session.TokenHash,
		session.DeviceInfo,
		session.IPAddress,
		session.UserAgent,
		session.IsActive,
		session.ExpiresAt,
		session.CreatedAt,
		session.LastUsedAt,
	)
	return &session, nil
}
