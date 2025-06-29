package session

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/wafi04/backend/internal/model"
	"github.com/wafi04/backend/pkg"
	"github.com/wafi04/backend/pkg/types"
)

type VerificationTokens struct {
	DB *sql.DB
}

func NewVerificationTokensService(db *sql.DB) *VerificationTokens {
	return &VerificationTokens{
		DB: db,
	}
}
func (s *VerificationTokens) Create(c context.Context, data *types.CreateVerificationTokens) (*model.VerificationToken, error) {

	query := `
		INSERT INTO verification_tokens (
			id, user_id, token_hash, token_type, expires_at, used_at, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7
		)
		RETURNING id, user_id, token_hash, token_type, expires_at, used_at, created_at
	`

	tokenID, err := pkg.GenerateRandomString(10, "")

	if err != nil {
		return nil, fmt.Errorf("failed to create token id")
	}

	var token model.VerificationToken
	err = s.DB.QueryRowContext(c, query,
		tokenID,
		data.UserID,
		pkg.NewTokenGenerator("token").HashToken("token"),
		data.TokenType,
		data.ExpiresAt,
		data.UsedAt,
		time.Now(),
	).Scan(
		&token.ID,
		&token.UserID,
		&token.TokenHash,
		&token.TokenType,
		&token.ExpiresAt,
		&token.UsedAt,
		&token.CreatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create verification token: %w", err)
	}

	return &token, nil
}
