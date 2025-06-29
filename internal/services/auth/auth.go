package auth

import (
	"context"

	"github.com/wafi04/backend/internal/model"
	"github.com/wafi04/backend/internal/repository/session"
	"github.com/wafi04/backend/internal/repository/users"
	"github.com/wafi04/backend/pkg/types"
)

type AuhtService struct {
	SessionRepository session.SessionRepository
	UserRepository    users.UserRepository
}

func NewAuthService(session session.SessionRepository, user users.UserRepository) *AuhtService {
	return &AuhtService{
		SessionRepository: session,
		UserRepository:    user,
	}
}

func (s *AuhtService) Register(c context.Context, user types.CreateUser) (*model.User, error) {
	return s.UserRepository.Create(c, &user)
}
