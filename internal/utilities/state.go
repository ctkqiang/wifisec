package utilities

import "github.com/google/uuid"

type Session struct {
	ID string `json:"id"`
}

func NewSession() *Session {
	return &Session{
		ID: uuid.New().String(),
	}
}
