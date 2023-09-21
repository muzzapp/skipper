package main

import (
	"github.com/zalando/skipper/filters"
	"github.com/zalando/skipper/plugins/filters/auth/internal/repo"
	"log"
	"log/slog"
	"os"
)

var _ filters.Spec = (*authSpec)(nil)

type authSpec struct{}

// InitFilter is called by Skipper to create a new instance of the filter when loaded as a plugin
func InitFilter(_ []string) (filters.Spec, error) {
	return &authSpec{}, nil
}

func (s *authSpec) Name() string {
	return "auth"
}

func (s *authSpec) CreateFilter(_ []interface{}) (filters.Filter, error) {
	slogHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})

	logger := slog.New(slogHandler)

	log.Println("1")

	filter := &authFilter{
		repo:   repo.NewRepo(os.Getenv("DYNAMO_TABLE_NAME")),
		logger: logger,
	}

	return filter, nil
}
