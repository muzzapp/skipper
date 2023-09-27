package device_integrity

import (
	"github.com/zalando/skipper/filters"
	"log/slog"
	"os"
)

var Spec filters.Spec = (*attestationSpec)(nil)

type attestationSpec struct{}

func (s *attestationSpec) Name() string {
	return "attestation"
}

func (s *attestationSpec) CreateFilter(_ []interface{}) (filters.Filter, error) {
	slogHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})

	logger := slog.New(slogHandler)

	filter := &attestationFilter{
		logger: logger,
		repo:   NewRepo(os.Getenv("DYNAMO_TABLE_NAME")), // TODO: env name is too generic
	}

	return filter, nil
}
