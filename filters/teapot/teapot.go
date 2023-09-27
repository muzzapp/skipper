package teapot

import (
	"time"
)

type teapotRoute []struct {
	URI     string `json:"uri"`
	Note    string `json:"note,omitempty"`
	IsRegex bool   `json:"regex,omitempty"`
}

type teapotService struct {
	Name   string      `json:"name"`
	Routes teapotRoute `json:"routes"`
}

type teapotConfig struct {
	Enabled         bool              `json:"enabled"`
	Services        []string          `json:"services"`
	IgnoreCountries []string          `json:"ignoreCountries"`
	OnlyCountries   []string          `json:"onlyCountries"`
	Title           map[string]string `json:"title"`
	Message         map[string]string `json:"message"`
	EndsAt          time.Time         `json:"endsAt"`
	ExtendBy        int               `json:"extendBy"`
}

type teapotError struct {
	Status int            `json:"status"`
	Error  teapotResponse `json:"error"`
}

type teapotResponse struct {
	Type                        int     `json:"type"`
	Title                       *string `json:"title"`
	Message                     *string `json:"message"`
	PredictedUptimeTimestampUTC string  `json:"predictedUptimeTimestampUTC"`
	Global                      bool    `json:"global"`
}
