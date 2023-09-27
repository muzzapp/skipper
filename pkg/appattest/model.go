package appattest

import "time"

type Model struct {
	UDID              string
	Challenge         []byte
	CreatedAt         time.Time `dynamodbav:",unixtime"`
	UpdatedAt         time.Time `dynamodbav:",unixtime"`
	Platform          string
	Headers           string
	RequestBody       string
	ChallengeResponse string
	PublicKey         string
	Counter           uint32
	KeyID             string `dynamodbav:",omitempty"`
	PlatformSuccess   bool   `dynamodbav:",omitempty"`
	NonceSuccess      bool   `dynamodbav:",omitempty"`
	DeviceErrorCode   string `dynamodbav:",omitempty"`
	GoogleResponse    string `dynamodbav:",omitempty"`
	MuzzError         string `dynamodbav:",omitempty"`
}
