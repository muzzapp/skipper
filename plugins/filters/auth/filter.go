package main

import (
	"fmt"
	"github.com/zalando/skipper/filters"
	dynamo "github.com/zalando/skipper/plugins/filters/auth/internal/repo"
	"log/slog"
	"os"
)

var _ filters.Filter = (*authFilter)(nil)

type authFilter struct {
	repo   *dynamo.Repo
	logger *slog.Logger
}

func (a authFilter) Request(ctx filters.FilterContext) {
	r := ctx.Request()

	// These are the only headers we're interested in
	udid := r.Header.Get("UDID")
	token := r.Header.Get("token")

	// If either header is missing, we don't want anything to break,
	// the downstream servers will handle the lack new headers
	if udid == "" || token == "" {
		return
	}

	// TODO: look in DynamoDB
	repo := dynamo.NewRepo(os.Getenv("DYNAMO_TABLE_NAME"))
	me, err := repo.FindByUdidAndToken(udid, token)
	if err != nil {
		return
	}

	r.Header.Add("x-account-uid", me.AccountUid)
	r.Header.Add("x-account-id", fmt.Sprintf("%d", me.AccountId))
	r.Header.Add("x-marriage-profile-uid", me.MarriageProfileUid)
	r.Header.Add("x-marriage-profile-id", fmt.Sprintf("%d", me.MarriageProfileId))
	r.Header.Add("x-social-uid", me.SocialUid)

	if me.B != "1" {
		r.Header.Add("x-admin-spoof", me.B)
	}
}

func (a authFilter) Response(_ filters.FilterContext) {}
