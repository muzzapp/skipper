package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"google.golang.org/api/option"
	"google.golang.org/api/playintegrity/v1"
)

var (
	//go:embed googleCredentials.json
	googleCredentials []byte
)

type googlePlayIntegrityServiceClient struct {
	logger *slog.Logger
	client *playintegrity.Service
}

func newGooglePlayIntegrityServiceClient(logger *slog.Logger) googlePlayIntegrityServiceClient {
	client, initGoogleServiceErr := playintegrity.NewService(
		context.Background(),
		option.WithCredentialsJSON(googleCredentials),
	)
	if initGoogleServiceErr != nil {
		panic("Failed to init Google Play Integrity Service")
	}

	return googlePlayIntegrityServiceClient{
		logger: logger,
		client: client,
	}
}

func (c googlePlayIntegrityServiceClient) validate(
	token []byte,
	nonce string,
	existingAppAttestation *AttestationModel,
) integrityEvaluation {
	googleResponse, googleErr := c.client.
		V1.
		DecodeIntegrityToken(
			productionAndroidPackageName,
			&playintegrity.DecodeIntegrityTokenRequest{
				IntegrityToken: string(token),
			},
		).
		Do()
	if googleErr != nil {
		googleResp, err := json.Marshal(googleResponse.ServerResponse)
		if err != nil {
			googleResp = []byte("Unable to decode JSON")
		}

		existingAppAttestation.GoogleResponse = string(googleResp)
		existingAppAttestation.PlatformSuccess = false
		existingAppAttestation.MuzzError = "Google threw an error"
		return integrityFailure
	}

	// $appAttestation->setGoogleResponse((string)json_encode($response));
	googleResp, err := json.Marshal(googleResponse.ServerResponse)
	if err != nil {
		googleResp = []byte("Unable to decode JSON")
	}

	existingAppAttestation.GoogleResponse = string(googleResp)

	appVerdict := googleResponse.TokenPayloadExternal.AppIntegrity.AppRecognitionVerdict
	if appVerdict == "UNEVALUATED" {
		existingAppAttestation.PlatformSuccess = false
		existingAppAttestation.MuzzError = "Google app verdict is UNEVALUATED"
		return integrityUnevaluated
	}

	deviceVerdict := googleResponse.TokenPayloadExternal.DeviceIntegrity.DeviceRecognitionVerdict
	certSha256Digest := googleResponse.TokenPayloadExternal.AppIntegrity.CertificateSha256Digest[0]
	requestPackageName := googleResponse.TokenPayloadExternal.RequestDetails.RequestPackageName
	googleNonce := googleResponse.TokenPayloadExternal.RequestDetails.Nonce

	var muzzError []string

	// Check if the signing certificate is invalid
	var certDigestMatch bool
	for _, certDigest := range []string{
		productionAndroidSigningCertDigest,
		debugAndroidSigningCertDigest,
	} {
		if certSha256Digest == certDigest {
			certDigestMatch = true
		}
	}
	if !certDigestMatch {
		muzzError = append(muzzError, "Invalid Android CertificateSha256Digest: "+certSha256Digest)
	}

	if requestPackageName != productionAndroidPackageName && requestPackageName != debugAndroidPackageName {
		muzzError = append(muzzError, "Invalid Android RequestPackageName: "+requestPackageName)
	}

	// Did Google give us confidence in the installation and device?
	var platformSuccess = true

	// Ensure the app has been recognised by the Play Store the package is `com.muzmatch.muzmatchapp`
	if requestPackageName != productionAndroidPackageName {
		if appVerdict != "PLAY_RECOGNIZED" {
			platformSuccess = false
			muzzError = append(muzzError, "Invalid AppRecognitionVerdict: "+appVerdict)
		}
	}

	if deviceVerdict[0] != "MEETS_DEVICE_INTEGRITY" {
		platformSuccess = false
		muzzError = append(muzzError, "Invalid DeviceRecognitionVerdict: "+deviceVerdict[0])
	}

	// Are the nonce values the same?
	var nonceSuccess = true
	if nonce != googleNonce {
		nonceSuccess = false
		muzzError = append(muzzError, fmt.Sprintf("Nonce mismatch: server %q app %q", nonce, googleNonce))
	}

	existingAppAttestation.PlatformSuccess = platformSuccess
	existingAppAttestation.NonceSuccess = nonceSuccess

	if len(muzzError) > 0 {
		existingAppAttestation.MuzzError = strings.Join(muzzError, "\n")
		return integrityFailure
	}

	return integritySuccess
}
