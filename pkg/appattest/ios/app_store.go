package ios

import (
	"crypto/x509"
	_ "embed"
	"github.com/muzzapp/skipper/pkg/appattest"
	"github.com/muzzapp/skipper/pkg/appattest/ios/assertation"
	"github.com/muzzapp/skipper/pkg/appattest/ios/attestation"
	"log/slog"
)

var (
	//go:embed Apple_App_Attestation_Root_CA.pem
	appleRootCertBytes []byte
)

type AppStore struct {
	req    *attestation.Request
	logger *slog.Logger
}

func NewAppStoreIntegrityServiceClient(logger *slog.Logger) AppStore {
	return AppStore{
		logger: logger,
	}
}

func (as AppStore) ValidateAttestation(
	existingAppAttestation *appattest.Model,
	encodedAttestation string,
	encodedChallengeData []byte,
	encodedKeyID string,
) (appattest.IntegrityEvaluation, error) {
	att, err := attestation.New(
		as.logger,
		appleRootCertBytes,
		encodedAttestation,
		encodedChallengeData,
		encodedKeyID,
	)
	if err != nil {
		as.logger.Error("bad request", "err", err)
		return appattest.IntegrityFailure, err
	}

	if err = att.Parse(); err != nil {
		as.logger.Error("parse fail", "err", err)
		return appattest.IntegrityFailure, err
	}

	// Step 1.
	// Verify that the x5c array contains the intermediate and leaf certificates for App Attest,
	// starting from the credential certificate in the first data buffer in the array (credcert).
	// Verify the validity of the certificates using Apple's App Attest root certificate.
	if err = att.ValidateCertificate(); err != nil {
		as.logger.Error("validate certificate", "err", err)
		return appattest.IntegrityFailure, err
	}

	// Step 2.
	// Create clientDataHash as the SHA256 hash of the one-time challenge your server sends to your app before
	// performing the attestation, and append that hash to the end of the authenticator data
	// (authData from the decoded object).
	att.ClientHashData()

	// Step 3.
	// Generate a new SHA256 hash of the composite item to create nonce.
	att.GenerateNonce()

	// Step 4.
	// Obtain the value of the credCert extension with OID 1.2.840.113635.100.8.2, which is a DER-encoded ASN.1
	// sequence. Decode the sequence and extract the single octet string that it contains.
	// Verify that the string equals nonce.
	if err = att.CheckAgainstNonce(); err != nil {
		as.logger.Error("check against nonce", "err", err)
		return appattest.IntegrityFailure, err
	}

	existingAppAttestation.NonceSuccess = true

	// Step 5.
	// Create the SHA256 hash of the public key in credCert, and verify that it matches the key identifier from your app.
	publicKey, err := att.GeneratePublicKey()
	if err != nil {
		as.logger.Error("generate public key", "err", err)
		return appattest.IntegrityFailure, err
	}

	x509EncodedPub, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		as.logger.Error("failed to stringify public key", "err", err)
		return appattest.IntegrityFailure, err
	}

	existingAppAttestation.PublicKey = string(x509EncodedPub)

	// Step 6.
	// Compute the SHA256 hash of your app's App ID, and verify that it's the same as the authenticator
	// data's RP ID hash.
	if err = att.CheckAgainstAppID(); err != nil {
		as.logger.Error("check against appID", "err", err)
		return appattest.IntegrityFailure, err
	}

	// Step 7.
	// Verify that the authenticator data’s counter field equals 0.
	if err = att.CheckCounterIsZero(); err != nil {
		as.logger.Error("check counter is zero", "err", err)
		return appattest.IntegrityFailure, err
	}

	// Step 8.
	// Verify that the authenticator data’s aaguid field is either appattestdevelop if operating in the
	// development environment, or appattest followed by seven 0x00 bytes if operating in the production environment.
	if err = att.ValidateAAGUID(); err != nil {
		as.logger.Error("validate AAGUID", "err", err)
		return appattest.IntegrityFailure, err
	}

	// Step 9.
	// Verify that the authenticator data’s credentialId field is the same as the key identifier.
	if err = att.ValidateCredentialID(); err != nil {
		as.logger.Error("validate credentialID", "err", err)
		return appattest.IntegrityFailure, err
	}

	existingAppAttestation.PlatformSuccess = true
	return appattest.IntegritySuccess, nil
}

func (as AppStore) ValidateAssertation(
	existingAppAttestation *appattest.Model,
	encodedAssertation string,
	encodedKeyID string,
) (appattest.IntegrityEvaluation, error) {
	ass, err := assertation.New(
		as.logger,
		existingAppAttestation.Challenge,
		encodedAssertation,
		encodedKeyID,
		[]byte(existingAppAttestation.PublicKey),
		existingAppAttestation.Counter,
	)
	if err != nil {
		return appattest.IntegrityFailure, err
	}

	if err = ass.Parse(); err != nil {
		as.logger.Error("assertation parse fail", "err", err)
		return appattest.IntegrityFailure, err
	}

	// Step 1
	// Compute clientDataHash as the SHA256 hash of clientData.
	ass.ClientHashData()

	// Step 2
	// Concatenate authenticatorData and clientDataHash, and apply a SHA256 hash over the result to form nonce.
	ass.GenerateNonce()

	// Step 3
	// Use the public key that you store from the attestation object to verify that the assertion’s signature is valid for nonce.

	// Step 4
	// Compute the SHA256 hash of the client’s App ID, and verify that it matches the RP ID in the authenticator data.
	if err = ass.CheckAgainstAppID(); err != nil {
		as.logger.Error("check against appID", "err", err)
		return appattest.IntegrityFailure, err
	}

	// Step 5
	// Verify that the authenticator data’s counter value is greater than the value from the previous assertion, or greater than 0 on the first assertion.
	if err = ass.CheckCounterIsDifferent(); err != nil {
		as.logger.Error("check counter is not smaller than previous", "err", err)
		return appattest.IntegrityFailure, err
	}

	// Step 6
	// Verify that the embedded challenge in the client data matches the earlier challenge to the client.
	//if err = ass.CompareChallenges(); err != nil {
	//	as.logger.Error("challenge comparison failed", "err", err)
	//	return appattest.IntegrityFailure, err
	//}

	return appattest.IntegritySuccess, nil
}
