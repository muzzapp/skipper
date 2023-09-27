package attestation

import (
	"crypto/ecdsa"
	"crypto/x509"
	"github.com/fxamacker/cbor/v2"
	"github.com/muzzapp/skipper/pkg/appattest/ios/authenticator"
	"log/slog"
)

type Request struct {
	RootCert           []byte
	DecodedAttestation []byte
	ChallengeData      []byte
	DecodedKeyID       []byte
	DecodedAppID       []byte
}

type Attestation struct {
	logger *slog.Logger
	req    *Request

	credCert        *x509.Certificate
	attestationCbor *attestationCbor
	clientDataHash  [32]byte
	generatedNonce  [32]byte
	publicKey       *ecdsa.PublicKey
}

type attestationCbor struct {
	AttAuthData authenticator.AuthenticatorData
	Format      string           `cbor:"fmt"`
	AttStmt     appleCborAttStmt `cbor:"attStmt"`
	RawAuthData []byte           `cbor:"authData"`
}

type appleCborAttStmt struct {
	X5C     [][]byte `cbor:"x5c"`
	Receipt []byte   `cbor:"receipt"`
}

type AttestedCredentialData struct {
	AAGUID       []byte `cbor:"aaguid"`
	CredentialID []byte `cbor:"credentialId"`
	// The raw credential public key bytes received from the attestation data
	CredentialPublicKey []byte `cbor:"public_key"`
}

// AppleAnonymousAttestation has not yet publish schema for the extension(as of JULY 2021.)
type AppleAnonymousAttestation struct {
	Nonce []byte `asn1:"tag:1,explicit"`
}

type appleCborCert struct {
	CredCert []byte `cbor:"credCert"`
	CACert   []byte `cbor:"caCert"`
}

func (a *attestationCbor) UnmarshalCBOR(data []byte) error {
	type attestationCborAlias attestationCbor

	aux := &struct {
		*attestationCborAlias
	}{
		attestationCborAlias: (*attestationCborAlias)(a),
	}

	if err := cbor.Unmarshal(data, &aux); err != nil {
		return err
	}

	a.RawAuthData = aux.RawAuthData
	a.Format = aux.Format

	return a.AttAuthData.Unmarshal(a.RawAuthData)
}
