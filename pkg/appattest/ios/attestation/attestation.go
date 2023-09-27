package attestation

import (
	"bytes"
	"compress/zlib"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"github.com/fxamacker/cbor/v2"
	"io"
	"log/slog"
)

func New(
	logger *slog.Logger,
	appleRootCertBytes []byte,
	encodedAttestation string,
	challengeData []byte,
	encodedKeyID string,
) (*Attestation, error) {
	a := Attestation{}
	a.logger = logger

	req, err := a.buildRequest(appleRootCertBytes, encodedAttestation, challengeData, encodedKeyID)
	if err != nil {
		return nil, nil
	}

	a.req = req

	return &a, nil
}

func (a *Attestation) buildRequest(
	appleRootCertBytes []byte,
	encodedAttestation string,
	challengeData []byte,
	encodedKeyID string,
) (*Request, error) {
	var req Request
	req.RootCert = appleRootCertBytes

	decodedAttestationPayload, err := base64.URLEncoding.DecodeString(encodedAttestation)
	a.logger.Debug("attestation payload", "payload", encodedAttestation)
	if err != nil {
		a.logger.Error("cannot decode attestation payload", "error", err)
		return nil, err
	}
	req.DecodedAttestation = decodedAttestationPayload // Still in ZLIB format

	req.ChallengeData = challengeData

	decodedKeyID, err := base64.StdEncoding.DecodeString(encodedKeyID)
	a.logger.Debug("key id payload", "payload", encodedKeyID)
	if err != nil {
		a.logger.Error("cannot decode key id payload", "error", err)
		return nil, err
	}
	req.DecodedKeyID = decodedKeyID

	return &req, nil
}

func (a *Attestation) Parse() error {
	// iOS implements level 5 zlib compression - https://developer.apple.com/documentation/compression/compression_zlib
	// iOS doesn't prepend the zlib magic bytes - so we're adding them, found via https://stackoverflow.com/a/43170354
	decodedAttestationPayload := append([]byte{0x78, 0x5E}, a.req.DecodedAttestation...)

	reader, readerErr := zlib.NewReader(bytes.NewBuffer(decodedAttestationPayload))
	if readerErr != nil {
		return errors.New("cannot create reader")
	}

	var attestationCborData bytes.Buffer
	_, _ = io.Copy(&attestationCborData, reader)
	_ = reader.Close()

	var acbor attestationCbor
	if err := cbor.Unmarshal(attestationCborData.Bytes(), &acbor); err != nil {
		return errors.New("cannot read CBOR data")
	}
	a.attestationCbor = &acbor

	return nil
}

func (a *Attestation) ValidateCertificate() error {
	if a.attestationCbor.Format != "apple-appattest" {
		return errors.New("cbor fmt is not 'apple-appattest'")
	}

	// If x5c is not present, return an error
	if len(a.attestationCbor.AttStmt.X5C) == 0 {
		return errors.New("x5c is not present")
	}

	if len(a.attestationCbor.AttStmt.X5C) != 2 {
		return errors.New("x5c is not of length 2")
	}

	// Step 2. Verify the validity of Apple's certificate chain
	credCert, parseLeafCertErr := x509.ParseCertificate(a.attestationCbor.AttStmt.X5C[0])
	if parseLeafCertErr != nil {
		return errors.New("failed to parse leaf certificate")
	}

	intermediateCert, parseIntermediateCertErr := x509.ParseCertificate(a.attestationCbor.AttStmt.X5C[1])
	if parseIntermediateCertErr != nil {
		return errors.New("failed to parse intermediate certificate")
	}

	intermediaryPool := x509.NewCertPool()
	intermediaryPool.AddCert(intermediateCert)

	rootPool := x509.NewCertPool()
	ok := rootPool.AppendCertsFromPEM(a.req.RootCert)
	if !ok {
		return errors.New("failed to create root certificate pool")
	}

	_, verifyErr := credCert.Verify(
		x509.VerifyOptions{
			DNSName:       "", // Should be empty
			Intermediates: intermediaryPool,
			Roots:         rootPool,
		},
	)

	if verifyErr != nil {
		return errors.New("unable to verify certificate")
	}

	a.credCert = credCert

	return nil
}

func (a *Attestation) ClientHashData() {
	a.clientDataHash = sha256.Sum256(a.req.ChallengeData)
}

func (a *Attestation) GenerateNonce() {
	a.generatedNonce = sha256.Sum256(append(a.attestationCbor.RawAuthData, a.clientDataHash[:]...))
}

func (a *Attestation) CheckAgainstNonce() error {
	var attExtBytes []byte
	for _, ext := range a.credCert.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}) {
			attExtBytes = ext.Value
		}
	}

	if len(attExtBytes) == 0 {
		return errors.New("attestation certificate extensions missing 1.2.840.113635.100.8.2")
	}

	decoded := AppleAnonymousAttestation{}
	if _, err := asn1.Unmarshal(attExtBytes, &decoded); err != nil {
		return errors.New("enable to parse apple attestation certificate extensions")
	}

	if !bytes.Equal(decoded.Nonce, a.generatedNonce[:]) {
		return errors.New("attestation certificate does not contain expected nonce")
	}

	return nil
}

func (a *Attestation) GeneratePublicKey() (*ecdsa.PublicKey, error) {
	pubKey := a.credCert.PublicKey.(*ecdsa.PublicKey)
	publicKeyBytes := elliptic.Marshal(pubKey, pubKey.X, pubKey.Y)
	pubKeyHash := sha256.Sum256(publicKeyBytes)

	if bytes.Equal(pubKeyHash[:], a.req.DecodedKeyID) {
		a.publicKey = pubKey
		return a.publicKey, nil
	}

	return a.publicKey, errors.New("public key hash doesn't match key identifier")
}

func (a *Attestation) CheckAgainstAppID() error {
	possibleAppIds := [][]byte{
		[]byte("5MRWH833JE.com.muzmatch.muzmatch"),
		[]byte("5MRWH833JE.com.muzmatch.muzmatch.alpha"),
	}

	var appID [32]byte
	for _, possibleAppId := range possibleAppIds {
		appID = sha256.Sum256(possibleAppId)
		if bytes.Equal(appID[:], a.attestationCbor.AttAuthData.RPIDHash) {
			return nil
		}
	}

	return errors.New("RPID does not match AppID")
}

func (a *Attestation) CheckCounterIsZero() error {
	if a.attestationCbor.AttAuthData.Counter == 0 {
		return nil
	}

	return errors.New("authenticator data counter field does not equal 0")
}

func (a *Attestation) ValidateAAGUID() error {
	// Is it dev?
	if bytes.Equal([]byte("appattestdevelop"), a.attestationCbor.AttAuthData.AttData.AAGUID) {
		return nil
	}

	// Is it prod?
	if bytes.Equal([]byte("appattest\x00\x00\x00\x00\x00\x00\x00"), a.attestationCbor.AttAuthData.AttData.AAGUID) {
		return nil
	}

	return errors.New("invalid AAGUID provided")
}

func (a *Attestation) ValidateCredentialID() error {
	if bytes.Equal(a.req.DecodedKeyID, a.attestationCbor.AttAuthData.AttData.CredentialID) {
		return nil
	}

	return errors.New("bad credentialID provided")
}
