package assertation

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"github.com/fxamacker/cbor/v2"
	"log/slog"
)

func New(
	logger *slog.Logger,
	storedChallenge []byte,
	encodedAssertation, encodedKeyID string,
	publicKey []byte,
	previousCounter uint32,
) (*Assertation, error) {
	a := Assertation{}
	a.logger = logger

	req, err := a.buildRequest(
		storedChallenge,
		encodedAssertation,
		encodedKeyID,
		publicKey,
		previousCounter,
	)
	if err != nil {
		return nil, err
	}

	a.req = req

	return &a, nil
}

func (a *Assertation) buildRequest(
	storedChallenge []byte,
	encodedAssertation, encodedKeyID string,
	publicKey []byte,
	previousCounter uint32,
) (*Request, error) {
	var req Request
	req.StoredChallenge = storedChallenge

	decodedAssertationPayload, err := base64.URLEncoding.DecodeString(encodedAssertation)
	a.logger.Debug("assertation payload", "payload", encodedAssertation)
	if err != nil {
		a.logger.Error("cannot decode assertation payload", "error", err)
		return nil, err
	}
	req.DecodedAssertation = decodedAssertationPayload // Still in ZLIB format

	decodedKeyID, err := base64.StdEncoding.DecodeString(encodedKeyID)
	a.logger.Debug("key id payload", "payload", encodedKeyID)
	if err != nil {
		a.logger.Error("cannot decode key id payload", "error", err)
		return nil, err
	}
	req.DecodedKeyID = decodedKeyID

	req.PublicKey = publicKey
	req.PreviousCounter = previousCounter

	return &req, nil
}

func (a *Assertation) Parse() error {
	var acbor assertationCbor
	//if err := cbor.Unmarshal(assertationCborData.Bytes(), &acbor); err != nil {
	if err := cbor.Unmarshal(a.req.DecodedAssertation, &acbor); err != nil {
		return errors.New("cannot read CBOR data")
	}
	a.assertationCbor = &acbor

	return nil
}

func (a *Assertation) ClientHashData() {
	a.clientDataHash = sha256.Sum256(a.req.DecodedAssertation)
}

func (a *Assertation) GenerateNonce() {
	a.generatedNonce = sha256.Sum256(append(a.req.RawAuthData, a.clientDataHash[:]...))
}

func (a *Assertation) ValidateAgainstPublicKey() error {
	x, y := elliptic.Unmarshal(elliptic.P256(), a.req.PublicKey)
	if x == nil {
		return errors.New("failed to parse the public key")
	}
	pubkey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}
	nonceHash := sha256.Sum256(a.nonce[:])
	valid := ecdsa.VerifyASN1(pubkey, nonceHash[:], a.assertationCbor.Signature)
	if !valid {
		errors.New("public key hash doesn't match key identifier")
	}

	return nil
}

func (a *Assertation) CheckAgainstAppID() error {
	possibleAppIds := [][]byte{
		[]byte("5MRWH833JE.com.muzmatch.muzmatch"),
		[]byte("5MRWH833JE.com.muzmatch.muzmatch.alpha"),
	}

	var appID [32]byte
	for _, possibleAppId := range possibleAppIds {
		appID = sha256.Sum256(possibleAppId)
		if bytes.Equal(appID[:], a.assertationCbor.AttAuthData.RPIDHash) {
			return nil
		}
	}

	return errors.New("RPID does not match AppID")
}

func (a *Assertation) CheckCounterIsDifferent() error {
	if a.assertationCbor.AttAuthData.Counter > a.req.PreviousCounter {
		return nil
	}

	return errors.New("authenticator data counter field does not equal 0")
}

func (a *Assertation) CompareChallenges() error {
	if bytes.Equal(a.req.StoredChallenge, []byte("")) {
		return nil
	}

	return errors.New("assertation challenge doesn't match attestation challenge")
}
