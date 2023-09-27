package assertation

import (
	"github.com/fxamacker/cbor/v2"
	"github.com/muzzapp/skipper/pkg/appattest/ios/authenticator"
	"log/slog"
)

type Request struct {
	generatedNonce [32]byte

	RawAuthData        []byte
	PublicKey          []byte
	PreviousCounter    uint32
	DecodedKeyID       []byte
	ProvidedChallenge  []byte
	StoredChallenge    []byte
	DecodedAssertation []byte
}

type Assertation struct {
	logger *slog.Logger
	req    *Request

	clientDataHash  [32]byte
	nonce           [32]byte
	generatedNonce  [32]byte
	assertationCbor *assertationCbor
}

type assertationCbor struct {
	AttAuthData authenticator.AuthenticatorData
	Signature   []byte `cbor:"signature"`
	RawAuthData []byte `cbor:"authenticatorData"`
}

func (a *assertationCbor) UnmarshalCBOR(data []byte) error {
	type assertationCborAlias assertationCbor

	aux := &struct {
		*assertationCborAlias
	}{
		assertationCborAlias: (*assertationCborAlias)(a),
	}

	if err := cbor.Unmarshal(data, &aux); err != nil {
		return err
	}

	a.RawAuthData = aux.RawAuthData

	return a.AttAuthData.Unmarshal(a.RawAuthData)
}
