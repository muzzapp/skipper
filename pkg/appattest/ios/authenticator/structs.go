package authenticator

import (
	"encoding/binary"
)

type AuthenticatorFlags byte

type AttestedCredentialData struct {
	AAGUID              []byte `cbor:"aaguid"`
	CredentialID        []byte `cbor:"credentialId"`
	CredentialPublicKey []byte `cbor:"public_key"` // The raw credential public key bytes received from the attestation data
}

type AuthenticatorData struct {
	RPIDHash []byte                 `cbor:"rpid"`
	Flags    AuthenticatorFlags     `cbor:"flags"`
	Counter  uint32                 `cbor:"sign_count"`
	AttData  AttestedCredentialData `cbor:"att_data"`
	ExtData  []byte                 `cbor:"ext_data"`
}

func (a *AuthenticatorData) Unmarshal(data []byte) error {
	a.RPIDHash = data[:32]

	a.Flags = AuthenticatorFlags(data[32])
	a.Counter = binary.BigEndian.Uint32(data[33:37])

	if len(data) <= 37 {
		return nil
	}

	a.AttData.AAGUID = data[37:53]
	idLength := binary.BigEndian.Uint16(data[53:55])
	a.AttData.CredentialID = data[55 : 55+idLength]
	a.AttData.CredentialPublicKey = data[55+idLength:]

	//minAuthDataLength := 37
	//remaining := len(a.RawAuthData) - minAuthDataLength
	//
	//// Apple didn't read the W3C specification properly and sets the attestedCredentialData flag, while it's not present for an assertion. We'll just look the length...
	//if len(a.RawAuthData) > minAuthDataLength {
	//	a.unmarshalAttestedData(a.RawAuthData)
	//	attDataLen := len(a.AttAuthData.AttData.AAGUID) + 2 + len(a.AttAuthData.AttData.CredentialID) + len(a.AttAuthData.AttData.CredentialPublicKey)
	//	remaining = remaining - attDataLen
	//}
	//
	//if remaining != 0 {
	//	return errors.New("leftover bytes decoding AuthenticatorData")
	//}

	return nil
}
