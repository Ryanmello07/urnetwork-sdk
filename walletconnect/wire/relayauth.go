//go:build !js && !ios_extension

package wire

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// The relay knows a client by an Ed25519 key (relay-client-auth). The client
// presents it as a did:key in a token it signs itself; the relay keeps the
// client's mailbox under that identity, so one key serves a client from its
// first subscribe to its end.

const (
	// did:key in multibase "z" (base58 in the bitcoin alphabet)
	didKeyPrefix = "did:key:z"
	// the did:key of an Ed25519 key is always this long: the two bytes of
	// the multicodec and the 32 of the key make 47 base58 characters
	didKeyLength = len(didKeyPrefix) + 47

	// crypto-authentication: the header of the token, in this byte order
	tokenHeader = `{"alg":"EdDSA","typ":"JWT"}`
	// relay-client-auth: act "must be equal to client_auth"
	relayAuthAction = "client_auth"
)

// the multicodec of an Ed25519 public key, 0xed, as a varint
var ed25519Multicodec = [2]byte{0xed, 0x01}

// the parts of a token are base64 in the url alphabet with no padding. Strict
// decoding refuses a last character with bits that belong to no byte.
var tokenBase64 = base64.RawURLEncoding.Strict()

// ClientKey is the relay client key of a seed (ed25519.NewKeyFromSeed).
func ClientKey(seed Key) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(seed[:])
}

// DidKey is the did:key of an Ed25519 public key: "did:key:z" and the base58
// of the bytes 0xed 0x01 followed by the 32 key bytes.
func DidKey(public ed25519.PublicKey) string {
	identifier := make([]byte, 0, len(ed25519Multicodec)+len(public))
	identifier = append(identifier, ed25519Multicodec[:]...)
	identifier = append(identifier, public...)
	return didKeyPrefix + Base58Encode(identifier)
}

// PublicKeyFromDidKey is the Ed25519 public key a did:key names. Any other
// did, multibase or key type is an error.
//
// Text longer than such a did:key is refused before it is decoded: the
// decoding takes time quadratic in the length, and the text is a claim of a
// token nobody has verified yet.
func PublicKeyFromDidKey(did string) (ed25519.PublicKey, error) {
	if len(did) > didKeyLength {
		return nil, errors.New("walletconnect: the did:key is not an ed25519 key")
	}
	encoded, found := strings.CutPrefix(did, didKeyPrefix)
	if !found {
		return nil, errors.New("walletconnect: not a base58 did:key")
	}
	identifier, err := Base58Decode(encoded)
	if err != nil {
		return nil, errors.New("walletconnect: not a base58 did:key")
	}
	if len(identifier) != len(ed25519Multicodec)+ed25519.PublicKeySize ||
		identifier[0] != ed25519Multicodec[0] || identifier[1] != ed25519Multicodec[1] {
		return nil, errors.New("walletconnect: the did:key is not an ed25519 key")
	}
	return ed25519.PublicKey(identifier[len(ed25519Multicodec):]), nil
}

// RelayClaims is the payload of a relay token. The order of the fields is the
// order of the bytes that are signed; the specification's own signed example
// has it (without act), and a relay verifies whatever bytes it is sent.
type RelayClaims struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Aud string `json:"aud"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
	Act string `json:"act,omitempty"`
}

// SignToken is the token of claims signed with key: the header, the claims
// and the Ed25519 signature of "<header>.<claims>", each in unpadded
// base64url, joined with dots. Ed25519 is deterministic, so the same claims
// and key give the same token.
//
// A key that is not an Ed25519 private key gives "".
func SignToken(claims RelayClaims, key ed25519.PrivateKey) string {
	return signToken(MarshalCompact(claims), key)
}

// signToken signs payload, the JSON of the claims, byte for byte as given.
func signToken(payload []byte, key ed25519.PrivateKey) string {
	if payload == nil || len(key) != ed25519.PrivateKeySize {
		return ""
	}
	data := tokenBase64.EncodeToString([]byte(tokenHeader)) + "." + tokenBase64.EncodeToString(payload)
	return data + "." + tokenBase64.EncodeToString(ed25519.Sign(key, []byte(data)))
}

// VerifyToken reads a token and checks its signature against the key its iss
// names. That is all it checks: whether aud, iat and exp are acceptable is
// for the caller, a relay, to decide.
func VerifyToken(token string) (*RelayClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("walletconnect: a token has three parts")
	}
	headerJson, err := tokenBase64.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("walletconnect: the token's header is not base64url")
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerJson, &header); err != nil || header.Alg != "EdDSA" || header.Typ != "JWT" {
		return nil, errors.New("walletconnect: the token is not an EdDSA JWT")
	}
	claimsJson, err := tokenBase64.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("walletconnect: the token's claims are not base64url")
	}
	claims := &RelayClaims{}
	if err := json.Unmarshal(claimsJson, claims); err != nil {
		return nil, errors.New("walletconnect: the token's claims are not json")
	}
	public, err := PublicKeyFromDidKey(claims.Iss)
	if err != nil {
		return nil, errors.New("walletconnect: the token's iss is not an ed25519 did:key")
	}
	signature, err := tokenBase64.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("walletconnect: the token's signature is not base64url")
	}
	// the signature covers the header too; one of another length than 64
	// bytes does not verify
	if !ed25519.Verify(public, []byte(parts[0]+"."+parts[1]), signature) {
		return nil, errors.New("walletconnect: the token's signature does not verify")
	}
	return claims, nil
}

// RelayAuthBackdateSeconds is how far before now a relay token says it was
// issued, and how far after now it expires: 12 hours each way. The hosted
// relay was measured to refuse a token whose iat is more than about two
// minutes ahead of its own clock, and a phone's clock can run ahead; dated 12
// hours back the token is accepted.
const RelayAuthBackdateSeconds = 43200

// RelayAuthToken is the token for one connection to the relay at the url aud:
// iss the did:key of key, sub the hex of sub, iat nowUnix - 12 h, exp
// nowUnix + 12 h, act "client_auth".
//
// sub is a nonce, 32 fresh random bytes for every connection. aud is the
// relay url as it is dialled, without its query.
//
// A key that is not an Ed25519 private key gives "".
func RelayAuthToken(key ed25519.PrivateKey, aud string, nowUnix int64, sub Key) string {
	if len(key) != ed25519.PrivateKeySize {
		return ""
	}
	public, _ := key.Public().(ed25519.PublicKey)
	return SignToken(RelayClaims{
		Iss: DidKey(public),
		Sub: sub.Hex(),
		Aud: aud,
		Iat: nowUnix - RelayAuthBackdateSeconds,
		Exp: nowUnix + RelayAuthBackdateSeconds,
		Act: relayAuthAction,
	}, key)
}
