//go:build !js && !ios_extension

package wire

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// Key is 32 bytes: a symmetric key, an X25519 private or public key, or the
// seed of the relay client key. On the wire a key is 64 lower-case hex
// characters.
type Key [32]byte

// NewKey reads a key from rand. A source that fails or runs dry is an error,
// never a partly filled key.
func NewKey(rand io.Reader) (Key, error) {
	if rand == nil {
		return Key{}, errors.New("walletconnect: no random source")
	}
	var key Key
	if _, err := io.ReadFull(rand, key[:]); err != nil {
		return Key{}, fmt.Errorf("walletconnect: random source: %w", err)
	}
	return key, nil
}

// ParseKey reads 64 hex characters of either case.
func ParseKey(hexString string) (Key, error) {
	var key Key
	if len(hexString) != hex.EncodedLen(len(key)) {
		return Key{}, errors.New("walletconnect: a key is 64 hex characters")
	}
	if _, err := hex.Decode(key[:], []byte(hexString)); err != nil {
		return Key{}, errors.New("walletconnect: a key is 64 hex characters")
	}
	return key, nil
}

// Hex is the key as it travels: lower-case hex.
func (k Key) Hex() string {
	return hex.EncodeToString(k[:])
}

// Format makes fmt print a fixed text for a key in place of its bytes, which
// %v would print in decimal and %x in hex, also where the Key is an exported
// field of the value that is printed, a KeyPair or a Pairing.
//
// It is a second line of defence: a key is still never handed to a formatting
// call. fmt asks no method where it reports a misused verb, and prints the
// bytes there: for %w (which vet reports) and for %p of a value that is no
// pointer (which vet does not report for a Key: to it a type with a Format
// method takes any verb). fmt also prints the bytes of a Key in an unexported
// field, and encoding/json writes a Key as its bytes.
func (k Key) Format(state fmt.State, verb rune) {
	io.WriteString(state, "wire.Key(hidden)")
}

// KeyPair is an X25519 key pair (crypto-keys: the keys of the key agreement
// are Curve25519 keys). The dapp makes one per proposal and sends Public in
// it.
type KeyPair struct{ Private, Public Key }

// NewKeyPair reads the private key from rand and derives the public key. The
// 32 bytes are used as they come, as RFC 7748 has it: the scalar is clamped
// when it is used, not when it is stored.
//
// The private key is read here and not by crypto/ecdh's GenerateKey, which
// ignores its reader since Go 1.26: the caller's source decides the key.
func NewKeyPair(rand io.Reader) (*KeyPair, error) {
	private, err := NewKey(rand)
	if err != nil {
		return nil, err
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(private[:])
	if err != nil {
		return nil, fmt.Errorf("walletconnect: x25519: %w", err)
	}
	pair := &KeyPair{Private: private}
	copy(pair.Public[:], privateKey.PublicKey().Bytes())
	return pair, nil
}

// DeriveSymKey is the session key both sides derive after the approval:
// HKDF-SHA256 of X25519(private, peerPublic) with no salt and no info, 32
// bytes. The specification says only that the secret "is hashed using HKDF"
// (crypto-keys); these parameters are the ones ur.io's client uses.
//
// A peer key that yields no secret (a point of small order, for which X25519
// gives all zero bytes) is an error.
func DeriveSymKey(private Key, peerPublic Key) (Key, error) {
	privateKey, err := ecdh.X25519().NewPrivateKey(private[:])
	if err != nil {
		return Key{}, fmt.Errorf("walletconnect: x25519: %w", err)
	}
	publicKey, err := ecdh.X25519().NewPublicKey(peerPublic[:])
	if err != nil {
		return Key{}, fmt.Errorf("walletconnect: x25519: %w", err)
	}
	shared, err := privateKey.ECDH(publicKey)
	if err != nil {
		return Key{}, fmt.Errorf("walletconnect: x25519: %w", err)
	}
	var symKey Key
	derived, err := hkdf.Key(sha256.New, shared, nil, "", len(symKey))
	if err != nil {
		return Key{}, fmt.Errorf("walletconnect: hkdf: %w", err)
	}
	copy(symKey[:], derived)
	return symKey, nil
}

// Topic is the relay topic of a symmetric key: the hex of the sha256 of the
// 32 key bytes (not of their hex text). It names the pairing topic of a
// pairing key and the session topic of a session key.
func Topic(symKey Key) string {
	sum := sha256.Sum256(symKey[:])
	return hex.EncodeToString(sum[:])
}

// MessageId is the relay's id of a message: the hex of the sha256 of the
// message string as published (relay-client-api). Two deliveries of one
// message have one id, which is what a receiver drops duplicates by.
func MessageId(message string) string {
	sum := sha256.Sum256([]byte(message))
	return hex.EncodeToString(sum[:])
}

// ErrEnvelope is what every failure of Open wraps: a message that cannot be
// opened is dropped, whatever was wrong with it.
var ErrEnvelope = errors.New("walletconnect: bad envelope")

const (
	// the one envelope type this client sends and reads
	// (crypto-envelopes): type | iv | ciphertext | tag
	envelopeType0  = 0
	envelopeIvSize = chacha20poly1305.NonceSize
	envelopeMin    = 1 + envelopeIvSize + chacha20poly1305.Overhead
)

// Seal is the type 0 envelope of plaintext under symKey: the byte 0, the 12
// byte iv, and the ChaCha20-Poly1305 ciphertext with its 16 byte tag, in
// padded base64. Nothing is authenticated beside the plaintext: there is no
// associated data, so the type byte is not covered.
//
// An iv must never seal two different messages under one key. Seal takes it
// as an argument so that a known answer can be tested; SealRandom is how a
// message is sealed. A message that is sent again is sent as the string it
// was, not sealed again.
//
// The result is "" only where the cipher itself is refused, which for a key
// of 32 bytes is FIPS 140-only mode, in which no key pair can be made either.
func Seal(symKey Key, iv [12]byte, plaintext []byte) string {
	message, _ := seal(symKey, iv, plaintext)
	return message
}

// SealRandom is Seal with an iv read from rand.
func SealRandom(symKey Key, rand io.Reader, plaintext []byte) (string, error) {
	if rand == nil {
		return "", errors.New("walletconnect: no random source")
	}
	var iv [12]byte
	if _, err := io.ReadFull(rand, iv[:]); err != nil {
		return "", fmt.Errorf("walletconnect: random source: %w", err)
	}
	return seal(symKey, iv, plaintext)
}

func seal(symKey Key, iv [12]byte, plaintext []byte) (string, error) {
	aead, err := chacha20poly1305.New(symKey[:])
	if err != nil {
		return "", fmt.Errorf("walletconnect: cipher: %w", err)
	}
	envelope := make([]byte, 1+len(iv), envelopeMin+len(plaintext))
	envelope[0] = envelopeType0
	copy(envelope[1:], iv[:])
	return EncodeBase64(aead.Seal(envelope, iv[:], plaintext, nil)), nil
}

// Open is the plaintext of a type 0 envelope sealed under symKey. Every
// failure wraps ErrEnvelope: text that is not base64, an envelope too short
// to hold an iv and a tag, a type other than 0 (a type 1 envelope, which
// carries its sender's public key, included), a wrong key, a changed byte.
func Open(symKey Key, message string) ([]byte, error) {
	envelope, err := DecodeBase64(message)
	if err != nil {
		return nil, fmt.Errorf("%w: not base64", ErrEnvelope)
	}
	if len(envelope) == 0 {
		return nil, fmt.Errorf("%w: empty", ErrEnvelope)
	}
	if envelope[0] != envelopeType0 {
		return nil, fmt.Errorf("%w: type %d", ErrEnvelope, envelope[0])
	}
	if len(envelope) < envelopeMin {
		return nil, fmt.Errorf("%w: too short", ErrEnvelope)
	}
	aead, err := chacha20poly1305.New(symKey[:])
	if err != nil {
		return nil, fmt.Errorf("%w: no cipher", ErrEnvelope)
	}
	iv, sealed := envelope[1:1+envelopeIvSize], envelope[1+envelopeIvSize:]
	plaintext, err := aead.Open(nil, iv, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: not authentic", ErrEnvelope)
	}
	return plaintext, nil
}
