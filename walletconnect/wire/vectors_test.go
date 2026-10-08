//go:build !js && !ios_extension

package wire

// Fixed vectors of the wire format. Every expected value in this file comes
// from one of
//
//   - an RFC: 7748 (X25519), 5869 (HKDF), 8439 (ChaCha20-Poly1305), 8032
//     (Ed25519), and the SHA-256 "abc" example of FIPS 180;
//   - the WalletConnect specification's own did:key and did-jwt test case
//     (clients/core/crypto/crypto-authentication) and its pairing uri example
//     (clients/core/pairing/pairing-uri);
//   - a fixed-input value computed twice, by ur.io's JavaScript client and by
//     a separate Go program, with the same result both times: the session key
//     and topic, the envelopes, the relay token, the pairing uri and the
//     wallet link;
//   - the namespace verdicts and the grammar cases of ur.io's client tests;
//   - for base58 beyond "Hello World!" and the two did:key examples, a
//     separate program (the string of the whole alphabet is also a test
//     vector of Bitcoin's).
//
// None was produced by the code under test. The keys and tokens below are
// published test values, not credentials.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// RFC 7748 section 6.1
	rfc7748AlicePrivate = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
	rfc7748AlicePublic  = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
	rfc7748BobPrivate   = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
	rfc7748BobPublic    = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
	rfc7748Shared       = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"

	// RFC 5869 appendix A.1 and A.3 (42 bytes each)
	rfc5869A1 = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
	rfc5869A3 = "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"

	// RFC 8439 section 2.8.2
	rfc8439Key        = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
	rfc8439Nonce      = "070000004041424344454647"
	rfc8439Aad        = "50515253c0c1c2c3c4c5c6c7"
	rfc8439Plaintext  = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	rfc8439Ciphertext = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
	rfc8439Tag        = "1ae10b594f09e26a7e902ecbd0600691"

	// RFC 8032 section 7.1, test 1
	rfc8032Seed      = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
	rfc8032Public    = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	rfc8032Signature = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"

	sha256Abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

	// the specification's did:key and did-jwt test case
	relayAuthSeed        = "58e0254c211b858ef7896b00e3f36beeb13d568d47c6031c4218b87718061295"
	relayAuthPublic      = "884ab67f787b69e534bfdba8d5beb4e719700e90ac06317ed177d49e5a33be5a"
	relayAuthDidKey      = "did:key:z6MkodHZwneVRShtaLf8JKYkxpDGp1vGZnpGmdBpX8M2exxH"
	specDidKeyExample    = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
	specDidKeyExampleKey = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
	relayUrl             = "wss://relay.walletconnect.com"
	specDidJwtSub        = "c479fe5dc464e771e78b193d239a65b58d278cad1c34bfb0b5716e5bb514928e"
	specDidJwtIat        = int64(1656910097)
	specDidJwtExp        = int64(1656996497)
	specDidJwt           = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJkaWQ6a2V5Ono2TWtvZEhad25lVlJTaHRhTGY4SktZa3hwREdwMXZHWm5wR21kQnBYOE0yZXh4SCIsInN1YiI6ImM0NzlmZTVkYzQ2NGU3NzFlNzhiMTkzZDIzOWE2NWI1OGQyNzhjYWQxYzM0YmZiMGI1NzE2ZTViYjUxNDkyOGUiLCJhdWQiOiJ3c3M6Ly9yZWxheS53YWxsZXRjb25uZWN0LmNvbSIsImlhdCI6MTY1NjkxMDA5NywiZXhwIjoxNjU2OTk2NDk3fQ.bAKl1swvwqqV_FgwvD4Bx3Yp987B9gTpZctyBviA-EkAuWc8iI8SyokOjkv9GJESgid4U8Tf2foCgrQp2qrxBA"

	// the complete relay token for that seed, sub = ab x 32, iat 1700000000
	// and exp 1700086400
	relayToken        = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJkaWQ6a2V5Ono2TWtvZEhad25lVlJTaHRhTGY4SktZa3hwREdwMXZHWm5wR21kQnBYOE0yZXh4SCIsInN1YiI6ImFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWIiLCJhdWQiOiJ3c3M6Ly9yZWxheS53YWxsZXRjb25uZWN0LmNvbSIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoxNzAwMDg2NDAwLCJhY3QiOiJjbGllbnRfYXV0aCJ9.iPXtjhiwyXXL5D6EquLDAyVIlvuRnLq6dxRqvkOTkQGG8D7GTgE-FzUbPLXypK6fOW6DTekWNRMMxZoBVh-sDg"
	relayTokenPayload = `{"iss":"did:key:z6MkodHZwneVRShtaLf8JKYkxpDGp1vGZnpGmdBpX8M2exxH","sub":"abababababababababababababababababababababababababababababababab","aud":"wss://relay.walletconnect.com","iat":1700000000,"exp":1700086400,"act":"client_auth"}`

	// session key and topic for the RFC 7748 key pairs
	sessionSymKey = "ea1d8a20f476d1e1ec952ca42708b8f7161ce7c81eadf97e520e2b40333decd5"
	sessionTopic  = "1ca1d70db64cab0f93de5934e27f7114e8e9fd7dd3c7145d81ce7f2dd2cd05c8"

	// type 0 envelope
	envelopeSymKey    = "587d5484ce2a2a6ee3ba1962fdd7e8588e06200c46823bd18fbd67def96ad303"
	envelopeIv        = "000102030405060708090a0b"
	envelopePlaintext = `{"id":1,"jsonrpc":"2.0","method":"wc_sessionPing","params":{}}`
	envelope          = "AAABAgMEBQYHCAkKC3HiMqY0z1Wt7IyJExvfAg0VFvvgPzCj/jJKRMH/mL1Uj6qF6fUee6HRog95oLMdxq0fF9oZEGZOUiOw9QLBo5BWJcU6dCbKOKQUS34zzg=="
	envelopeMessageId = "aff7a159634f7e8cb394138f6d62f133e23261a352888c5825868fa9c3098f5b"
	envelopeOfX       = "AAABAgMEBQYHCAkKC3Lf9j22wXkxfqRtEMKyYask"
	// type 1: sender = alice, key = sessionSymKey, plaintext "hello"
	envelopeType1 = "AYUg8AmJMKdUdIt93LQ+91oNvzoNJjga9OukqY6qm05qAAECAwQFBgcICQoLQC6cVGVGBRKQM8kwpGsiyN1vDsNN"

	// pairing
	pairingTopic = "59c972aedb6c86a0b0671be5ab622856e50ac00d51dc80c084e3b2a2f035d434"
	pairingUri   = "wc:59c972aedb6c86a0b0671be5ab622856e50ac00d51dc80c084e3b2a2f035d434@2?relay-protocol=irn&symKey=587d5484ce2a2a6ee3ba1962fdd7e8588e06200c46823bd18fbd67def96ad303&expiryTimestamp=1700000300&methods=[wc_sessionPropose]"
	novaLink     = "novawallet://wc?uri=wc%3A59c972aedb6c86a0b0671be5ab622856e50ac00d51dc80c084e3b2a2f035d434%402%3Frelay-protocol%3Dirn%26symKey%3D587d5484ce2a2a6ee3ba1962fdd7e8588e06200c46823bd18fbd67def96ad303%26expiryTimestamp%3D1700000300%26methods%3D%5Bwc_sessionPropose%5D"
	// the specification's example. Its topic is not sha256 of its symKey.
	specPairingTopic = "7f6e504bfad60b485450578e05678ed3e8e8c4751d3c6160be17160d63ec90f9"
	specPairingUri   = "wc:7f6e504bfad60b485450578e05678ed3e8e8c4751d3c6160be17160d63ec90f9@2?symKey=587d5484ce2a2a6ee3ba1962fdd7e8588e06200c46823bd18fbd67def96ad303&methods=[wc_sessionPropose],[wc_authRequest,wc_authBatchRequest]&relay-protocol=irn&expiryTimestamp=1705667684"

	// namespaces
	solanaChain      = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
	solanaAddress    = "74UNdYRpvakSABaYHSZMQNaXBVtA6f4ZZt1ruFnmcKe7"
	solanaMethod     = "solana_signMessage"
	evmAccount       = "eip155:1:0xab16a96d359ec26a11e2c2b3d8f8b8942d5bfcdb"
	bittensorChain   = "polkadot:2f0555cc76fc2840a25a6ea3b9637146"
	bittensorAddress = "5F3sa2TJAWMqDhXG6jhV4N8ko9SxwGy8TpaNS1repo5EYjQX"
	bittensorMethod  = "polkadot_signMessage"
	// another chain of the polkadot namespace (the Polkadot relay chain)
	polkadotChain = "polkadot:91b171bb158e2d3848fa23a9f1c25182"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex fixture: %v", err)
	}
	return b
}

// mustKey builds a Key without the code under test.
func mustKey(t *testing.T, s string) Key {
	t.Helper()
	b := mustHex(t, s)
	var key Key
	if len(b) != len(key) {
		t.Fatalf("bad key fixture: %d bytes", len(b))
	}
	copy(key[:], b)
	return key
}

func mustIv(t *testing.T, s string) [12]byte {
	t.Helper()
	b := mustHex(t, s)
	var iv [12]byte
	if len(b) != len(iv) {
		t.Fatalf("bad iv fixture: %d bytes", len(b))
	}
	copy(iv[:], b)
	return iv
}

// x25519Shared is the raw X25519 output, by the standard call DeriveSymKey wraps.
func x25519Shared(t *testing.T, privateHex string, publicHex string) []byte {
	t.Helper()
	private, err := ecdh.X25519().NewPrivateKey(mustHex(t, privateHex))
	if err != nil {
		t.Fatalf("private key: %v", err)
	}
	public, err := ecdh.X25519().NewPublicKey(mustHex(t, publicHex))
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	shared, err := private.ECDH(public)
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}
	return shared
}

type failingReader struct{}

func (failingReader) Read(p []byte) (int, error) {
	return 0, errors.New("no entropy")
}

func TestTV1Primitives(t *testing.T) {
	t.Run("RFC 7748 6.1 X25519", func(t *testing.T) {
		// NewKeyPair takes the private key from its reader, unchanged
		alice, err := NewKeyPair(bytes.NewReader(mustHex(t, rfc7748AlicePrivate)))
		if err != nil {
			t.Fatalf("alice: %v", err)
		}
		bob, err := NewKeyPair(bytes.NewReader(mustHex(t, rfc7748BobPrivate)))
		if err != nil {
			t.Fatalf("bob: %v", err)
		}
		if got := alice.Private.Hex(); got != rfc7748AlicePrivate {
			t.Errorf("alice private: got %s, want %s", got, rfc7748AlicePrivate)
		}
		if got := alice.Public.Hex(); got != rfc7748AlicePublic {
			t.Errorf("alice public: got %s, want %s", got, rfc7748AlicePublic)
		}
		if got := bob.Private.Hex(); got != rfc7748BobPrivate {
			t.Errorf("bob private: got %s, want %s", got, rfc7748BobPrivate)
		}
		if got := bob.Public.Hex(); got != rfc7748BobPublic {
			t.Errorf("bob public: got %s, want %s", got, rfc7748BobPublic)
		}
		if got := hex.EncodeToString(x25519Shared(t, rfc7748AlicePrivate, rfc7748BobPublic)); got != rfc7748Shared {
			t.Errorf("shared secret (alice): got %s, want %s", got, rfc7748Shared)
		}
		if got := hex.EncodeToString(x25519Shared(t, rfc7748BobPrivate, rfc7748AlicePublic)); got != rfc7748Shared {
			t.Errorf("shared secret (bob): got %s, want %s", got, rfc7748Shared)
		}
	})

	t.Run("RFC 5869 A.1 and A.3 HKDF-SHA256", func(t *testing.T) {
		ikm := bytes.Repeat([]byte{0x0b}, 22)
		a1, err := hkdf.Key(sha256.New, ikm, mustHex(t, "000102030405060708090a0b0c"), string(mustHex(t, "f0f1f2f3f4f5f6f7f8f9")), 42)
		if err != nil {
			t.Fatalf("A.1: %v", err)
		}
		if got := hex.EncodeToString(a1); got != rfc5869A1 {
			t.Errorf("A.1: got %s, want %s", got, rfc5869A1)
		}
		// A.3 has no salt and no info: the shape the session key uses
		a3, err := hkdf.Key(sha256.New, ikm, nil, "", 42)
		if err != nil {
			t.Fatalf("A.3: %v", err)
		}
		if got := hex.EncodeToString(a3); got != rfc5869A3 {
			t.Errorf("A.3: got %s, want %s", got, rfc5869A3)
		}
	})

	t.Run("RFC 8439 2.8.2 ChaCha20-Poly1305", func(t *testing.T) {
		aead, err := chacha20poly1305.New(mustHex(t, rfc8439Key))
		if err != nil {
			t.Fatalf("cipher: %v", err)
		}
		sealed := aead.Seal(nil, mustHex(t, rfc8439Nonce), []byte(rfc8439Plaintext), mustHex(t, rfc8439Aad))
		if got := hex.EncodeToString(sealed); got != rfc8439Ciphertext+rfc8439Tag {
			t.Errorf("sealed: got %s, want %s", got, rfc8439Ciphertext+rfc8439Tag)
		}

		// Seal is the same cipher with no associated data. The key stream
		// does not depend on the associated data, so the ciphertext is the
		// RFC's; the tag is not.
		sealedEnvelope, err := base64.StdEncoding.DecodeString(Seal(mustKey(t, rfc8439Key), mustIv(t, rfc8439Nonce), []byte(rfc8439Plaintext)))
		if err != nil {
			t.Fatalf("Seal did not return padded base64: %v", err)
		}
		if want := 1 + 12 + len(rfc8439Plaintext) + 16; len(sealedEnvelope) != want {
			t.Fatalf("envelope length: got %d, want %d", len(sealedEnvelope), want)
		}
		if sealedEnvelope[0] != 0 {
			t.Errorf("type byte: got %d, want 0", sealedEnvelope[0])
		}
		if got := hex.EncodeToString(sealedEnvelope[1:13]); got != rfc8439Nonce {
			t.Errorf("iv: got %s, want %s", got, rfc8439Nonce)
		}
		tagAt := 13 + len(rfc8439Plaintext)
		if got := hex.EncodeToString(sealedEnvelope[13:tagAt]); got != rfc8439Ciphertext {
			t.Errorf("ciphertext: got %s, want %s", got, rfc8439Ciphertext)
		}
		withoutAad := aead.Seal(nil, mustHex(t, rfc8439Nonce), []byte(rfc8439Plaintext), nil)
		if !bytes.Equal(sealedEnvelope[13:], withoutAad) {
			t.Errorf("Seal must use no associated data")
		}
		if got := hex.EncodeToString(sealedEnvelope[tagAt:]); got == rfc8439Tag {
			t.Errorf("the tag is the RFC's, so associated data was used")
		}
	})

	t.Run("RFC 8032 7.1 test 1 Ed25519", func(t *testing.T) {
		key := ClientKey(mustKey(t, rfc8032Seed))
		if len(key) != ed25519.PrivateKeySize {
			t.Fatalf("key length: got %d, want %d", len(key), ed25519.PrivateKeySize)
		}
		if got := hex.EncodeToString(key.Seed()); got != rfc8032Seed {
			t.Errorf("seed: got %s, want %s", got, rfc8032Seed)
		}
		public, ok := key.Public().(ed25519.PublicKey)
		if !ok {
			t.Fatalf("public key type: %T", key.Public())
		}
		if got := hex.EncodeToString(public); got != rfc8032Public {
			t.Errorf("public: got %s, want %s", got, rfc8032Public)
		}
		if got := hex.EncodeToString(ed25519.Sign(key, nil)); got != rfc8032Signature {
			t.Errorf("signature of the empty message: got %s, want %s", got, rfc8032Signature)
		}
	})

	t.Run("SHA-256 abc", func(t *testing.T) {
		if got := MessageId("abc"); got != sha256Abc {
			t.Errorf("MessageId: got %s, want %s", got, sha256Abc)
		}
	})
}

func TestTV2Encodings(t *testing.T) {
	t.Run("hex", func(t *testing.T) {
		if got := hex.EncodeToString([]byte{0x00, 0x0f, 0xff}); got != "000fff" {
			t.Errorf("hex: got %s, want 000fff", got)
		}
		key := Key{0x00, 0x0f, 0xff}
		if got, want := key.Hex(), "000fff"+strings.Repeat("00", 29); got != want {
			t.Errorf("Key.Hex: got %s, want %s", got, want)
		}

		parsed, err := ParseKey(envelopeSymKey)
		if err != nil {
			t.Fatalf("ParseKey: %v", err)
		}
		if parsed != mustKey(t, envelopeSymKey) {
			t.Errorf("ParseKey: got %s, want %s", parsed.Hex(), envelopeSymKey)
		}
		// either case on input, lower case on output
		upper, err := ParseKey(strings.ToUpper(envelopeSymKey))
		if err != nil {
			t.Fatalf("ParseKey upper case: %v", err)
		}
		if upper != parsed {
			t.Errorf("ParseKey upper case: got %s, want %s", upper.Hex(), envelopeSymKey)
		}
		if got := upper.Hex(); got != envelopeSymKey {
			t.Errorf("Hex: got %s, want %s", got, envelopeSymKey)
		}

		for name, text := range map[string]string{
			"empty":           "",
			"odd length":      envelopeSymKey[:63],
			"too short":       envelopeSymKey[:62],
			"too long":        envelopeSymKey + "00",
			"not hex":         "zz" + envelopeSymKey[2:],
			"not hex at last": envelopeSymKey[:62] + "zz",
			"0x prefix":       "0x" + envelopeSymKey[2:],
			"space":           " " + envelopeSymKey[1:],
			"not hex, 64 x g": strings.Repeat("g", 64),
		} {
			key, err := ParseKey(text)
			if err == nil {
				t.Errorf("ParseKey %s: no error", name)
				continue
			}
			if key != (Key{}) {
				t.Errorf("ParseKey %s: a key came back with the error", name)
			}
			// a refused key may still be most of a real one
			if len(text) >= 8 && strings.Contains(err.Error(), text[2:]) {
				t.Errorf("ParseKey %s: the error repeats its input", name)
			}
		}
	})

	t.Run("base64", func(t *testing.T) {
		if got := EncodeBase64([]byte("foobar")); got != "Zm9vYmFy" {
			t.Errorf("EncodeBase64 foobar: got %s", got)
		}
		if got := EncodeBase64([]byte("foob")); got != "Zm9vYg==" {
			t.Errorf("EncodeBase64 foob: got %s", got)
		}
		// the standard alphabet, not the url one
		if got := EncodeBase64([]byte{0xfb, 0xff, 0xbf}); got != "+/+/" {
			t.Errorf("EncodeBase64 fb ff bf: got %s", got)
		}
		for text, want := range map[string]string{
			"Zm9vYmFy": "foobar",
			"Zm9vYg==": "foob",
			"Zm9vYg":   "foob", // the padding is optional on input
			"Zm9v":     "foo",
			"":         "",
			"+/+/":     "\xfb\xff\xbf",
		} {
			got, err := DecodeBase64(text)
			if err != nil {
				t.Errorf("DecodeBase64 %q: %v", text, err)
				continue
			}
			if string(got) != want {
				t.Errorf("DecodeBase64 %q: got %q, want %q", text, got, want)
			}
		}
		for _, text := range []string{"!!not base64!!", "-_-_", "Zm9vY", "Zm9v=Yg", "Zm9vYg==x"} {
			if got, err := DecodeBase64(text); err == nil {
				t.Errorf("DecodeBase64 %q: no error, got %q", text, got)
			}
		}

		// the parts of a token: the url alphabet, no padding
		if got := tokenBase64.EncodeToString([]byte("foob")); got != "Zm9vYg" {
			t.Errorf("base64url foob: got %s", got)
		}
		if got := tokenBase64.EncodeToString([]byte{0xfb, 0xff, 0xbf}); got != "-_-_" {
			t.Errorf("base64url fb ff bf: got %s", got)
		}
		if got, err := tokenBase64.DecodeString("_-8"); err != nil || tokenBase64.EncodeToString(got) != "_-8" {
			t.Errorf("base64url _-8: got %x, %v", got, err)
		}
		for _, text := range []string{"Zm9vYg==", "+/+/", "_-9"} {
			if got, err := tokenBase64.DecodeString(text); err == nil {
				t.Errorf("base64url %q: no error, got %x", text, got)
			}
		}
	})

	t.Run("base58", func(t *testing.T) {
		for _, v := range []struct {
			bytesHex string
			text     string
		}{
			{hex.EncodeToString([]byte("Hello World!")), "2NEpo7TZRRrLZSi2U"},
			{"", ""},
			{"61", "2g"},
			{"626262", "a3gV"},
			// leading zero bytes are leading '1' characters
			{"000001", "112"},
			{"00000000000000000000", "1111111111"},
			// every character of the alphabet
			{"000111d38e5fc9071ffcd20b4a763cc9ae4f252bb4e48fd66a835e252ada93ff480d6dd43dc62a641155a5", "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"},
		} {
			if got := Base58Encode(mustHex(t, v.bytesHex)); got != v.text {
				t.Errorf("Base58Encode %s: got %s, want %s", v.bytesHex, got, v.text)
			}
			got, err := Base58Decode(v.text)
			if err != nil {
				t.Errorf("Base58Decode %s: %v", v.text, err)
				continue
			}
			if hex.EncodeToString(got) != v.bytesHex {
				t.Errorf("Base58Decode %s: got %x, want %s", v.text, got, v.bytesHex)
			}
		}
		// 0, O, I and l are not in the alphabet
		for _, text := range []string{"0", "O", "I", "l", "2NEpo7TZRRrLZSi2U!", "2NEpo7 TZRRrLZSi2U", "é"} {
			if got, err := Base58Decode(text); err == nil {
				t.Errorf("Base58Decode %q: no error, got %x", text, got)
			}
		}
	})

	t.Run("an envelope opens with its padding removed", func(t *testing.T) {
		unpadded := strings.TrimRight(envelope, "=")
		if unpadded == envelope {
			t.Fatalf("the fixture has no padding")
		}
		padded, err := DecodeBase64(envelope)
		if err != nil {
			t.Fatalf("DecodeBase64 padded: %v", err)
		}
		bare, err := DecodeBase64(unpadded)
		if err != nil {
			t.Fatalf("DecodeBase64 unpadded: %v", err)
		}
		if !bytes.Equal(padded, bare) || len(bare) != 1+12+len(envelopePlaintext)+16 {
			t.Errorf("DecodeBase64: padded and unpadded differ, or the length is wrong (%d)", len(bare))
		}
		plaintext, err := Open(mustKey(t, envelopeSymKey), unpadded)
		if err != nil {
			t.Fatalf("Open unpadded: %v", err)
		}
		if string(plaintext) != envelopePlaintext {
			t.Errorf("Open unpadded: got %q", plaintext)
		}
	})
}

func TestMarshalCompact(t *testing.T) {
	type inner struct {
		Zeta  string `json:"zeta"`
		Alpha int64  `json:"alpha"`
	}
	type outer struct {
		Text  string          `json:"text"`
		Raw   json.RawMessage `json:"raw"`
		Inner inner           `json:"inner"`
		List  []string        `json:"list"`
		Flag  bool            `json:"flag"`
	}
	got := MarshalCompact(outer{
		Text:  "<a&b>\n\"q\"",
		Raw:   json.RawMessage(`1791419882856123457`),
		Inner: inner{Zeta: "z", Alpha: 1791419882856123457},
		List:  []string{},
		Flag:  true,
	})
	// field order as declared, no html escaping, no space, no trailing newline
	want := `{"text":"<a&b>\n\"q\"","raw":1791419882856123457,"inner":{"zeta":"z","alpha":1791419882856123457},"list":[],"flag":true}`
	if string(got) != want {
		t.Errorf("MarshalCompact:\n got %s\nwant %s", got, want)
	}

	for value, want := range map[any]string{
		"plain":       `"plain"`,
		true:          `true`,
		int64(-7):     `-7`,
		struct{}{}:    `{}`,
		(*inner)(nil): `null`,
	} {
		if got := MarshalCompact(value); string(got) != want {
			t.Errorf("MarshalCompact(%#v): got %s, want %s", value, got, want)
		}
	}
	if got := MarshalCompact(nil); string(got) != "null" {
		t.Errorf("MarshalCompact(nil): got %s, want null", got)
	}

	// what cannot be encoded gives nil, never a panic
	for name, value := range map[string]any{
		"channel":      make(chan int),
		"function":     func() {},
		"bad raw json": json.RawMessage(`{"a":`),
		"panicking":    panickingMarshaler{},
	} {
		if got := MarshalCompact(value); got != nil {
			t.Errorf("MarshalCompact %s: got %s, want nil", name, got)
		}
	}
}

type panickingMarshaler struct{}

func (panickingMarshaler) MarshalJSON() ([]byte, error) {
	panic("boom")
}

func TestTV3RelayAuth(t *testing.T) {
	key := ClientKey(mustKey(t, relayAuthSeed))
	public, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("public key type: %T", key.Public())
	}

	t.Run("did:key", func(t *testing.T) {
		if got := hex.EncodeToString(public); got != relayAuthPublic {
			t.Errorf("public key: got %s, want %s", got, relayAuthPublic)
		}
		if got := DidKey(public); got != relayAuthDidKey {
			t.Errorf("DidKey: got %s, want %s", got, relayAuthDidKey)
		}
		decoded, err := PublicKeyFromDidKey(relayAuthDidKey)
		if err != nil {
			t.Fatalf("PublicKeyFromDidKey: %v", err)
		}
		if !bytes.Equal(decoded, public) {
			t.Errorf("PublicKeyFromDidKey: got %x, want %s", decoded, relayAuthPublic)
		}

		// the specification's example, in both directions
		example, err := PublicKeyFromDidKey(specDidKeyExample)
		if err != nil {
			t.Fatalf("PublicKeyFromDidKey example: %v", err)
		}
		if got := hex.EncodeToString(example); got != specDidKeyExampleKey {
			t.Errorf("PublicKeyFromDidKey example: got %s, want %s", got, specDidKeyExampleKey)
		}
		if got := DidKey(ed25519.PublicKey(mustHex(t, specDidKeyExampleKey))); got != specDidKeyExample {
			t.Errorf("DidKey example: got %s, want %s", got, specDidKeyExample)
		}

		for name, did := range map[string]string{
			"zabc":                  "did:key:zabc",
			"empty":                 "",
			"prefix only":           "did:key:z",
			"no multibase":          "did:key:",
			"another did method":    "did:web:example.com",
			"another multibase":     "did:key:f" + "ed01" + relayAuthPublic,
			"not the base58 set":    "did:key:z0MkodHZwneVRShtaLf8JKYkxpDGp1vGZnpGmdBpX8M2exxH",
			"upper case prefix":     "DID:KEY:z6MkodHZwneVRShtaLf8JKYkxpDGp1vGZnpGmdBpX8M2exxH",
			"x25519 multicodec":     "did:key:z6LSkrCgsrCvBMwAZECC9Q6sSJskqbBXrWk4xazaBK2YT7wf",
			"multicodec ed 02":      "did:key:z6Mm6rbwSaQ6DVSf9RSYXVj4A31o4WZbJztNFg99P3moAvCZ",
			"33 bytes":              "did:key:z2DQX3nSbASG3pWey3BuQQgpa363gCY6nwnbqdHxAzrQ2of",
			"the key with no codec": "did:key:z" + Base58Encode(mustHex(t, relayAuthPublic)),
			"no did:key:z prefix":   strings.TrimPrefix(relayAuthDidKey, "did:key:z"),
		} {
			if got, err := PublicKeyFromDidKey(did); err == nil {
				t.Errorf("PublicKeyFromDidKey %s: no error, got %x", name, got)
			}
		}

		// A did:key that is too long to be one is refused before it is
		// decoded, which would take time quadratic in its length (0.1 s for
		// these 64 KiB) and a thousand allocations. The refusal makes one.
		long := "did:key:z" + strings.Repeat("6", 64<<10)
		if allocations := testing.AllocsPerRun(1, func() { PublicKeyFromDidKey(long) }); allocations > 2 {
			t.Errorf("PublicKeyFromDidKey decodes a did:key of %d characters: %.0f allocations", len(long), allocations)
		}
	})

	specClaims := RelayClaims{
		Iss: relayAuthDidKey,
		Sub: specDidJwtSub,
		Aud: relayUrl,
		Iat: specDidJwtIat,
		Exp: specDidJwtExp,
	}

	t.Run("the specification's did-jwt", func(t *testing.T) {
		if got := SignToken(specClaims, key); got != specDidJwt {
			t.Fatalf("SignToken:\n got %s\nwant %s", got, specDidJwt)
		}
		claims, err := VerifyToken(specDidJwt)
		if err != nil {
			t.Fatalf("VerifyToken: %v", err)
		}
		if *claims != specClaims {
			t.Errorf("VerifyToken: got %+v, want %+v", *claims, specClaims)
		}

		// the last two characters replaced by AA
		tampered := specDidJwt[:len(specDidJwt)-2] + "AA"
		if tampered == specDidJwt {
			t.Fatalf("the fixture already ends in AA")
		}
		if claims, err := VerifyToken(tampered); err == nil {
			t.Errorf("VerifyToken accepted a tampered signature: %+v", claims)
		}
	})

	t.Run("the relay token", func(t *testing.T) {
		sub := mustKey(t, strings.Repeat("ab", 32))
		token := RelayAuthToken(key, relayUrl, 1700043200, sub)
		if token != relayToken {
			t.Fatalf("RelayAuthToken:\n got %s\nwant %s", token, relayToken)
		}
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			t.Fatalf("parts: got %d, want 3", len(parts))
		}
		for i, part := range parts {
			if strings.ContainsAny(part, "+/=") {
				t.Errorf("part %d is not unpadded base64url", i)
			}
		}
		header, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			t.Fatalf("header: %v", err)
		}
		if string(header) != `{"alg":"EdDSA","typ":"JWT"}` {
			t.Errorf("header: got %s", header)
		}
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatalf("payload: %v", err)
		}
		// the claims in the wire order iss, sub, aud, iat, exp, act
		if string(payload) != relayTokenPayload {
			t.Errorf("payload:\n got %s\nwant %s", payload, relayTokenPayload)
		}

		claims, err := VerifyToken(token)
		if err != nil {
			t.Fatalf("VerifyToken: %v", err)
		}
		want := RelayClaims{
			Iss: relayAuthDidKey,
			Sub: strings.Repeat("ab", 32),
			Aud: relayUrl,
			Iat: 1700000000,
			Exp: 1700086400,
			Act: "client_auth",
		}
		if *claims != want {
			t.Errorf("claims: got %+v, want %+v", *claims, want)
		}
		if RelayAuthBackdateSeconds != 43200 {
			t.Errorf("RelayAuthBackdateSeconds: got %d, want 43200", RelayAuthBackdateSeconds)
		}
		if claims.Iat != 1700043200-RelayAuthBackdateSeconds || claims.Exp != 1700043200+RelayAuthBackdateSeconds {
			t.Errorf("iat and exp must be 12 h either side of now: %d, %d", claims.Iat, claims.Exp)
		}

		// aud is whatever url is dialled
		other, err := VerifyToken(RelayAuthToken(key, "wss://relay.walletconnect.org", 1700043200, sub))
		if err != nil {
			t.Fatalf("VerifyToken other host: %v", err)
		}
		if other.Aud != "wss://relay.walletconnect.org" {
			t.Errorf("aud: got %s", other.Aud)
		}
	})

	t.Run("a map-built payload gives a different token", func(t *testing.T) {
		// Go writes map keys sorted, so the signed bytes differ
		payload := MarshalCompact(map[string]any{
			"iss": relayAuthDidKey,
			"sub": specDidJwtSub,
			"aud": relayUrl,
			"iat": specDidJwtIat,
			"exp": specDidJwtExp,
		})
		if !strings.HasPrefix(string(payload), `{"aud":`) {
			t.Fatalf("map payload: got %s", payload)
		}
		token := signToken(payload, key)
		if token == "" || token == specDidJwt {
			t.Fatalf("a map-built payload must give another token than the specification's")
		}
		// it carries the same claims and verifies: only the bytes differ
		claims, err := VerifyToken(token)
		if err != nil {
			t.Fatalf("VerifyToken: %v", err)
		}
		if *claims != specClaims {
			t.Errorf("claims: got %+v, want %+v", *claims, specClaims)
		}
	})

	t.Run("refused tokens", func(t *testing.T) {
		parts := strings.Split(specDidJwt, ".")
		otherKey := ClientKey(mustKey(t, rfc8032Seed))
		otherParts := strings.Split(SignToken(specClaims, otherKey), ".")
		if len(otherParts) != 3 {
			t.Fatalf("SignToken with another key: %d parts", len(otherParts))
		}
		b64 := base64.RawURLEncoding.EncodeToString
		for name, token := range map[string]string{
			"empty":                  "",
			"two parts":              parts[0] + "." + parts[1],
			"four parts":             specDidJwt + "." + parts[2],
			"no signature":           parts[0] + "." + parts[1] + ".",
			"short signature":        parts[0] + "." + parts[1] + "." + parts[2][:40],
			"padded signature":       specDidJwt + "==",
			"header not base64url":   "!!!" + "." + parts[1] + "." + parts[2],
			"payload not base64url":  parts[0] + ".!!!." + parts[2],
			"another payload":        parts[0] + "." + b64([]byte(relayTokenPayload)) + "." + parts[2],
			"another header":         b64([]byte(`{"typ":"JWT","alg":"EdDSA"}`)) + "." + parts[1] + "." + parts[2],
			"signed claims only":     parts[0] + "." + parts[1] + "." + b64(ed25519.Sign(key, []byte(parts[1]))),
			"signature of 63 bytes":  parts[0] + "." + parts[1] + "." + b64(make([]byte, 63)),
			"alg none":               signTokenParts([]byte(`{"alg":"none","typ":"JWT"}`), []byte(relayTokenPayload), key),
			"alg HS256":              signTokenParts([]byte(`{"alg":"HS256","typ":"JWT"}`), []byte(relayTokenPayload), key),
			"typ missing":            signTokenParts([]byte(`{"alg":"EdDSA"}`), []byte(relayTokenPayload), key),
			"header not json":        signTokenParts([]byte(`alg`), []byte(relayTokenPayload), key),
			"payload not json":       signTokenParts([]byte(`{"alg":"EdDSA","typ":"JWT"}`), []byte(`claims`), key),
			"payload not an object":  signTokenParts([]byte(`{"alg":"EdDSA","typ":"JWT"}`), []byte(`null`), key),
			"iss missing":            signToken([]byte(`{"sub":"x","aud":"y","iat":1,"exp":2}`), key),
			"iss not a did:key":      signToken([]byte(`{"iss":"did:web:example.com","sub":"x","aud":"y","iat":1,"exp":2}`), key),
			"signed by another key":  strings.Join(otherParts, "."),
			"signature of other key": parts[0] + "." + parts[1] + "." + otherParts[2],
		} {
			claims, err := VerifyToken(token)
			if err == nil {
				t.Errorf("VerifyToken %s: no error, got %+v", name, claims)
				continue
			}
			if claims != nil {
				t.Errorf("VerifyToken %s: claims came back with the error", name)
			}
			if len(token) > 40 && strings.Contains(err.Error(), token[len(token)-20:]) {
				t.Errorf("VerifyToken %s: the error repeats the token", name)
			}
		}
	})

	t.Run("a key of the wrong length gives no token and no panic", func(t *testing.T) {
		for _, bad := range []ed25519.PrivateKey{nil, {}, make(ed25519.PrivateKey, 32), make(ed25519.PrivateKey, 65)} {
			if got := SignToken(specClaims, bad); got != "" {
				t.Errorf("SignToken with a %d byte key: got %s", len(bad), got)
			}
			if got := RelayAuthToken(bad, relayUrl, 1700043200, Key{}); got != "" {
				t.Errorf("RelayAuthToken with a %d byte key: got %s", len(bad), got)
			}
		}
	})
}

// signTokenParts builds a token from arbitrary header and payload bytes, for
// the refusals VerifyToken must make.
func signTokenParts(header []byte, payload []byte, key ed25519.PrivateKey) string {
	data := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	return data + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(data)))
}

func TestTV4KeysAndEnvelopes(t *testing.T) {
	alicePrivate := mustKey(t, rfc7748AlicePrivate)
	alicePublic := mustKey(t, rfc7748AlicePublic)
	bobPrivate := mustKey(t, rfc7748BobPrivate)
	bobPublic := mustKey(t, rfc7748BobPublic)

	t.Run("session key and topic", func(t *testing.T) {
		fromAlice, err := DeriveSymKey(alicePrivate, bobPublic)
		if err != nil {
			t.Fatalf("DeriveSymKey alice: %v", err)
		}
		if got := fromAlice.Hex(); got != sessionSymKey {
			t.Errorf("DeriveSymKey alice: got %s, want %s", got, sessionSymKey)
		}
		fromBob, err := DeriveSymKey(bobPrivate, alicePublic)
		if err != nil {
			t.Fatalf("DeriveSymKey bob: %v", err)
		}
		if fromBob != fromAlice {
			t.Errorf("DeriveSymKey bob: got %s, want %s", fromBob.Hex(), sessionSymKey)
		}
		// = HKDF-SHA256(the RFC's shared secret, no salt, no info, 32)
		derived, err := hkdf.Key(sha256.New, mustHex(t, rfc7748Shared), nil, "", 32)
		if err != nil {
			t.Fatalf("hkdf: %v", err)
		}
		if got := hex.EncodeToString(derived); got != sessionSymKey {
			t.Errorf("hkdf of the shared secret: got %s, want %s", got, sessionSymKey)
		}
		// the topic hashes the 32 key bytes, not their hex text
		if got := Topic(fromAlice); got != sessionTopic {
			t.Errorf("Topic: got %s, want %s", got, sessionTopic)
		}
	})

	t.Run("a peer key with no shared secret is refused", func(t *testing.T) {
		// u = 0 and u = 1 are points of small order: X25519 gives all zero
		// bytes for them, which is no secret
		for name, peer := range map[string]Key{
			"u = 0": {},
			"u = 1": {1},
		} {
			key, err := DeriveSymKey(alicePrivate, peer)
			if err == nil {
				t.Errorf("DeriveSymKey %s: no error", name)
			}
			if key != (Key{}) {
				t.Errorf("DeriveSymKey %s: a key came back with the error", name)
			}
		}
	})

	symKey := mustKey(t, envelopeSymKey)
	iv := mustIv(t, envelopeIv)

	t.Run("type 0 envelope", func(t *testing.T) {
		sealed := Seal(symKey, iv, []byte(envelopePlaintext))
		if sealed != envelope {
			t.Fatalf("Seal:\n got %s\nwant %s", sealed, envelope)
		}
		if got := MessageId(sealed); got != envelopeMessageId {
			t.Errorf("MessageId: got %s, want %s", got, envelopeMessageId)
		}
		if got := Seal(symKey, iv, []byte("x")); got != envelopeOfX {
			t.Errorf("Seal x: got %s, want %s", got, envelopeOfX)
		}
		// the same inputs give the same string
		if again := Seal(symKey, iv, []byte(envelopePlaintext)); again != sealed {
			t.Errorf("Seal is not deterministic")
		}

		plaintext, err := Open(symKey, envelope)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if string(plaintext) != envelopePlaintext {
			t.Errorf("Open: got %q, want %q", plaintext, envelopePlaintext)
		}

		// an empty plaintext is the shortest envelope: 1 + 12 + 16 bytes
		empty := Seal(symKey, iv, nil)
		raw, err := base64.StdEncoding.DecodeString(empty)
		if err != nil || len(raw) != 29 {
			t.Fatalf("Seal empty: %d bytes, %v", len(raw), err)
		}
		opened, err := Open(symKey, empty)
		if err != nil {
			t.Fatalf("Open empty: %v", err)
		}
		if len(opened) != 0 {
			t.Errorf("Open empty: got %q", opened)
		}
	})

	t.Run("SealRandom takes the iv from its reader", func(t *testing.T) {
		sealed, err := SealRandom(symKey, bytes.NewReader(mustHex(t, envelopeIv)), []byte(envelopePlaintext))
		if err != nil {
			t.Fatalf("SealRandom: %v", err)
		}
		if sealed != envelope {
			t.Errorf("SealRandom:\n got %s\nwant %s", sealed, envelope)
		}

		for name, reader := range map[string]io.Reader{
			"short":   bytes.NewReader(mustHex(t, envelopeIv)[:11]),
			"empty":   bytes.NewReader(nil),
			"failing": failingReader{},
			"nil":     nil,
		} {
			if got, err := SealRandom(symKey, reader, []byte(envelopePlaintext)); err == nil || got != "" {
				t.Errorf("SealRandom with a %s reader: got %q, %v", name, got, err)
			}
		}

		// a fresh iv per message with the real source
		first, err := SealRandom(symKey, cryptorand.Reader, []byte(envelopePlaintext))
		if err != nil {
			t.Fatalf("SealRandom: %v", err)
		}
		second, err := SealRandom(symKey, cryptorand.Reader, []byte(envelopePlaintext))
		if err != nil {
			t.Fatalf("SealRandom: %v", err)
		}
		if first == second {
			t.Errorf("two envelopes of the same plaintext are equal")
		}
		for _, sealed := range []string{first, second} {
			plaintext, err := Open(symKey, sealed)
			if err != nil || string(plaintext) != envelopePlaintext {
				t.Errorf("Open of a SealRandom envelope: %q, %v", plaintext, err)
			}
		}
	})

	t.Run("refused envelopes", func(t *testing.T) {
		raw, err := base64.StdEncoding.DecodeString(envelope)
		if err != nil {
			t.Fatalf("fixture: %v", err)
		}
		reencode := func(edit func(b []byte) []byte) string {
			return base64.StdEncoding.EncodeToString(edit(bytes.Clone(raw)))
		}
		wrongKey := symKey
		wrongKey[0] = 0x68 // 58 in the fixture

		for _, v := range []struct {
			name    string
			key     Key
			message string
		}{
			{"wrong key", wrongKey, envelope},
			{"too short: 00 01 02 03", symKey, base64.StdEncoding.EncodeToString([]byte{0, 1, 2, 3})},
			{"too short: 28 bytes", symKey, base64.StdEncoding.EncodeToString(make([]byte, 28))},
			{"29 zero bytes", symKey, base64.StdEncoding.EncodeToString(make([]byte, 29))},
			{"ciphertext cut by 4 bytes", symKey, reencode(func(b []byte) []byte { return b[:len(b)-4] })},
			{"empty", symKey, ""},
			{"padding only", symKey, "=="},
			{"not base64", symKey, "!!not base64!!"},
			{"base64url", symKey, strings.NewReplacer("+", "-", "/", "_").Replace(envelope)},
			{"type 1", symKey, envelopeType1},
			{"type 1 with its own key", mustKey(t, sessionSymKey), envelopeType1},
			{"type 1: 01 and 40 zero bytes", symKey, base64.StdEncoding.EncodeToString(append([]byte{1}, make([]byte, 40)...))},
			{"type 9", symKey, reencode(func(b []byte) []byte { b[0] = 9; return b })},
			{"type byte changed to 1", symKey, reencode(func(b []byte) []byte { b[0] = 1; return b })},
			{"one extra trailing byte", symKey, reencode(func(b []byte) []byte { return append(b, 0) })},
			{"last byte flipped", symKey, reencode(func(b []byte) []byte { b[len(b)-1] ^= 1; return b })},
			{"iv flipped", symKey, reencode(func(b []byte) []byte { b[1] ^= 1; return b })},
			{"ciphertext flipped", symKey, reencode(func(b []byte) []byte { b[13] ^= 1; return b })},
		} {
			plaintext, err := Open(v.key, v.message)
			if err == nil {
				t.Errorf("Open %s: no error, got %q", v.name, plaintext)
				continue
			}
			if !errors.Is(err, ErrEnvelope) {
				t.Errorf("Open %s: the error does not wrap ErrEnvelope: %v", v.name, err)
			}
			if plaintext != nil {
				t.Errorf("Open %s: bytes came back with the error", v.name)
			}
			if len(v.message) > 20 && strings.Contains(err.Error(), v.message[:20]) {
				t.Errorf("Open %s: the error repeats the message", v.name)
			}
		}
		if ErrEnvelope.Error() != "walletconnect: bad envelope" {
			t.Errorf("ErrEnvelope: got %q", ErrEnvelope.Error())
		}
	})
}

func TestNewKey(t *testing.T) {
	// the reader's bytes are the key
	key, err := NewKey(bytes.NewReader(mustHex(t, envelopeSymKey)))
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	if got := key.Hex(); got != envelopeSymKey {
		t.Errorf("NewKey: got %s, want %s", got, envelopeSymKey)
	}

	first, err := NewKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	second, err := NewKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	if first == second || first == (Key{}) {
		t.Errorf("NewKey: two keys from the real source are equal, or zero")
	}

	firstPair, err := NewKeyPair(cryptorand.Reader)
	if err != nil {
		t.Fatalf("NewKeyPair: %v", err)
	}
	secondPair, err := NewKeyPair(cryptorand.Reader)
	if err != nil {
		t.Fatalf("NewKeyPair: %v", err)
	}
	if firstPair.Private == secondPair.Private || firstPair.Public == secondPair.Public || firstPair.Private == firstPair.Public {
		t.Errorf("NewKeyPair: two pairs from the real source share a key")
	}
	// both sides of a fresh pair agree
	a, err := DeriveSymKey(firstPair.Private, secondPair.Public)
	if err != nil {
		t.Fatalf("DeriveSymKey: %v", err)
	}
	b, err := DeriveSymKey(secondPair.Private, firstPair.Public)
	if err != nil {
		t.Fatalf("DeriveSymKey: %v", err)
	}
	if a != b || a == (Key{}) {
		t.Errorf("the two sides derive different keys")
	}

	// a source that fails or runs dry is an error, never a partly filled key
	for name, reader := range map[string]io.Reader{
		"short":   bytes.NewReader(mustHex(t, envelopeSymKey)[:31]),
		"empty":   bytes.NewReader(nil),
		"failing": failingReader{},
		"nil":     nil,
	} {
		if key, err := NewKey(reader); err == nil || key != (Key{}) {
			t.Errorf("NewKey with a %s reader: got %s, %v", name, key.Hex(), err)
		}
		if pair, err := NewKeyPair(reader); err == nil || pair != nil {
			t.Errorf("NewKeyPair with a %s reader: got %v, %v", name, pair != nil, err)
		}
	}
}

// A formatting verb prints a fixed text for a key, by itself or as a field of
// what is printed, and never its bytes.
func TestKeyFormat(t *testing.T) {
	var key Key
	for i := range key {
		// 161 to 192, a1 to c0: nothing else the values below print has the
		// decimal or the hex form of one of these bytes in it
		key[i] = 0xa1 + byte(i)
	}
	shows := func(text string) bool {
		text = strings.ToLower(text)
		for _, b := range key {
			if strings.Contains(text, strconv.Itoa(int(b))) || strings.Contains(text, hex.EncodeToString([]byte{b})) {
				return true
			}
		}
		return false
	}
	for _, v := range []struct {
		value any
		keys  int
	}{
		{key, 1},
		{&KeyPair{Private: key, Public: key}, 2},
		{&Pairing{SymKey: key, Topic: "t", ExpiryUnix: 5}, 1},
	} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%d", "%x", "%s"} {
			got := fmt.Sprintf(verb, v.value)
			if strings.Count(got, "wire.Key(hidden)") != v.keys || shows(got) {
				t.Errorf("%s of a %T: got %s", verb, v.value, got)
			}
		}
	}
}

func TestTV5PairingUri(t *testing.T) {
	symKey := mustKey(t, envelopeSymKey)

	t.Run("the uri is built by hand", func(t *testing.T) {
		if got := Topic(symKey); got != pairingTopic {
			t.Fatalf("Topic: got %s, want %s", got, pairingTopic)
		}
		// without a topic the uri names the key's own
		if got := (&Pairing{SymKey: symKey, ExpiryUnix: 1700000300}).Uri(); got != pairingUri {
			t.Errorf("Uri:\n got %s\nwant %s", got, pairingUri)
		}
		if got := (&Pairing{SymKey: symKey, Topic: pairingTopic, ExpiryUnix: 1700000300}).Uri(); got != pairingUri {
			t.Errorf("Uri with its topic:\n got %s\nwant %s", got, pairingUri)
		}
		// percent-encoded once as a whole, it is the value of a wallet link
		if got := "novawallet://wc?uri=" + url.QueryEscape(pairingUri); got != novaLink {
			t.Errorf("wallet link:\n got %s\nwant %s", got, novaLink)
		}
	})

	t.Run("NewPairing", func(t *testing.T) {
		pairing, err := NewPairing(bytes.NewReader(mustHex(t, envelopeSymKey)), 1700000000)
		if err != nil {
			t.Fatalf("NewPairing: %v", err)
		}
		if pairing.SymKey != symKey {
			t.Errorf("SymKey: got %s, want %s", pairing.SymKey.Hex(), envelopeSymKey)
		}
		if pairing.ExpiryUnix != 1700000300 {
			t.Errorf("ExpiryUnix: got %d, want 1700000300", pairing.ExpiryUnix)
		}
		if pairing.Topic != Topic(pairing.SymKey) || pairing.Topic != pairingTopic {
			t.Errorf("Topic: got %s, want %s", pairing.Topic, pairingTopic)
		}
		if got := pairing.Uri(); got != pairingUri {
			t.Errorf("Uri:\n got %s\nwant %s", got, pairingUri)
		}

		first, err := NewPairing(cryptorand.Reader, 1700000000)
		if err != nil {
			t.Fatalf("NewPairing: %v", err)
		}
		second, err := NewPairing(cryptorand.Reader, 1700000000)
		if err != nil {
			t.Fatalf("NewPairing: %v", err)
		}
		if first.SymKey == second.SymKey || first.Topic == second.Topic || first.Topic != Topic(first.SymKey) {
			t.Errorf("NewPairing: two pairings share a key or a topic")
		}

		if pairing, err := NewPairing(failingReader{}, 1700000000); err == nil || pairing != nil {
			t.Errorf("NewPairing with a failing reader: got %v, %v", pairing != nil, err)
		}
	})

	t.Run("round trip", func(t *testing.T) {
		parsed, err := ParsePairingUri(pairingUri)
		if err != nil {
			t.Fatalf("ParsePairingUri: %v", err)
		}
		want := Pairing{SymKey: symKey, Topic: pairingTopic, ExpiryUnix: 1700000300}
		if *parsed != want {
			t.Errorf("ParsePairingUri: got %s %s %d", parsed.SymKey.Hex(), parsed.Topic, parsed.ExpiryUnix)
		}
		if got := parsed.Uri(); got != pairingUri {
			t.Errorf("Uri of the parsed pairing:\n got %s\nwant %s", got, pairingUri)
		}

		// a wallet link's value, unwrapped by the caller
		unwrapped, err := url.QueryUnescape(strings.TrimPrefix(novaLink, "novawallet://wc?uri="))
		if err != nil {
			t.Fatalf("unescape: %v", err)
		}
		fromLink, err := ParsePairingUri(unwrapped)
		if err != nil {
			t.Fatalf("ParsePairingUri of the unwrapped link: %v", err)
		}
		if *fromLink != want {
			t.Errorf("ParsePairingUri of the unwrapped link: got %s %s %d", fromLink.SymKey.Hex(), fromLink.Topic, fromLink.ExpiryUnix)
		}
	})

	t.Run("what a parse tolerates", func(t *testing.T) {
		query := "relay-protocol=irn&symKey=" + envelopeSymKey
		for _, v := range []struct {
			name   string
			uri    string
			topic  string
			expiry int64
		}{
			// the specification's example: another parameter order, two
			// method groups, a topic that is not sha256 of the key
			{"the specification's example", specPairingUri, specPairingTopic, 1705667684},
			{"brackets percent-encoded", "wc:" + pairingTopic + "@2?" + query + "&expiryTimestamp=1700000300&methods=%5Bwc_sessionPropose%5D", pairingTopic, 1700000300},
			{"unknown parameters", "wc:" + pairingTopic + "@2?future=1&" + query + "&flag&expiryTimestamp=1700000300&x=%zz&methods=[wc_sessionPropose]&", pairingTopic, 1700000300},
			{"no expiry and no methods", "wc:" + pairingTopic + "@2?" + query, pairingTopic, 0},
			{"upper case key", "wc:" + pairingTopic + "@2?relay-protocol=irn&symKey=" + strings.ToUpper(envelopeSymKey), pairingTopic, 0},
			{"percent-encoded values", "wc:" + pairingTopic + "@2?relay-protocol=%69rn&symKey=%35" + envelopeSymKey[1:] + "&expiryTimestamp=%31700000300", pairingTopic, 1700000300},
			{"a short topic", "wc:aa@2?" + query, "aa", 0},
			{"a parameter twice: the last one counts", "wc:" + pairingTopic + "@2?relay-protocol=waku&symKey=" + sessionSymKey + "&expiryTimestamp=1&" + query + "&expiryTimestamp=1700000300", pairingTopic, 1700000300},
		} {
			parsed, err := ParsePairingUri(v.uri)
			if err != nil {
				t.Errorf("ParsePairingUri %s: %v", v.name, err)
				continue
			}
			if parsed.SymKey != symKey || parsed.Topic != v.topic || parsed.ExpiryUnix != v.expiry {
				t.Errorf("ParsePairingUri %s: got %s %s %d", v.name, parsed.SymKey.Hex(), parsed.Topic, parsed.ExpiryUnix)
			}
		}

		// the topic a uri names is kept, and written again
		example, err := ParsePairingUri(specPairingUri)
		if err != nil {
			t.Fatalf("ParsePairingUri: %v", err)
		}
		wantUri := "wc:" + specPairingTopic + "@2?relay-protocol=irn&symKey=" + envelopeSymKey + "&expiryTimestamp=1705667684&methods=[wc_sessionPropose]"
		if got := example.Uri(); got != wantUri {
			t.Errorf("Uri of the example:\n got %s\nwant %s", got, wantUri)
		}
		// a pairing with no expiry writes none
		bare := &Pairing{SymKey: symKey, Topic: pairingTopic}
		wantUri = "wc:" + pairingTopic + "@2?relay-protocol=irn&symKey=" + envelopeSymKey + "&methods=[wc_sessionPropose]"
		if got := bare.Uri(); got != wantUri {
			t.Errorf("Uri with no expiry:\n got %s\nwant %s", got, wantUri)
		}
	})

	t.Run("refused uris", func(t *testing.T) {
		query := "relay-protocol=irn&symKey=" + envelopeSymKey
		for name, uri := range map[string]string{
			"empty":                 "",
			"no relay-protocol":     "wc:" + pairingTopic + "@2?symKey=" + envelopeSymKey,
			"empty relay-protocol":  "wc:" + pairingTopic + "@2?relay-protocol=&symKey=" + envelopeSymKey,
			"no symKey":             "wc:" + pairingTopic + "@2?relay-protocol=irn",
			"empty symKey":          "wc:" + pairingTopic + "@2?relay-protocol=irn&symKey=",
			"empty topic":           "wc:@2?" + query,
			"no version":            "wc:" + pairingTopic + "?" + query,
			"empty version":         "wc:" + pairingTopic + "@?" + query,
			"scheme ws":             "ws:" + pairingTopic + "@2?" + query,
			"scheme in upper case":  "WC:" + pairingTopic + "@2?" + query,
			"topic not hex":         "wc:zz@2?" + query,
			"topic with a space":    "wc:" + pairingTopic[:62] + " a@2?" + query,
			"no query":              "wc:" + pairingTopic + "@2",
			"still percent-encoded": url.QueryEscape(pairingUri),
			"a wallet link":         novaLink,
			// what the Pairing type cannot hold
			"a short symKey":            "wc:aa@2?symKey=bb&relay-protocol=irn",
			"symKey not hex":            "wc:" + pairingTopic + "@2?relay-protocol=irn&symKey=" + strings.Repeat("zz", 32),
			"symKey bad escape":         "wc:" + pairingTopic + "@2?relay-protocol=irn&symKey=%zz" + envelopeSymKey[3:],
			"version 1":                 "wc:" + pairingTopic + "@1?" + query,
			"version 3":                 "wc:" + pairingTopic + "@3?" + query,
			"version not a number":      "wc:" + pairingTopic + "@two?" + query,
			"another relay protocol":    "wc:" + pairingTopic + "@2?relay-protocol=waku&symKey=" + envelopeSymKey,
			"expiry not a number":       "wc:" + pairingTopic + "@2?" + query + "&expiryTimestamp=soon",
			"expiry negative":           "wc:" + pairingTopic + "@2?" + query + "&expiryTimestamp=-5",
			"expiry empty":              "wc:" + pairingTopic + "@2?" + query + "&expiryTimestamp=",
			"expiry beyond 64 bits":     "wc:" + pairingTopic + "@2?" + query + "&expiryTimestamp=99999999999999999999",
			"expiry with a fraction":    "wc:" + pairingTopic + "@2?" + query + "&expiryTimestamp=1700000300.5",
			"relay-protocol bad escape": "wc:" + pairingTopic + "@2?relay-protocol=%4&symKey=" + envelopeSymKey,
		} {
			pairing, err := ParsePairingUri(uri)
			if err == nil {
				t.Errorf("ParsePairingUri %s: no error", name)
				continue
			}
			if pairing != nil {
				t.Errorf("ParsePairingUri %s: a pairing came back with the error", name)
			}
			// the uri holds the pairing key: an error never repeats any of it
			if strings.Contains(err.Error(), envelopeSymKey[:16]) || strings.Contains(err.Error(), pairingTopic[:16]) {
				t.Errorf("ParsePairingUri %s: the error repeats the uri: %v", name, err)
			}
		}
	})
}

func TestTV6Namespaces(t *testing.T) {
	const (
		allNamespaces  = "All namespaces must be approved"
		accountsEmpty  = "Accounts must not be empty"
		accountsCaip10 = "Accounts must be CAIP-10 compliant"
		accountsMatch  = "Accounts must be defined in matching namespace"
		allMethods     = "All methods must be approved"
		allChains      = "All chains must have at least one account"
	)
	solanaAccount := solanaChain + ":" + solanaAddress
	solanaOther := "solana:othernet:" + solanaAddress
	bittensorAccount := bittensorChain + ":" + bittensorAddress
	polkadotAccount := polkadotChain + ":" + bittensorAddress

	one := func(key string, namespace *Namespace) map[string]*Namespace {
		return map[string]*Namespace{key: namespace}
	}

	t.Run("ValidateNamespaces", func(t *testing.T) {
		for _, v := range []struct {
			name     string
			key      string
			chain    string
			method   string
			approved map[string]*Namespace
			code     int // 0 = valid
			message  string
		}{
			// the specification's cases, as ur.io's client tests them
			{"valid, with one more method and an event", "solana", solanaChain, solanaMethod,
				one("solana", &Namespace{Accounts: []string{solanaAccount}, Methods: []string{solanaMethod, "solana_signTransaction"}, Events: []string{"x"}}),
				0, ""},
			{"no namespace at all", "solana", solanaChain, solanaMethod,
				map[string]*Namespace{},
				5000, allNamespaces},
			{"nil", "solana", solanaChain, solanaMethod,
				nil,
				5000, allNamespaces},
			{"the namespace is null", "solana", solanaChain, solanaMethod,
				one("solana", nil),
				5000, allNamespaces},
			{"only another namespace", "solana", solanaChain, solanaMethod,
				one("eip155", &Namespace{Accounts: []string{evmAccount}, Methods: []string{solanaMethod}}),
				5000, allNamespaces},
			{"the key in another case", "solana", solanaChain, solanaMethod,
				one("Solana", &Namespace{Accounts: []string{solanaAccount}, Methods: []string{solanaMethod}}),
				5000, allNamespaces},
			{"no accounts", "solana", solanaChain, solanaMethod,
				one("solana", &Namespace{Accounts: []string{}, Methods: []string{solanaMethod}, Events: []string{}}),
				5001, accountsEmpty},
			{"an account that is not CAIP-10", "solana", solanaChain, solanaMethod,
				one("solana", &Namespace{Accounts: []string{"solana:" + solanaAddress}, Methods: []string{solanaMethod}}),
				5001, accountsCaip10},
			{"no method", "solana", solanaChain, solanaMethod,
				one("solana", &Namespace{Accounts: []string{solanaAccount}, Methods: []string{}, Events: []string{}}),
				5002, allMethods},
			{"another method only", "solana", solanaChain, solanaMethod,
				one("solana", &Namespace{Accounts: []string{solanaAccount}, Methods: []string{"solana_signTransaction", "Solana_SignMessage"}}),
				5002, allMethods},
			{"an account on another chain only", "solana", solanaChain, solanaMethod,
				one("solana", &Namespace{Accounts: []string{solanaOther}, Methods: []string{solanaMethod}}),
				5001, allChains},
			{"an account of another namespace", "solana", solanaChain, solanaMethod,
				one("solana", &Namespace{Accounts: []string{evmAccount}, Methods: []string{solanaMethod}}),
				5103, accountsMatch},
			{"an account on the chain and one on another", "solana", solanaChain, solanaMethod,
				one("solana", &Namespace{Accounts: []string{solanaAccount, solanaOther}, Methods: []string{solanaMethod}}),
				0, ""},
			{"the other chain's account first", "solana", solanaChain, solanaMethod,
				one("solana", &Namespace{Accounts: []string{solanaOther, solanaAccount}, Methods: []string{solanaMethod}}),
				0, ""},
			{"a key that is a chain id", "eip155:10", "eip155:10", "personal_sign",
				one("eip155:10", &Namespace{Accounts: []string{"eip155:10:0xab16a96d359ec26a11e2c2b3d8f8b8942d5bfcdb"}, Methods: []string{"personal_sign"}}),
				0, ""},
			{"more namespaces than asked for", "solana", solanaChain, solanaMethod,
				map[string]*Namespace{
					"solana": {Accounts: []string{solanaAccount}, Methods: []string{solanaMethod}},
					"eip155": {Accounts: []string{"not an account"}},
					"cosmos": nil,
				},
				0, ""},

			// the order of the checks
			{"accounts are checked before methods", "solana", solanaChain, solanaMethod,
				one("solana", &Namespace{Events: []string{"x"}}),
				5001, accountsEmpty},
			{"the namespace of an account before the method", "solana", solanaChain, solanaMethod,
				one("solana", &Namespace{Accounts: []string{evmAccount}}),
				5103, accountsMatch},
			{"the method before the chain", "solana", solanaChain, solanaMethod,
				one("solana", &Namespace{Accounts: []string{solanaOther}}),
				5002, allMethods},
			{"account by account: namespace of the first, then form of the second", "solana", solanaChain, solanaMethod,
				one("solana", &Namespace{Accounts: []string{evmAccount, "garbage"}, Methods: []string{solanaMethod}}),
				5103, accountsMatch},
			{"account by account: form of the first", "solana", solanaChain, solanaMethod,
				one("solana", &Namespace{Accounts: []string{"garbage", evmAccount}, Methods: []string{solanaMethod}}),
				5001, accountsCaip10},
			{"a bad account after a good one", "solana", solanaChain, solanaMethod,
				one("solana", &Namespace{Accounts: []string{solanaAccount, ""}, Methods: []string{solanaMethod}}),
				5001, accountsCaip10},

			// a chain and a method are always required
			{"no chain asked for", "solana", "", solanaMethod,
				one("solana", &Namespace{Accounts: []string{solanaAccount}, Methods: []string{solanaMethod}}),
				5001, allChains},
			{"no method asked for", "solana", solanaChain, "",
				one("solana", &Namespace{Accounts: []string{solanaAccount}, Methods: []string{solanaMethod}}),
				5002, allMethods},

			// this client's own proposal
			{"bittensor", "polkadot", bittensorChain, bittensorMethod,
				one("polkadot", &Namespace{Chains: []string{bittensorChain}, Accounts: []string{bittensorAccount}, Methods: []string{bittensorMethod}, Events: []string{}}),
				0, ""},
			{"bittensor after polkadot", "polkadot", bittensorChain, bittensorMethod,
				one("polkadot", &Namespace{Accounts: []string{polkadotAccount, bittensorAccount}, Methods: []string{"polkadot_signTransaction", bittensorMethod}}),
				0, ""},
			{"polkadot only", "polkadot", bittensorChain, bittensorMethod,
				one("polkadot", &Namespace{Accounts: []string{polkadotAccount}, Methods: []string{bittensorMethod}}),
				5001, allChains},
			{"the chain listed with no account on it", "polkadot", bittensorChain, bittensorMethod,
				one("polkadot", &Namespace{Chains: []string{bittensorChain}, Accounts: []string{polkadotAccount}, Methods: []string{bittensorMethod}}),
				5001, allChains},
			{"bittensor without the method", "polkadot", bittensorChain, bittensorMethod,
				one("polkadot", &Namespace{Accounts: []string{bittensorAccount}, Methods: []string{"polkadot_signTransaction"}}),
				5002, allMethods},
		} {
			err := ValidateNamespaces(v.key, v.chain, v.method, v.approved)
			if v.code == 0 {
				if err != nil {
					t.Errorf("%s: got %d %q, want valid", v.name, err.Code, err.Message)
				}
				continue
			}
			if err == nil {
				t.Errorf("%s: valid, want %d %q", v.name, v.code, v.message)
				continue
			}
			if err.Code != v.code || err.Message != v.message {
				t.Errorf("%s: got %d %q, want %d %q", v.name, err.Code, err.Message, v.code, v.message)
			}
			if err.Error() != v.message {
				t.Errorf("%s: Error() is %q, want %q", v.name, err.Error(), v.message)
			}
		}
	})

	t.Run("namespaces as a settle carries them", func(t *testing.T) {
		for _, v := range []struct {
			text    string
			code    int
			message string
		}{
			{`{"polkadot":{"accounts":["` + bittensorAccount + `"],"methods":["polkadot_signMessage"],"events":[]}}`, 0, ""},
			{`{"polkadot":{"chains":["` + bittensorChain + `"],"accounts":["` + polkadotAccount + `","` + bittensorAccount + `"],"methods":["polkadot_signTransaction","polkadot_signMessage"],"events":["accountsChanged"]},"eip155":{"accounts":[],"methods":[],"events":[]}}`, 0, ""},
			{`null`, 5000, allNamespaces},
			{`{}`, 5000, allNamespaces},
			{`{"polkadot":null}`, 5000, allNamespaces},
			{`{"polkadot":{}}`, 5001, accountsEmpty},
			{`{"polkadot":{"accounts":null,"methods":null,"events":null}}`, 5001, accountsEmpty},
			{`{"polkadot":{"accounts":["` + bittensorAccount + `"]}}`, 5002, allMethods},
			{`{"polkadot":{"accounts":["` + bittensorAccount + `"],"methods":null}}`, 5002, allMethods},
		} {
			var approved map[string]*Namespace
			if err := json.Unmarshal([]byte(v.text), &approved); err != nil {
				t.Errorf("%s: %v", v.text, err)
				continue
			}
			err := ValidateNamespaces("polkadot", bittensorChain, bittensorMethod, approved)
			switch {
			case v.code == 0 && err != nil:
				t.Errorf("%s: got %d %q, want valid", v.text, err.Code, err.Message)
			case v.code != 0 && err == nil:
				t.Errorf("%s: valid, want %d %q", v.text, v.code, v.message)
			case v.code != 0 && (err.Code != v.code || err.Message != v.message):
				t.Errorf("%s: got %d %q, want %d %q", v.text, err.Code, err.Message, v.code, v.message)
			}
		}
	})

	t.Run("CAIP-2 and CAIP-10 grammar", func(t *testing.T) {
		for text, want := range map[string]bool{
			"eip155:1":                          true,
			solanaChain:                         true,
			bittensorChain:                      true, // a reference of 32 characters, the longest
			polkadotChain:                       true,
			"abc:1":                             true, // 3 to 8 characters before the colon
			"abcdefgh:1":                        true,
			"a-1:x_Y-9":                         true,
			"42":                                false,
			"EIP155:1":                          false,
			"ab:1":                              false,
			"abcdefghi:1":                       false,
			"eip155:" + strings.Repeat("a", 33): false,
			"":                                  false,
			":":                                 false,
			"eip155:":                           false,
			":1":                                false,
			"eip_155:1":                         false,
			"eip155:1.0":                        false,
			"eip155:1:":                         false,
			"eip155:1:0xab":                     false,
			"eip155:1\n":                        false,
			" eip155:1":                         false,
			"eip155:é":                          false,
		} {
			if got := IsCaip2(text); got != want {
				t.Errorf("IsCaip2(%q): got %v, want %v", text, got, want)
			}
		}
		for text, want := range map[string]bool{
			evmAccount:                             true,
			solanaAccount:                          true,
			solanaOther:                            true,
			bittensorAccount:                       true,
			"eip155:1:" + strings.Repeat("a", 128): true,
			"abc:1:a-b.c%20":                       true,
			"eip155:1":                             false,
			"eip155:1:":                            false,
			"eip155:1:" + strings.Repeat("a", 129): false,
			"solana:" + solanaAddress:              false,
			solanaAccount + ":x":                   false,
			"EIP155:1:0xab":                        false,
			"eip155:1:0x_ab":                       false,
			"eip155:1:0xab ":                       false,
			"eip155:1:0xab\n":                      false,
			"eip155::0xab":                         false,
			":1:0xab":                              false,
			"":                                     false,
			"garbage":                              false,
			"eip155:1:é":                           false,
		} {
			if got := IsCaip10(text); got != want {
				t.Errorf("IsCaip10(%q): got %v, want %v", text, got, want)
			}
		}
	})

	t.Run("ChainAccounts and AccountAddress", func(t *testing.T) {
		second := bittensorChain + ":5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
		approved := map[string]*Namespace{
			"polkadot": {Accounts: []string{
				polkadotAccount,
				second,
				"garbage",
				bittensorAccount,
				bittensorChain + ":",
				bittensorChain + "x:" + bittensorAddress,
				second, // twice, as the wallet gave it
			}},
			// an id of the chain under another key is not this namespace's
			"eip155": {Accounts: []string{evmAccount, bittensorChain + ":" + solanaAddress}},
			"kusama": nil,
		}
		got := ChainAccounts(approved, "polkadot", bittensorChain)
		want := []string{second, bittensorAccount, second}
		if strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("ChainAccounts: got %q, want %q", got, want)
		}
		if got := ChainAccounts(approved, "polkadot", polkadotChain); len(got) != 1 || got[0] != polkadotAccount {
			t.Errorf("ChainAccounts on the other chain: got %q", got)
		}
		if got := ChainAccounts(approved, "eip155", "eip155:1"); len(got) != 1 || got[0] != evmAccount {
			t.Errorf("ChainAccounts of another namespace: got %q", got)
		}
		for name, got := range map[string][]string{
			"nil":                     ChainAccounts(nil, "polkadot", bittensorChain),
			"a missing namespace":     ChainAccounts(approved, "solana", bittensorChain),
			"a null namespace":        ChainAccounts(approved, "kusama", bittensorChain),
			"no chain":                ChainAccounts(approved, "polkadot", ""),
			"a chain with no account": ChainAccounts(approved, "polkadot", "polkadot:other"),
		} {
			if len(got) != 0 {
				t.Errorf("ChainAccounts for %s: got %q, want none", name, got)
			}
		}

		if got := AccountAddress(bittensorAccount); got != bittensorAddress {
			t.Errorf("AccountAddress: got %q, want %q", got, bittensorAddress)
		}
		if got := AccountAddress(evmAccount); got != "0xab16a96d359ec26a11e2c2b3d8f8b8942d5bfcdb" {
			t.Errorf("AccountAddress: got %q", got)
		}
		for _, account := range []string{"", "garbage", "eip155:1", "eip155:1:", solanaAccount + ":x", "solana:" + solanaAddress} {
			if got := AccountAddress(account); got != "" {
				t.Errorf("AccountAddress(%q): got %q, want none", account, got)
			}
		}
	})
}
