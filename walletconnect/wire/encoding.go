//go:build !js && !ios_extension

// Package wire is the wire format of the WalletConnect v2 relay and Sign
// protocols, as far as one polkadot_signMessage session needs it: the
// encodings, keys, topics and envelopes, the relay token, the JSON-RPC frames
// and their ids, the pairing uri, the validation of a settled session's
// namespaces, and the Sign messages a dapp sends.
//
// It was written from ur.io's own client and from the public specification
// (github.com/WalletConnect/walletconnect-specs, docs/specs, at commit
// ecbbf6e1) only. Where the specification leaves a choice (the HKDF
// parameters, base64 for a sealed envelope, lower-case hex, the order of the
// relay token's claims) the choice made here is the one ur.io's client made.
//
// The package is pure: no network, no clock, no goroutine. The time and the
// source of randomness are arguments.
//
// Nothing here writes a key, a uri, a token or a message into an error.
package wire

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
)

// EncodeBase64 is base64 in the standard alphabet with padding, the form a
// sealed envelope travels in as a relay message.
func EncodeBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// DecodeBase64 reads base64 in the standard alphabet, with or without its
// padding. ur.io's client, in JavaScript, takes either form, and so does this
// one; Go's padded decoder alone would refuse the bare form. Like Go's
// decoders it passes over line breaks.
func DecodeBase64(s string) ([]byte, error) {
	b, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return nil, errors.New("walletconnect: not base64")
	}
	return b, nil
}

// the bitcoin alphabet: no 0, O, I or l
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// Base58Encode is base58 in the bitcoin alphabet (multibase "z", without the
// "z"): the number the bytes spell, written in base 58, behind one '1' for
// every leading zero byte. It is meant for a key, not for long input.
func Base58Encode(b []byte) string {
	zeros := 0
	for zeros < len(b) && b[zeros] == 0 {
		zeros++
	}
	number := new(big.Int).SetBytes(b)
	radix := big.NewInt(58)
	digit := new(big.Int)
	// the digits come out last one first
	var reversed []byte
	for number.Sign() > 0 {
		number.DivMod(number, radix, digit)
		reversed = append(reversed, base58Alphabet[digit.Int64()])
	}
	text := make([]byte, 0, zeros+len(reversed))
	for i := 0; i < zeros; i++ {
		text = append(text, base58Alphabet[0])
	}
	for i := len(reversed) - 1; i >= 0; i-- {
		text = append(text, reversed[i])
	}
	return string(text)
}

// Base58Decode is the inverse of Base58Encode. A character outside the
// alphabet is an error. Like Base58Encode it takes time quadratic in the
// length, which for a key is nothing.
func Base58Decode(s string) ([]byte, error) {
	zeros := 0
	for zeros < len(s) && s[zeros] == base58Alphabet[0] {
		zeros++
	}
	number := new(big.Int)
	radix := big.NewInt(58)
	for i := 0; i < len(s); i++ {
		digit := strings.IndexByte(base58Alphabet, s[i])
		if digit < 0 {
			return nil, errors.New("walletconnect: not base58")
		}
		number.Mul(number, radix)
		number.Add(number, big.NewInt(int64(digit)))
	}
	tail := number.Bytes()
	b := make([]byte, zeros+len(tail))
	copy(b[zeros:], tail)
	return b, nil
}

// MarshalCompact is the JSON of v as JavaScript's JSON.stringify writes it for
// the values this package sends: members in the order they are declared, no
// white space, '<', '>' and '&' as themselves, no trailing newline. (Go writes
// U+2028 and U+2029 as escapes where JavaScript writes the characters; both
// spell the same string.)
//
// The order matters where the bytes are signed (the relay token), and a map
// is written with its keys sorted, so what is sent is made of structs. The
// one map, the required namespaces of a proposal, has one key.
//
// It never panics. Only this package's own types, strings, booleans and
// json.RawMessage are meant to be passed, and for those it cannot fail. A
// value that cannot be encoded gives nil.
func MarshalCompact(v any) []byte {
	text, ok := marshalCompact(v)
	if !ok {
		return nil
	}
	return text
}

func marshalCompact(v any) (text []byte, ok bool) {
	// a panic can only come out of a MarshalJSON method of the caller's
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(v); err != nil {
		return nil, false
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n")), true
}
