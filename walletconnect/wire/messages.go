//go:build !js && !ios_extension

package wire

import (
	"bytes"
	"encoding/json"
	"math"
	"strconv"
	"strings"
)

// The relay tag of every message of the pairing and Sign protocols
// (core/pairing/rpc-methods, sign/rpc-methods), and the times to live, in
// seconds, that go with them:
//
//	request             tag   ttl    tag of the answer
//	wc_pairingDelete    1000  86400  1001
//	wc_pairingPing      1002  30     1003
//	wc_sessionPropose   1100  300    1101 approve, 1120 reject, 1121 auto reject
//	wc_sessionSettle    1102  300    1103
//	wc_sessionUpdate    1104  86400  1105
//	wc_sessionExtend    1106  86400  1107
//	wc_sessionRequest   1108  300    1109
//	wc_sessionEvent     1110  300    1111
//	wc_sessionDelete    1112  86400  1113
//	wc_sessionPing      1114  30     1115
//
// An answer is published with the time to live of its request. An answer to
// a method the receiver does not know has tag 0 and lives a day.
const (
	TagPairingDelete            = 1000
	TagPairingDeleteResponse    = 1001
	TagPairingPing              = 1002
	TagPairingPingResponse      = 1003
	TagSessionPropose           = 1100
	TagSessionProposeApprove    = 1101
	TagSessionSettle            = 1102
	TagSessionSettleResponse    = 1103
	TagSessionUpdate            = 1104
	TagSessionUpdateResponse    = 1105
	TagSessionExtend            = 1106
	TagSessionExtendResponse    = 1107
	TagSessionRequest           = 1108
	TagSessionRequestResponse   = 1109
	TagSessionEvent             = 1110
	TagSessionEventResponse     = 1111
	TagSessionDelete            = 1112
	TagSessionDeleteResponse    = 1113
	TagSessionPing              = 1114
	TagSessionPingResponse      = 1115
	TagSessionProposeReject     = 1120
	TagSessionProposeAutoReject = 1121
	TagUnsupported              = 0

	TtlFiveMinutes = 300
	TtlOneDay      = 86400
	TtlPing        = 30
)

const (
	methodPairingDelete  = "wc_pairingDelete"
	methodSessionPropose = "wc_sessionPropose"
	methodSessionRequest = "wc_sessionRequest"
	methodSessionDelete  = "wc_sessionDelete"

	// sign/error-codes: USER_DISCONNECTED, the reason a dapp gives for ending
	// a session
	userDisconnectedCode    = 6000
	userDisconnectedMessage = "User disconnected."
)

// Metadata is how a party describes itself to the other.
//
// It has no redirect member: a redirect a wallet sends is not read, and no
// link a wallet names is opened. The redirect this client may name for
// itself is ProposeOptions.Redirect.
type Metadata struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Url         string   `json:"url"`
	Icons       []string `json:"icons"`
}

// Redirect is the link a dapp names for itself in its metadata, for a wallet
// to bring the dapp to the front again (core/pairing/data-structures,
// Metadata). Sent only, never read. An empty member is left out.
type Redirect struct {
	Native    string `json:"native,omitempty"`
	Universal string `json:"universal,omitempty"`
}

// ProposeOptions are the members of a proposal that ur.io's client does not
// send. The zero value sends none: the proposal is then byte for byte what
// ur.io's client sends.
type ProposeOptions struct {
	// params.pairingTopic: in the Proposal structure of sign/data-structures,
	// not in the params of wc_sessionPropose in sign/rpc-methods. "" = not sent.
	PairingTopic string
	// params.expiryTimestamp, unix seconds. NOT in the public specification
	// for a proposal: the name and the place are those of the device test of
	// 2026-10-09, by analogy with the pairing uri (delta 1.3). 0 = not sent.
	ExpiryTimestamp int64
	// params.proposer.metadata.redirect. nil, or both members empty = not sent.
	Redirect *Redirect
}

type proposeParams struct {
	Relays             []proposeRelay               `json:"relays"`
	Proposer           proposer                     `json:"proposer"`
	RequiredNamespaces map[string]requiredNamespace `json:"requiredNamespaces"`
	OptionalNamespaces struct{}                     `json:"optionalNamespaces"`
	PairingTopic       string                       `json:"pairingTopic,omitempty"`
	ExpiryTimestamp    int64                        `json:"expiryTimestamp,omitempty"`
}

type proposeRelay struct {
	Protocol string `json:"protocol"`
}

type proposer struct {
	PublicKey string           `json:"publicKey"`
	Metadata  proposerMetadata `json:"metadata"`
}

// Metadata as this client sends its own: the redirect behind the four members.
type proposerMetadata struct {
	Metadata
	Redirect *Redirect `json:"redirect,omitempty"`
}

// a required namespace has no accounts member, which is why it is not a
// Namespace
type requiredNamespace struct {
	Chains  []string `json:"chains"`
	Methods []string `json:"methods"`
	Events  []string `json:"events"`
}

// ProposeRequest is wc_sessionPropose, published on the pairing topic with
// TagSessionPropose and TtlFiveMinutes:
//
//	{"id":..,"jsonrpc":"2.0","method":"wc_sessionPropose","params":{
//	  "relays":[{"protocol":"irn"}],
//	  "proposer":{"publicKey":"<hex>","metadata":{"name":..,"description":..,"url":..,"icons":[..]}},
//	  "requiredNamespaces":{"<namespaceKey>":{"chains":["<chain>"],"methods":["<method>"],"events":[]}},
//	  "optionalNamespaces":{}}}
//
// One required namespace with one chain, one method and no event; nothing
// optional. The containers that are empty are sent empty, as ur.io's client
// sends them, and not as the null a nil slice would give; metadata without
// icons is sent with an empty list for the same reason.
//
// Each member of options that is set is added: "redirect" behind the icons,
// "pairingTopic" and "expiryTimestamp", in that order, behind
// optionalNamespaces. Never sent: session properties.
func ProposeRequest(id int64, proposerPublicKey Key, metadata Metadata, namespaceKey string, chain string, method string, options ProposeOptions) []byte {
	if metadata.Icons == nil {
		metadata.Icons = []string{}
	}
	redirect := options.Redirect
	if redirect != nil && *redirect == (Redirect{}) {
		redirect = nil
	}
	return RequestFrame(id, methodSessionPropose, proposeParams{
		Relays: []proposeRelay{{Protocol: relayProtocol}},
		Proposer: proposer{
			PublicKey: proposerPublicKey.Hex(),
			Metadata:  proposerMetadata{Metadata: metadata, Redirect: redirect},
		},
		RequiredNamespaces: map[string]requiredNamespace{
			namespaceKey: {
				Chains:  []string{chain},
				Methods: []string{method},
				Events:  []string{},
			},
		},
		PairingTopic:    options.PairingTopic,
		ExpiryTimestamp: options.ExpiryTimestamp,
	})
}

type sessionRequestParams struct {
	Request sessionRequest `json:"request"`
	ChainId string         `json:"chainId"`
}

type sessionRequest struct {
	Method string            `json:"method"`
	Params signMessageParams `json:"params"`
}

type signMessageParams struct {
	Address string `json:"address"`
	Message string `json:"message"`
}

// SessionRequest is wc_sessionRequest for a method that takes an address and
// a message, as polkadot_signMessage does, published on the session topic
// with TagSessionRequest and TtlFiveMinutes:
//
//	{"id":..,"jsonrpc":"2.0","method":"wc_sessionRequest","params":{
//	  "request":{"method":"<method>","params":{"address":"<address>","message":"<message>"}},
//	  "chainId":"<chain>"}}
//
// address is the address as the wallet gave it in the session's account.
// message is the text to sign, as text and not as hex. The request carries no
// expiry of its own.
func SessionRequest(id int64, chain string, method string, address string, message string) []byte {
	return RequestFrame(id, methodSessionRequest, sessionRequestParams{
		Request: sessionRequest{
			Method: method,
			Params: signMessageParams{
				Address: address,
				Message: message,
			},
		},
		ChainId: chain,
	})
}

// deleteParams are the reason a party gives for ending a pairing or a
// session: wc_pairingDelete (core/pairing/rpc-methods) and wc_sessionDelete
// (sign/rpc-methods) carry the same members.
type deleteParams struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// PairingDeleteRequest is wc_pairingDelete with the reason a dapp gives,
// published on the pairing topic with TagPairingDelete and TtlOneDay:
//
//	{"id":..,"jsonrpc":"2.0","method":"wc_pairingDelete","params":{"code":6000,"message":"User disconnected."}}
func PairingDeleteRequest(id int64) []byte {
	return RequestFrame(id, methodPairingDelete, deleteParams{
		Code:    userDisconnectedCode,
		Message: userDisconnectedMessage,
	})
}

// SessionDeleteRequest is wc_sessionDelete with the reason a dapp gives,
// published on the session topic with TagSessionDelete and TtlOneDay:
//
//	{"id":..,"jsonrpc":"2.0","method":"wc_sessionDelete","params":{"code":6000,"message":"User disconnected."}}
func SessionDeleteRequest(id int64) []byte {
	return RequestFrame(id, methodSessionDelete, deleteParams{
		Code:    userDisconnectedCode,
		Message: userDisconnectedMessage,
	})
}

// ProposeResult is the result of an approved proposal. The wallet's public
// key is 64 hex characters, which ParseKey checks; with it DeriveSymKey gives
// the session key and Topic the session topic.
type ProposeResult struct {
	ResponderPublicKey string `json:"responderPublicKey"`
}

// SettleParams is what this client reads of the params of wc_sessionSettle.
// The controller's public key must be the one the proposal was approved with.
type SettleParams struct {
	Controller struct {
		PublicKey string `json:"publicKey"`
	} `json:"controller"`
	Namespaces map[string]*Namespace `json:"namespaces"`
	Expiry     json.RawMessage       `json:"expiry"`
}

// ExpiryUnix is the session's expiry in seconds. It is false unless the
// expiry is a JSON number: a string of digits, null and a missing member are
// refused, as ur.io's client refuses them.
//
// A number with a fraction is rounded down and one beyond 64 bits is the
// nearest int64, so that whatever JavaScript takes for a finite number has a
// value here. Whether the expiry is in the future is for the caller to
// decide.
func (s *SettleParams) ExpiryUnix() (int64, bool) {
	if s == nil {
		return 0, false
	}
	text := string(bytes.Trim(s.Expiry, " \t\r\n"))
	if !isJsonNumber(text) {
		return 0, false
	}
	if expiry, err := strconv.ParseInt(text, 10, 64); err == nil {
		return expiry, true
	}
	// a fraction, an exponent, or more digits than an int64 has. A value
	// too large for a float64 is infinite in JavaScript, and an error here.
	number, err := strconv.ParseFloat(text, 64)
	if err != nil || math.IsInf(number, 0) || math.IsNaN(number) {
		return 0, false
	}
	number = math.Floor(number)
	switch {
	case number >= 1<<63:
		return math.MaxInt64, true
	case number <= -(1 << 63):
		return math.MinInt64, true
	}
	return int64(number), true
}

// isJsonNumber reports whether text is one JSON number and nothing else:
//
//	-? ( 0 | [1-9][0-9]* ) ( . [0-9]+ )? ( ( e | E ) [+-]? [0-9]+ )?
//
// Go's own number parsers take more than that ("+5", "0x10", "1_000", "Inf"),
// and a quoted number is not a number.
func isJsonNumber(text string) bool {
	rest := strings.TrimPrefix(text, "-")
	integer := countDigits(rest)
	if integer == 0 || (integer > 1 && rest[0] == '0') {
		return false
	}
	rest = rest[integer:]
	if strings.HasPrefix(rest, ".") {
		fraction := countDigits(rest[1:])
		if fraction == 0 {
			return false
		}
		rest = rest[1+fraction:]
	}
	if strings.HasPrefix(rest, "e") || strings.HasPrefix(rest, "E") {
		rest = rest[1:]
		if strings.HasPrefix(rest, "+") || strings.HasPrefix(rest, "-") {
			rest = rest[1:]
		}
		exponent := countDigits(rest)
		if exponent == 0 {
			return false
		}
		rest = rest[exponent:]
	}
	return rest == ""
}

func countDigits(text string) int {
	n := 0
	for n < len(text) && isDigit(text[n]) {
		n++
	}
	return n
}
