//go:build !js && !ios_extension

package wire

import (
	"errors"
	"io"
	"net/url"
	"strconv"
	"strings"
)

const (
	// pairing-uri: the expiry "should be generated 5 minutes in the future"
	pairingTtlSeconds = 300
	pairingUriVersion = "2"
	relayProtocol     = "irn"
	// the one group of methods this client's pairing is for, as the
	// specification's example writes a group: brackets as they are
	pairingMethods = "[wc_sessionPropose]"
)

// Pairing is what a dapp hands a wallet to start a session: a random
// symmetric key, the topic the proposal waits on, and when the offer ends.
// Whoever holds the key can answer the proposal, so the key and the uri are
// secrets until the session is settled.
type Pairing struct {
	SymKey     Key
	Topic      string
	ExpiryUnix int64
}

// NewPairing makes a pairing with a key from rand, the topic of that key and
// an expiry 300 seconds after nowUnix.
func NewPairing(rand io.Reader, nowUnix int64) (*Pairing, error) {
	symKey, err := NewKey(rand)
	if err != nil {
		return nil, err
	}
	return &Pairing{
		SymKey:     symKey,
		Topic:      Topic(symKey),
		ExpiryUnix: nowUnix + pairingTtlSeconds,
	}, nil
}

// Uri is the pairing as a wallet scans or opens it:
//
//	wc:<topic>@2?relay-protocol=irn&symKey=<hex>&expiryTimestamp=<unix>&methods=[wc_sessionPropose]
//
// It is built by hand: the order of the parameters is fixed and the brackets
// are not percent-encoded, neither of which url.Values does. To put the uri
// into a wallet's own link, percent-encode all of it once.
//
// A pairing with no Topic is written with the topic of its key, which is the
// only topic a pairing made here has. A pairing with no expiry is written
// without the parameter.
func (p *Pairing) Uri() string {
	if p == nil {
		return ""
	}
	topic := p.Topic
	if topic == "" {
		topic = Topic(p.SymKey)
	}
	var uri strings.Builder
	uri.WriteString("wc:")
	uri.WriteString(topic)
	uri.WriteString("@" + pairingUriVersion + "?relay-protocol=" + relayProtocol + "&symKey=")
	uri.WriteString(p.SymKey.Hex())
	if p.ExpiryUnix != 0 {
		uri.WriteString("&expiryTimestamp=")
		uri.WriteString(strconv.FormatInt(p.ExpiryUnix, 10))
	}
	uri.WriteString("&methods=" + pairingMethods)
	return uri.String()
}

// ParsePairingUri reads a pairing uri, as a wallet does; here that is the
// test wallet. The parameters may come in any order, the methods may be
// written with their brackets percent-encoded, and parameters it does not
// know are passed over. The topic is kept as the uri names it.
//
// Refused: anything that is not "wc:<hex topic>@<version>?<parameters>"; a
// uri with no symKey or no relay-protocol; and what a Pairing cannot hold: a
// version other than 2, a symKey that is not 64 hex characters, a
// relay-protocol other than irn, an expiryTimestamp that is not a number of
// seconds. A uri still wrapped in a wallet's link, or still percent-encoded,
// is not a pairing uri: the caller unwraps it first.
//
// The uri holds the pairing key, so no error repeats any of it.
func ParsePairingUri(uri string) (*Pairing, error) {
	rest, found := strings.CutPrefix(uri, "wc:")
	if !found {
		return nil, errors.New("walletconnect: not a wc: uri")
	}
	head, query, found := strings.Cut(rest, "?")
	if !found {
		return nil, errors.New("walletconnect: the pairing uri has no parameters")
	}
	topic, version, found := strings.Cut(head, "@")
	if !found || !isHex(topic) {
		return nil, errors.New("walletconnect: the pairing uri has no hex topic and version")
	}
	if version != pairingUriVersion {
		return nil, errors.New("walletconnect: the pairing uri is not version 2")
	}

	pairing := &Pairing{Topic: topic}
	hasSymKey := false
	protocol := ""
	for _, parameter := range strings.Split(query, "&") {
		name, escaped, _ := strings.Cut(parameter, "=")
		switch name {
		case "symKey", "relay-protocol", "expiryTimestamp":
		default:
			// methods, relay-data and whatever a later version adds
			continue
		}
		// PathUnescape, not QueryUnescape: a '+' stays a '+'
		value, err := url.PathUnescape(escaped)
		if err != nil {
			return nil, errors.New("walletconnect: the pairing uri has a bad escape")
		}
		switch name {
		case "symKey":
			symKey, err := ParseKey(value)
			if err != nil {
				return nil, errors.New("walletconnect: the pairing uri's symKey is not 64 hex characters")
			}
			pairing.SymKey = symKey
			hasSymKey = true
		case "relay-protocol":
			protocol = value
		case "expiryTimestamp":
			if !isDecimal(value) {
				return nil, errors.New("walletconnect: the pairing uri's expiryTimestamp is not a number")
			}
			expiry, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return nil, errors.New("walletconnect: the pairing uri's expiryTimestamp is not a number")
			}
			pairing.ExpiryUnix = expiry
		}
	}
	if !hasSymKey {
		return nil, errors.New("walletconnect: the pairing uri has no symKey")
	}
	if protocol != relayProtocol {
		return nil, errors.New("walletconnect: the pairing uri's relay-protocol is not irn")
	}
	return pairing, nil
}

// isHex reports whether s is one or more hex digits of either case.
func isHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(isDigit(c) || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// isDecimal reports whether s is one or more digits, with no sign.
func isDecimal(s string) bool {
	return s != "" && countDigits(s) == len(s)
}
