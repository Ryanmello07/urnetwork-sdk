//go:build !js && !ios_extension

package walletconnect

import (
	"context"
	"crypto/rand"
	"io"
	"net"
	"time"

	"github.com/urnetwork/sdk/walletconnect/wire"
)

// DefaultRelayUrls are the two names of the hosted relay. They are one
// network: a client's mailbox follows it from one to the other.
var DefaultRelayUrls = []string{"wss://relay.walletconnect.com", "wss://relay.walletconnect.org"}

// Config is what a client is made of. The rules named in the comments are
// those of design B.3.
type Config struct {
	ProjectId       string
	RelayUrls       []string // nil = DefaultRelayUrls; tried in turn (B.3 R5)
	IdentifierName  string   // "bundleId", "packageName" or "" (B.3 R15)
	IdentifierValue string   // "" presents nothing
	Metadata        wire.Metadata
	NamespaceKey    string // "polkadot"
	Chain           string // the one CAIP-2 chain proposed
	Method          string // the one method proposed and requested
	// Optional members of the proposal (wire.ProposeOptions; delta 2.2). The
	// topic and the expiry are the pairing's own: only whether they are sent
	// is chosen here. With none of the three the proposal is ur.io's.
	ProposePairingTopic bool
	ProposeExpiry       bool
	Redirect            *wire.Redirect // nil = no redirect in the metadata
	// seconds of running time the socket is kept after SetForeground(false); 0 closes it at once (B.3 R3)
	BackgroundSocketSeconds int
	Now                     func() int64                                                                // unix milliseconds; nil = time.Now().UnixMilli
	Rand                    io.Reader                                                                   // nil = crypto/rand.Reader
	NetDial                 func(ctx context.Context, network string, address string) (net.Conn, error) // nil = a plain net.Dialer
	// tests: replaces the TCP dial and the TLS handshake (gorilla's NetDialTLSContext); the url stays wss
	DialTLS func(ctx context.Context, network string, address string) (net.Conn, error)
	Timing  *Timing                          // nil = DefaultTiming()
	OnEvent func(event Event)                // called by the Client, one event at a time
	Logf    func(format string, args ...any) // nil = silent; never given a secret
	// One line per event, for a device test (delta 5.3); nil = none. Called on
	// the loop. Never given a key, a uri, a token, a message text, a signature
	// or any text that a wallet or the relay wrote: numbers, fixed words and 8
	// hex characters of a topic the client holds, and nothing else.
	Trace func(format string, args ...any)
}

// withDefaults is a copy of the config in which every nil that stands for a
// default is that default. NetDial, Logf and Trace stay nil: they are asked
// where they are used.
func (c *Config) withDefaults() *Config {
	config := *c
	if len(config.RelayUrls) == 0 {
		config.RelayUrls = DefaultRelayUrls
	}
	if config.Now == nil {
		config.Now = func() int64 { return time.Now().UnixMilli() }
	}
	if config.Rand == nil {
		config.Rand = rand.Reader
	}
	if config.Timing == nil {
		config.Timing = DefaultTiming()
	}
	return &config
}

// EventKind says what an Event tells.
type EventKind int

const (
	EventPairingReady   EventKind = iota + 1 // the proposal is acknowledged by the relay: hand PairingUri to the wallet
	EventSessionSettled                      // approval and a valid settle were read
	EventRequestSent                         // the request was written to a subscribed socket (R13)
	EventRequestResult                       // the wallet answered with a result
	EventRequestFailed                       // the request ended without a result; the session is still open
	EventConnected                           // Connected changed
	EventClosed                              // the client is over; always the last event, exactly once
)

// Event is what a Client tells its owner through Config.OnEvent.
type Event struct {
	Kind                EventKind
	PairingUri          string   // EventPairingReady
	PairingExpiryMillis int64    // EventPairingReady
	Accounts            []string // EventSessionSettled: CAIP-10 ids on Config.Chain exactly as the wallet gave them, in order
	RequestId           int64    // EventRequestSent, EventRequestResult, EventRequestFailed
	Signature           string   // EventRequestResult: result.signature, or the result itself when it is a string; "" otherwise
	Connected           bool     // EventConnected
	Err                 *Error   // EventRequestFailed; EventClosed (nil after Close or the linger)
}
