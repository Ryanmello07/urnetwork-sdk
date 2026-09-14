package urmessage

import "errors"

// Every refusal this package owns. Each one exists because its alternative is a silent zero: a
// message that was never sent, a message that arrived and was dropped, or a group that looks open
// and is not.
var (
	// The config did not carry something with no honest default.
	ErrNoTransport = errors.New("urmessage: a device needs an sdk.MessageTransport; S2-7 is open and this package stands nothing up")
	ErrNoReserver  = errors.New("urmessage: a device needs a durable stream index reserver; sdk.NewStreamIndexReserver over an sdk.StreamStore is the one this module ships")

	// Hello has not been said on this transport, so there is no connection nonce for write_auth
	// or req_auth to be computed over.
	ErrNotConnected = errors.New("urmessage: this device has not said Hello, and every authenticator is a mac over the connection's server_nonce")

	// §4.3.1's nonce moved and the session would not take the new one. NEVER swallowed: a send
	// that cannot be re-bound is a send that has not happened.
	ErrNonceRebind = errors.New("urmessage: this group's session could not be rebound onto the connection's current server_nonce")

	// The server refused. Carried rather than collapsed into a nil, because §4.5's reasons are
	// what a caller has to see.
	ErrSubmitRefused = errors.New("urmessage: the message server refused this record")
	ErrFetchRefused  = errors.New("urmessage: the message server refused this fetch")
	ErrCreateRefused = errors.New("urmessage: the message server refused this group")
	ErrHelloRefused  = errors.New("urmessage: the message server refused this Hello")

	// The ordering §6.1 imposes, raised here rather than met as a REASON_REJECTED on the wire.
	ErrGroupNotOpen  = errors.New("urmessage: this group has not been opened on the server; Open publishes the founding commit, the epoch's wraps and the marker that closes them")
	ErrGroupOpen     = errors.New("urmessage: this group is already open on the server")
	ErrNoMemberAdded = errors.New("urmessage: a group is opened at the epoch its first commit creates, so AddMember comes before Open")
	ErrAlphaOneAdd   = errors.New("urmessage: the alpha adds one member, before Open, in the commit that opens epoch 1; a second add is a second epoch and is not built")

	// A text that will not fit a rung, refused by the sealer and named here so the caller sees a
	// sentence about its message rather than about a size bucket.
	ErrTextTooLong = errors.New("urmessage: this text does not fit the largest inline size bucket; blob-backed bodies are out of scope for the alpha")

	// A record came back that a key should have opened and did not.
	ErrRecordOpen = errors.New("urmessage: a record from a member of this group did not open")

	// The head this package writes, read back as something else.
	ErrHeadFormat = errors.New("urmessage: this record's head is not one this build wrote")
)
