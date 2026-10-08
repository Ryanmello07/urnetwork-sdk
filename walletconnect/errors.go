//go:build !js && !ios_extension

package walletconnect

import "strconv"

// ErrorKind says what ended a client or a request.
type ErrorKind string

const (
	ErrUnavailable ErrorKind = "unavailable" // the relay refused the client or could not be reached in time
	ErrExpired     ErrorKind = "expired"     // a deadline passed and two mailbox reads after it were empty
	ErrRejected    ErrorKind = "rejected"    // the user declined, or the wallet ended the pairing
	ErrUnsupported ErrorKind = "unsupported" // the wallet does not offer the namespace, the chain or the method
	ErrNoAccount   ErrorKind = "no_account"  // approved without an account on the chain
	ErrDeleted     ErrorKind = "deleted"     // the wallet ended the session
	ErrWallet      ErrorKind = "wallet"      // anything else the wallet did wrong, or sent
)

// Error is the one error of this package.
type Error struct {
	Kind   ErrorKind
	Code   int    // the wallet's or the relay's numeric code; 0 when there is none
	Detail string // written by this package; never text received from a peer
}

func (e *Error) Error() string {
	text := "walletconnect: " + string(e.Kind)
	if e.Detail != "" {
		text += ": " + e.Detail
	}
	if e.Code != 0 {
		text += " (code " + strconv.Itoa(e.Code) + ")"
	}
	return text
}
