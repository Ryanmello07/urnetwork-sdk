//go:build !js && !ios_extension

// Package walletconnect is the dapp side of WalletConnect v2 as far as an app
// needs it to have a wallet app sign a message: it pairs with one wallet over
// the relay, holds one session, and sends one polkadot_signMessage request at
// a time. It is no general client: there is no second session, no other
// request, no event, and nothing is stored.
//
// The package wire below it is the wire format. The package relaytest is a
// relay for tests that behaves as the hosted relay was measured to behave.
//
// Clean-room record. This package and the two below it were written from two
// sources only: the WalletConnect client ur.io runs in its own pages, and the
// public specification, github.com/WalletConnect/walletconnect-specs at
// commit ecbbf6e1, docs/specs. The fixed values of the tests are RFC test
// vectors, the specification's own did-jwt test case, and values that were
// computed independently by ur.io's JavaScript and by a second Go
// implementation. No source of a WalletConnect or Reown SDK was consulted.
package walletconnect
