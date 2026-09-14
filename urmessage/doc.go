// Package urmessage is the send/receive seam: the join between connect/messagegroup's MLS, this
// module's durable stream store and §10.1 transport, and a real message server.
//
// It is the alpha and it is deliberately small. A group exists, a second device joins it by
// Welcome, a line of text is sealed as a DURABLE record and submitted, and the other device
// fetches it and opens it. Everything else a messenger has -- media and blobs, the rendezvous and
// contact cards, recovery, multi-device, EPH messages (ledger 185 and 186, deferred for alpha),
// read receipts, typing indicators -- is NOT HERE AND IS NOT STUBBED. Nothing in this package
// pretends to carry them: there is no method that accepts a picture and drops it.
//
// ---------------------------------------------------------------------------------------------
// DECISION S2-7: HOW A CLIENT REACHES THE SERVER. TAKEN, NOT RESOLVED.
// ---------------------------------------------------------------------------------------------
//
// The transport is INJECTED. [DeviceConfig.Transport] is an [sdk.MessageTransport] the caller
// built over a connect client the caller owns, and this package dials nothing, authenticates
// nothing and closes nothing.
//
// For the alpha the wiring taken is the one `msgrepo/cmd/message-server/stack_test.go` uses: two
// `connect.NewClient`s over `connect.NewNoContractClientOob` joined by two in-process routes, with
// no network space, no operator and no `ByJwt`.
//
// IT WAS TAKEN BECAUSE IT IS ONE OF EXACTLY TWO, AND THE OTHER IS BLOCKED ON AN ACTION NO CODE IN
// THIS WORKSPACE CAN PERFORM. `connect` HAS NO INBOUND LISTENER FOR CLIENT FRAMES. The query, so
// that the number is checkable rather than quoted: over connect at 27c50c2,
//
//	grep -rnE 'net\.Listen|websocket\.Upgrader' --include=*.go . | grep -v _test.go | grep -v /mls/
//
// answers SIX lines and not one of them accepts a peer's frames -- `egress.go:40` is a comment
// about a dialer Control callback, `extender/extender.go:149` and `:247` are the extender's own
// TCP and UDP ports, `ip_mux_upgrade.go:337` is the DNS/TCP mux, `transport.go:1423` is a UDP
// socket QUIC dials out of, and `tun.go:965` is gVisor's userspace stack inside the TUN. So a
// `connect.Client` receives a frame in exactly two ways: an in-process
// `connect.Route`, or a `connect.PlatformTransport` that DIALS OUT to `wss://connect.<host>` and
// is handed frames the platform routes to its client_id. `sdk/sim_device.go:115`'s authenticated
// `connect.NewClient(ByJwt, ApiUrl)` is the second, and it needs the message server to hold a
// `ByJwt` for a `network_client` that an admin OF THAT OPERATOR mints -- spec B §9.1 and §9.2 --
// which is an operator-admin action against a running URnetwork operator and is not something
// `connect`, `sdk` or the server module can do for itself.
//
// So the choice is not "loopback is faster". It is "loopback, or stand up an operator". The alpha
// takes loopback, and the day somebody has an operator credential the injection point does not
// move: [DeviceConfig.Transport] is already a transport over a client the caller built, and a
// platform-attached client goes in the same hole.
//
// WHAT THAT DOES NOT COVER, in full:
//
//   - The client is not authenticated to the server. `peer.Checks.ConnectionAuthenticated` is
//     satisfied by the connect layer's source id and nothing else; there is no account, no JWT and
//     no platform.
//   - There is no remote server. The two connect clients must be joined by a route somebody else
//     established, which today means one process -- the app and the server in one binary. A
//     message server on another machine is the platform-transport path above, and that is gated on
//     the credential, not on this package.
//   - Nothing here survives the app exiting. The MLS state store is in memory (see
//     [NewMemoryStateStore]) and an in-process server keeps its rows in `store.MemoryStore`.
//   - No NAT traversal, no TLS termination, no reconnection of the connect client itself, no
//     contract or provide mode. `NewNoContractClientOob` is what removes the contract requirement.
//   - Nothing here chooses a server id, discovers one, or verifies that the id it was handed is a
//     message server rather than any other connect peer.
//
// S2-7 is not resolved by any of this and this package makes no claim on it.
//
// ---------------------------------------------------------------------------------------------
// DECISION S2-2: WHAT HAPPENS ON A RECONNECT. RE-HELLO AND REBIND, AND NEVER SILENTLY.
// ---------------------------------------------------------------------------------------------
//
// A `GroupSession` MACs `write_auth` over the `server_nonce` it was constructed with, and §4.3.1
// replaces that nonce at every Hello. So a session outlives its nonce, and a record sealed against
// a dead one is refused on the wire. The alpha's answer has two halves because the problem has two
// halves, and the second is Wave 2's filed Finding E.
//
//  1. THE HALF THAT IS VISIBLE. [sdk.MessageTransport.NonceEpoch] moves at every completed Hello.
//     Every submit and every fetch in this package first compares that number against the one the
//     session was last bound at, and calls `RebindServerNonce` when it has moved. A rebind that
//     fails is returned to the caller as [ErrNonceRebind]; it is never swallowed and the send is
//     never reported as having happened.
//
//  2. THE HALF THAT IS NOT. NonceEpoch counts HELLOS, NOT CONNECTIONS. A connection replaced
//     underneath the binding without a Hello through it -- a second transport on the same connect
//     client, which is one client_id and therefore one connection to `peer.Connections` -- leaves
//     a superseded nonce readable at an unchanged number, and clause 1 sees nothing to repair. So
//     a record that comes back REASON_REJECTED gets exactly ONE recovery attempt: a fresh Hello
//     through this transport, a rebind onto the nonce it issued, `ReauthRecord` to re-MAC the
//     record that is already sealed -- which consumes no stream index and re-encrypts nothing --
//     and one resubmission. If that is refused too, [Send] returns [ErrSubmitRefused] naming both
//     refusals. It NEVER returns nil.
//
// The retry is bounded at one and is not a loop. A second refusal is a fact about the group or the
// epoch rather than about the nonce, and a client that kept trying would turn a visible failure
// into a busy one.
//
// WHAT IS STILL OPEN. S2-2 is not resolved: this package observes a reconnect only through Hellos
// it performed and through refusals it was answered, and a `connect.Client` that reconnects
// underneath it announces nothing to either. The refusal-driven half is the alpha's cover for
// that, and it costs one wasted round trip per superseded nonce.
//
// ---------------------------------------------------------------------------------------------
// WHAT IS HANDED OVER OUT OF BAND, NAMED RATHER THAN LEFT FOR A READER TO FIND.
// ---------------------------------------------------------------------------------------------
//
// [Invite] carries four values from the founder to the joiner, by a channel this package does not
// have and does not invent -- the rendezvous and contact cards are out of scope. They are the
// three `connect/messagegroup`'s own join test names, plus the group id:
//
//   - the MLS Welcome and ratchet tree, which is ledger 44a's named hand-off;
//   - `pq_secret`, drawn by [messagegroup.NewPqSecret], whose DELIVERY is M1-20 / m1 task 14;
//   - `group_handle_key`, computed by `GroupHandleKey(StorageRoot(...))`, whose carrier is M1-2;
//   - the 32 octet group id the server rows are keyed by.
//
// Every one of those is a value a PRODUCTION function produced. There is no test-only key source
// on the path: no constant key, no zero secret, no fixture exporter. What is missing is a
// CARRIER, and inventing one here would be inventing the rendezvous.
//
// ---------------------------------------------------------------------------------------------
// THE MLS STATE STORE IS IN MEMORY AND SAYS SO.
// ---------------------------------------------------------------------------------------------
//
// `connect/mls` publishes the `StateStore` INTERFACE and no implementation of it; the only one in
// the corpus is `messagegroup`'s own `memoryStateStore`, declared in a _test.go file and therefore
// unreachable from any build. [NewMemoryStateStore] is this package's, it is production code, and
// it persists NOTHING: close the process and the MLS group is gone. The durable half that does
// exist is the stream index reserver, which is [sdk.StreamStore] and is crash safe, because a
// reused stream index is a reused nonce under a reused record key and an MLS group that has to be
// recreated is only an inconvenience.
package urmessage
