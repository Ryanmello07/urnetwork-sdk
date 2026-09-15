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

	// An invite whose octets are not the octets that were encoded: truncated, mangled in a paste, or
	// rewritten by a carrier. It is refused at ParseInvite, which is where a user pasting one can be
	// told, and never at the join or at the first Receive after it.
	ErrInviteDamaged = errors.New("urmessage: this invite is damaged: it is not the octets the founder encoded")

	// A record came back that a key should have opened and did not.
	ErrRecordOpen = errors.New("urmessage: a record from a member of this group did not open")

	// The head this package writes, read back as something else.
	ErrHeadFormat = errors.New("urmessage: this record's head is not one this build wrote")

	// ── the durable state store ───────────────────────────────────────────────────────────

	// The directory could not be opened, read, written or flushed. It is the store's "this
	// disk is not answering", and it is deliberately NOT the same value as a missing record:
	// J1-4 is that mls.StateStore gives its callers no way to tell those two apart, and
	// [Device.Restore] is a caller that must.
	ErrStateStoreState = errors.New("urmessage: the durable state store could not be read or written")

	// A second store over one directory. It is the one refusal that is about another process
	// rather than about this one.
	ErrStateStoreLocked = errors.New("urmessage: this state directory is already held by a single-writer exclusion")

	// A file under a name this store computes that is not a record this build wrote: the wrong
	// magic, the wrong version, the wrong kind, a checksum that does not match, or a record
	// whose own key octets are not the key that was asked for.
	ErrStateStoreFormat = errors.New("urmessage: this is not a state record this build wrote")

	// No such value. It is a sentinel and not a nil: "this device was never in that group" and
	// "the disk is broken" are two readings a restore has to branch on.
	ErrStateNotFound = errors.New("urmessage: this state store holds no such value")

	// The store holds no device identity yet, which is the ordinary state of a fresh
	// directory and is what makes [NewDevice] mint one rather than refuse.
	ErrNoDeviceIdentity = errors.New("urmessage: this state store holds no device identity")

	// ── restoring ─────────────────────────────────────────────────────────────────────────

	// [Device.Restore] was called on a device whose state store cannot persist an identity or
	// a group record, so there is nothing to restore FROM. Refused by name rather than
	// answering an empty slice, which reads exactly like "this device was in no groups".
	ErrNoDeviceStore = errors.New("urmessage: this device's state store is not durable, so there is nothing to restore; OpenDurableStateStore is the one this module ships")

	// A restored group could not be rebuilt. The cause is carried.
	ErrRestore = errors.New("urmessage: this group could not be restored from the durable state store")

	// A method on the restored-group handle that this package cannot perform. See
	// restoredHandle for why the two that are refused are refused, and for J1-8.
	ErrRestoredHandle = errors.New("urmessage: a restored mls group cannot do this through sdk's own handle; it needs connect's GroupEngine to grow a LoadGroup (J1-8)")

	// ── §4.3.4's fetch attestation, and §4.3.4's pagination ───────────────────────────────

	// The server advertised attestation support and then answered a fetch without one, or
	// with one that does not describe the page it came with. Both are downgrades and both are
	// detectable WITHOUT a key; the signature is not, and [Group.Receive] says why.
	ErrFetchAttestation = errors.New("urmessage: this fetch's attestation does not describe the page it came with")

	// The server answered a truncated page and then advanced no cursor, so paging cannot
	// terminate. Refused rather than looped.
	ErrFetchNoProgress = errors.New("urmessage: the message server answered an incomplete fetch page that advanced no cursor")

	// The page bound was reached with the server still saying there is more. The messages read
	// so far are returned WITH this error, never silently.
	ErrFetchIncomplete = errors.New("urmessage: the message server still has records for this group and this Receive stopped at its page bound")

	// The server answered a page it called COMPLETE and named a `high_water_record_id` above
	// every record it handed over. §4.3.4 makes that field the server's own statement of the
	// highest record it holds for this group, so a complete page that stops below it is the
	// server holding records back -- the one failure the AEAD cannot see, detectable with no
	// key and no attestation. Returned WITH whatever did arrive, never instead of it. See
	// [Group.Receive] for the one honest server that also produces it.
	ErrFetchOmitted = errors.New("urmessage: the message server answered a complete page and named a high water above every record it handed over")

	// A record that did not open has been re-fetched [maxRecordAttempts] times and is given up
	// on. It is named ONCE, here, rather than silently dropped: before this error existed the
	// cursor moved past a failed record on its first sight of it and no later fetch ever asked
	// for it again.
	ErrRecordAbandoned = errors.New("urmessage: a record from a member of this group did not open after every retry and is no longer being fetched")

	// ── one identity, two devices ─────────────────────────────────────────────────────────

	// A SECOND WRITER IS SEALING UNDER THIS DEVICE'S IDENTITY IN THIS GROUP, which is what a
	// COPY of the app-data folder produces: two devices at one leaf, one sender_handle and one
	// stream counter. Two records under one (epoch, sender_handle, stream_index) are one
	// record_key and one nonce, which spec A §5.6 calls a total break of both AEADs for that
	// record. STICKY: a group that has seen this refuses to seal again for the life of the
	// process, because the alternative is to go on producing the collision. See
	// [Group.Receive] for exactly what is detected, when, and what is NOT.
	ErrIdentityInUse = errors.New("urmessage: another device is sealing records under this device's identity in this group, so this group will not seal again")

	// ── reconnecting is not failing ───────────────────────────────────────────────────────

	// [Device.Connect]'s Hellos were NOT ANSWERED for the whole of its budget. It is "not yet",
	// and it is a different value from every other refusal here for exactly one reason: on the
	// deployed server a reconnecting client_id is not routed to for about sixty seconds
	// (measured; msgrepo docs/reports/2026-09-15-operator-and-connect-findings.md item 5), so
	// the ordinary state of a client that just woke up is this one. A caller that shows a user
	// "could not connect" here is telling them something false; the sentence is "reconnecting".
	//
	// IT IS NOT A CLAIM THAT THE WINDOW IS STILL OPEN. The budget bounds how long one call
	// blocks, nothing more, and the answer to this error is to call [Device.Connect] again.
	// A server that ANSWERS -- a refusal by reason, or a Hello carrying no nonce -- is
	// [ErrHelloRefused] or [ErrNotConnected] on the first attempt and is never this.
	ErrReconnecting = errors.New("urmessage: this device is reconnecting: the message server has not answered Hello yet, which is the ordinary state of a client_id that has just re-dialled")

	// A RESTORED GROUP HAS NOT YET COMPARED ITS STREAM POSITION AGAINST THE SERVER'S ROWS.
	// [Group.Receive] is what performs that comparison, and until it has run once this group
	// will not seal -- because the seal is the irreversible half: a copied folder that sends
	// before it listens has already produced the two-time pad whatever the server then does
	// with the record.
	ErrNotReconciled = errors.New("urmessage: this restored group has not reconciled its stream position against the server yet; Receive once before Send")
)
