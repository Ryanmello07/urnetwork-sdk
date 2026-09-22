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

	// ── ingesting a commit (§6.1's membership change, MASTER §11) ──────────────────────────

	// An is_commit record was received and this device could not follow the group into the epoch
	// it opens: the commit would not process, would not apply, or the session could not be advanced
	// onto the new epoch. It is carried rather than swallowed because a member that cannot ingest a
	// commit has fallen off the group and cannot read the next message.
	ErrCommitIngest = errors.New("urmessage: this group received a membership-change commit it could not follow into the next epoch")

	// The receiving-client authorization decision refused an ingested commit: MASTER §11's
	// "rejected by every receiving client on validation." The rule that refused it is carried,
	// as one of the sentinels below, mls's own, or the cause a configured [CommitAuthorizer]
	// returned -- so a caller can errors.Is this AND the rule. Since ledger item 242's R1 the
	// role model's rules ([authorizeCommit]) run on every ingested commit, and this is what a
	// commit that breaks one of them answers.
	ErrCommitUnauthorized = errors.New("urmessage: a received commit was refused by this device's authorization check")

	// ── the role model's rules, MASTER §11 and ledger item 242 (roles.go) ──────────────────
	//
	// One sentinel per rule, so that a refusal names the rule and a test can hold each rule
	// apart from its neighbours. Three rules answer connect/mls's own sentinels instead and are
	// not redeclared here: R3 is mls.ErrAdminRemovedByNonOwner, and the two caps are
	// mls.ErrGroupSizeExceeded and mls.ErrDeviceLimitExceeded.

	// R0a: the commit leaves the group with no urmessage_group_policy, or with one that does not
	// parse or does not validate (two owners, no owner, a non canonical role list). The mls
	// reason is carried -- mls.ErrNoGroupPolicy for the absence.
	ErrCommitPolicyInvalid = errors.New("urmessage: the commit leaves the group without a valid urmessage_group_policy")

	// R0b: a group context extension other than 0xF001 -- 0x0003 required_capabilities above
	// all -- is not byte identical before and after the commit.
	ErrCommitExtensionChanged = errors.New("urmessage: the commit changes a group context extension a policy commit may not touch")

	// R0c: the post-commit policy names an identity that holds no leaf after the commit.
	ErrCommitPolicyPhantom = errors.New("urmessage: the post-commit policy names an identity with no leaf in the group")

	// R6a: an Add whose credential claims an identity already in the group, committed by anyone
	// but that identity. A second device is the identity's own to add.
	ErrCommitIdentityClaimed = errors.New("urmessage: an added leaf claims an identity already in the group and the committer is not that identity")

	// R6c: a leaf present before and after the commit changed its credential identity (an
	// Update, or the committer's own path), or the leaf sets before and after do not agree with
	// what the commit says it added and removed.
	ErrCommitIdentityChanged = errors.New("urmessage: a leaf's identity changed across the commit, or the membership change is not the one the commit declares")

	// R6d: a leaf of the post-commit tree carries no urmessage_leaf_keys extension (0xF002), so
	// no epoch wrap could reach it. Both send doors refuse such a key package; this is the
	// receiving side's twin of that refusal, over the seam's HasLeafKeys.
	ErrCommitLeafWithoutKeys = errors.New("urmessage: a leaf of the post-commit tree carries no urmessage_leaf_keys, so no epoch wrap could reach it")

	// R1: an Add of a NEW identity by a committer who is neither ADMIN nor OWNER (ruling 1).
	ErrCommitAddByNonAdmin = errors.New("urmessage: only an admin or the owner may add a new identity to the group")

	// R2: a Remove of a MEMBER's or OBSERVER's leaf, not the committer's own identity, by a
	// committer who is neither ADMIN nor OWNER.
	ErrCommitRemoveByNonAdmin = errors.New("urmessage: only an admin or the owner may remove another member")

	// R5: the owner changed and the committer is not the owner, the new owner held no leaf
	// before the commit (ruling 10) or holds none after it, or the outgoing owner is still
	// present and is not an ADMIN afterwards (ruling 4).
	ErrCommitOwnerTransfer = errors.New("urmessage: ownership may only be transferred by the owner, to a current member, and the outgoing owner becomes an admin")

	// R4: a change to the admin set -- any role to ADMIN, or ADMIN to MEMBER or OBSERVER -- by a
	// committer who is not the owner.
	ErrCommitRoleChangeByNonOwner = errors.New("urmessage: only the owner may change who is an admin")

	// R4: a MEMBER to OBSERVER or OBSERVER to MEMBER change, or a retention or disappearing
	// bucket change, by a committer who is neither ADMIN nor OWNER.
	ErrCommitPolicyChangeByNonAdmin = errors.New("urmessage: only an admin or the owner may change a member's role or the group's policy")

	// R4: a change to the policy's server_id -- the message server the group lives on (MASTER
	// §6), whose change is V2's group migration between hosts -- by a committer who is not the
	// owner. Its own value rather than the admin-set one so a refusal names what moved.
	ErrCommitServerIdChangeByNonOwner = errors.New("urmessage: only the owner may change the server the group lives on")

	// R7: a commit by a MEMBER or an OBSERVER that carries more than its own device leaves -- an
	// Update of another leaf carried by reference, a group context extension list other than the
	// one the group had -- since §11's table gives "commit epochs" to ADMIN and OWNER and ruling 5
	// gives an OBSERVER "its own device add / remove and nothing else". A bare, path-only commit
	// is NOT this: ruling 12 makes it the PCS self-heal every role may make.
	ErrCommitBeyondOwnDevices = errors.New("urmessage: a member or an observer may commit its own device leaves and nothing else")

	// A role name on a [CommitAuthorization] that is not one of the four this profile defines.
	// The ingest path never builds one; it is here so the pure rule function refuses rather
	// than guesses when handed a value it did not build.
	ErrCommitRoleUnknown = errors.New("urmessage: a role name on the commit authorization is not one this profile defines")

	// ── the committing arm's own refusals (R2, rolescommit.go) ─────────────────────────────
	//
	// A role refusal on the send side is NEVER one of these: it is [ErrCommitUnauthorized]
	// wrapping the rule above, the receivers' own sentence, because the send side judges by the
	// same predicate. These two name a REQUEST that is malformed before any rule is reached.

	// [Group.SetRole] was asked for "owner", or for a name this profile does not define.
	// Ownership moves through [Group.TransferOwnership] and nothing else, because a transfer is
	// two role changes in one commit (the new owner up, the old owner to ADMIN, ruling 4) and a
	// SetRole to owner would leave two owners for R0a to refuse or none for a member to be judged
	// against.
	ErrRoleNotSettable = errors.New("urmessage: SetRole takes admin, member or observer; ownership moves through TransferOwnership")

	// [Group.TransferOwnership] named the identity that already owns the group. It is refused by
	// name rather than built, because the policy it would build -- the same identity set to owner
	// and then to admin -- has no owner at all, and R0a's answer to that describes a broken
	// policy rather than a pointless request.
	ErrAlreadyOwner = errors.New("urmessage: that identity already owns this group")

	// A commit this device built and submitted LOST THE EPOCH RACE: the server answered
	// REASON_COMMIT_LOST or REASON_EPOCH_STALE to it, which is MASTER §9.3's delivery service
	// saying another commit closed this epoch first. Both reasons are answered only after
	// write_auth verified (spec B §4.5), so neither is a nonce fact and S2-2's recovery is not
	// spent on them.
	//
	// THE GROUP IS WHERE IT WAS. The staged epoch is erased through the seam's ClearPendingCommit,
	// the handle, the session and [Group.Epoch] all still stand at the epoch the commit was built
	// against, and [Group.Members] reads the policy that is live rather than the one that did not
	// land. What the caller owes is §9.3's other half: [Group.Receive] to follow the winner into the
	// next epoch, then the verb again, which re-derives against the winner. Before 2026-09-22 the
	// commit was merged BEFORE it was submitted, and the loser was left at a private epoch nobody
	// else entered -- unable to open the winner's commit or to seal a record the server would
	// take -- until the app restarted. It wraps [ErrSubmitRefused] too, so a caller reading "did
	// it land" sees the answer it always saw.
	ErrCommitLost = errors.New("urmessage: another commit closed this epoch first, so this one was not built on the group's current state; Receive to follow the winner, then retry")

	// The head this package writes, read back as something else.
	ErrHeadFormat = errors.New("urmessage: this record's head is not one this build wrote")

	// ── the content envelope ──────────────────────────────────────────────────────────────

	// THE SENDER BROKE A RULE THE KIND CODE ALONE DECIDES: a body too short for its layout,
	// trailing octets after a layout with no tail, an empty required tail, a kind of 0x00, or a
	// code outside the retention classes its range allows. It is spec A §7.4's "malformed", and
	// it is a statement about the octets rather than about this build's age -- which is what
	// makes it a different value from [ErrContentUnsupported].
	ErrContentMalformed = errors.New("urmessage: this record's application plaintext is not a content envelope this build can read")

	// A CODE THIS BUILD DOES NOT KNOW, on a class its range allows. It is NOT a failure: the
	// record keeps its position and its message_id, the walk continues, and it renders as one
	// closed placeholder. A future kind is not malformed, and the day spec A §7.4's closed set
	// grows the "unsupported" value owner choice 11 owes, this is what carries it.
	ErrContentUnsupported = errors.New("urmessage: this record carries a content kind this build does not know")

	// An unknown code on EPH(0), which is never persisted: dropped, with nothing to render and
	// no history for a gap to be a hole in. It is carried as an error so that a caller that
	// wanted to know can, and no walk in this build can reach it -- see [transientOnly].
	ErrContentDropped = errors.New("urmessage: this record is a transient nothing on this build would keep")

	// An emoji this package will not seal. See checkEmoji for exactly what is checked and for
	// the larger half that is NOT, which is open item M1-41.
	ErrEmojiRefused = errors.New("urmessage: this is not an emoji a reaction may carry")

	// A kind that names another message named one this group does not hold. It is raised on the
	// SEND side only: on the receive side a reaction or a tombstone whose target has not
	// arrived is HELD, because the walk's order is not the conversation's order.
	ErrNoSuchMessage = errors.New("urmessage: this group holds no message under that message_id")

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

	// The table of authenticated receiver-ladder heads ([PeerHead]) could not be written after a
	// walk that raised one. Nothing in THIS process is affected -- the heads are in memory -- and
	// what it costs is a restart: a device restored without them tracks a peer's ladder at the
	// head the disk last held, and a peer more than one window past that is silent for the rest
	// of the epoch. Ledger item 241. It is answered by [Group.Receive] after the walk's own
	// answer, and the write is tried again on the next walk.
	ErrPeerHeadsPersist = errors.New("urmessage: the receiver-ladder heads could not be persisted")

	// The store holds no device identity yet, which is the ordinary state of a fresh
	// directory and is what makes [NewDevice] mint one rather than refuse.
	ErrNoDeviceIdentity = errors.New("urmessage: this state store holds no device identity")

	// ── restoring ─────────────────────────────────────────────────────────────────────────

	// [Device.Restore] was called on a device whose state store cannot persist an identity or
	// a group record, so there is nothing to restore FROM. Refused by name rather than
	// answering an empty slice, which reads exactly like "this device was in no groups".
	ErrNoDeviceStore = errors.New("urmessage: this device's state store is not durable, so there is nothing to restore; OpenDurableStateStore is the one this module ships")

	// A restored group could not be rebuilt. The cause is carried -- including
	// `messagegroup.ErrEngineLoadedEpoch`, which is the epoch mismatch this package used to refuse
	// itself and which now belongs to the engine door every caller of that interface goes through.
	//
	// THERE WAS A SECOND SENTINEL HERE AND IT IS GONE. It named the two methods a restored group
	// could not perform -- Process and ApplyCommit -- and it named its own cause: `connect`'s
	// GroupEngine had no LoadGroup, so this package carried a handle of its own that could not
	// write `messagegroup.EngineProcessed`'s unexported staged field. LoadGroup landed, the second
	// handle was deleted, and a sentinel for an impossibility that is no longer one is exactly the
	// shape this corpus keeps filing. It is REMOVED rather than retired in place.
	ErrRestore = errors.New("urmessage: this group could not be restored from the durable state store")

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
