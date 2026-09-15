package urmessage

import (
	"context"
	"fmt"

	"github.com/urnetwork/connect/messagegroup"
	"github.com/urnetwork/connect/mls"
)

// ── S2-14's other half: coming back ──────────────────────────────────────────────────────────

// Restore re-enters every group this device's durable store holds a record for.
//
// IT IS THE POINT OF THE DURABLE STORE AND IT IS NOT AUTOMATIC. A caller says Hello first -- every
// authenticator is a MAC over the connection's nonce and a restored session is bound to the nonce
// this transport holds now -- and then calls this. The two are separate because [Device.Connect]
// rebinds the groups a device ALREADY holds, and until this runs a restarted device holds none.
//
// WHAT A RESTORED GROUP CAN AND CANNOT DO, said here because the list is short and the absence of
// it would be read as "everything".
//
//   - It can SEND, AFTER IT HAS RECEIVED ONCE: the session is rebuilt at the record's epoch off
//     the MLS exporter, the stream index continues from the durable reserver, and the server takes
//     the record -- but the first [Group.Send] on a restored group is refused with
//     [ErrNotReconciled] until one [Group.Receive] has completed. That ordering is the CLONE
//     CHECK and it is stated below.
//   - It can RECEIVE, including records sealed BEFORE the restart AND THE ONES IT SEALED ITSELF: a
//     receiver ladder is followed from its root (`trackLocked` passes head index 0), and the
//     cursor is not persisted, so a restored device re-fetches this group's history and
//     re-derives every key it needs for it. Its own records are opened rather than skipped, which
//     is what makes a restored conversation the whole conversation; see [Group.openPageLocked].
//   - It cannot ADD a member or OPEN: both need the epoch-zero founding session, which exists on
//     the founder before the first commit and is not persisted. A restored group answers
//     [ErrAlphaOneAdd] and [ErrNoMemberAdded] by name, which is the same answer a joiner gets.
//   - It cannot INGEST a commit, so it cannot follow the group into a later epoch. That is J1-8
//     and it belongs to `connect`: see [restoredHandle]. The alpha has exactly one epoch
//     ([ErrAlphaOneAdd]), so nothing in this build can reach it -- and the day a second epoch is
//     built, this is the thing that has to land first.
//
// A GROUP THAT WILL NOT RESTORE IS NAMED AND THE REST STILL COME BACK. One unreadable epoch state
// must not cost a device every other conversation it is in, so the refusals are collected and
// returned together with whatever did restore.
//
// ---------------------------------------------------------------------------------------------
// ONE COPY OF THE APP-DATA FOLDER IS TWO DEVICES ON ONE IDENTITY, AND THIS IS WHERE THAT IS MET.
// ---------------------------------------------------------------------------------------------
//
// A DURABLE IDENTITY IS WHAT MAKES A RESTART A RESTORE AND IT IS ALSO WHAT MAKES A COPY DANGEROUS.
// Before the store existed, a restarted device drew a FRESH Ed25519 identity and a fresh MLS
// group, so a copied directory was harmless: the copy was a different leaf with a different
// sender_handle and it collided with nothing. With the identity on the disk, a copied folder is a
// second device at the SAME leaf, the SAME sender_handle, the SAME epoch and the SAME stream
// counter -- and two records under one (epoch, sender_handle, stream_index) are one record_key and
// one nonce, which spec A section 5.6 calls a total break of both AEADs for that record. The
// single-writer exclusion does NOT reach this: it is held per DIRECTORY, and a copy is a second
// directory, so both opens are granted and neither knows about the other.
//
// THE SERVER REFUSING THE DUPLICATE SUBMISSION IS NOT A DEFENCE AND IS NOT TREATED AS ONE. The
// message server answers REASON_STREAM_INDEX_REGRESSED to the second record, which is real defence
// in depth for the SERVER'S rows -- and the sealing has already happened by then. Two ciphertexts
// under one keystream exist on this disk and on the wire whether or not the server stores the
// second.
//
// SO THE CHECK IS BEFORE THE SEAL, AND IT IS TWO CLAUSES.
//
//  1. A RESTORED GROUP WILL NOT SEND UNTIL IT HAS RECEIVED. [Group.Receive] walks the group's
//     whole history -- the cursor is not persisted -- opens every record of this device's own,
//     and holds the highest stream index it finds against [messagegroup.StreamIndexReserver]'s
//     HighWater for this stream. Every index on the server under this sender_handle was allocated
//     by this device's reserver and a reserver never rewinds, so an index ABOVE the high water was
//     sealed by something else holding these keys. There is no second reading of it. The group
//     then refuses to seal, for the life of the process, with [ErrIdentityInUse].
//  2. AFTER IT HAS RECONCILED, an own record that opens under this device's sender_handle and is
//     not a record this device sealed is the same finding, refused the same way. TWO SHAPES, and
//     the second is the one an index-only check could not see: an index this device never sealed
//     at, and an index it DID seal at carrying a body_hash that is not the one it sealed. The
//     hash is why [Group.ownIndices] is a map and not a set; §3.1's body_hash is authenticated by
//     both AEADs, so a party without this group's keys cannot produce a record that opens at all.
//
// WHAT THIS COVERS: every copy that is BEHIND the original -- a phone backup, a folder copied last
// week, a partial restore that brought the state directory and not the stream directory -- is
// caught at its first Receive, BEFORE it has sealed anything. So is a copy that cannot reach the
// server at all, because clause 1 refuses the send when the reconciliation has not run. And a copy
// that is exactly level but LISTENS before it speaks is caught by clause 2 with no ciphertext
// produced at all.
//
// WHAT IT DOES NOT COVER, said plainly because a half-stated defence is worse than none. TWO
// COPIES THAT ARE EXACTLY LEVEL and both SEAL before either fetches again agree with the server
// and with each other at the moment of the seal, so nothing on either side has any evidence the
// other exists, and THEY COLLIDE ONCE. That is one record's total break and this build cannot
// prevent it.
//
// WHAT CLAUSE 2 THEN DOES, stated exactly rather than optimistically: the server takes one of the
// two submissions and refuses the other, and the side that LOST meets the winner's record at the
// index it sealed at, with a body_hash that is not its own -- so the loser stops. The WINNER sees
// nothing it did not seal and carries on, which is correct: it is then the only writer of that
// stream and produces no further collision. So the count is one record, not a stream of them, and
// the side still capable of making more is the side that is stopped.
//
// WHAT WOULD CLOSE IT PROPERLY: a copy that came back under a DIFFERENT leaf, which is an MLS
// Update commit -- and a restored group cannot ingest a commit (J1-8, see [restoredHandle]) and
// the alpha has exactly one epoch ([ErrAlphaOneAdd]). **FILED AS S2-28: a copied app-data folder
// needs a new leaf, not a detection.** Until it is ruled, the two clauses above are the whole
// answer and the sentences you are reading are the rest of it. `sdk/cp3b/clone_test.go` drives
// every case in this paragraph, including the residual.
func (self *Device) Restore(ctx context.Context) ([]*Group, error) {
	store, durable := self.stateStore.(DeviceStore)
	if !durable {
		return nil, ErrNoDeviceStore
	}
	nonce, nonceEpoch, err := self.nonce()
	if err != nil {
		return nil, err
	}
	records, err := store.GroupRecords()
	if err != nil {
		return nil, err
	}
	restored := []*Group{}
	var firstFailure error
	for _, record := range records {
		if self.holdsGroup(record.GroupId) {
			continue
		}
		group, err := self.restoreOne(record, nonce, nonceEpoch)
		if err != nil {
			if firstFailure == nil {
				firstFailure = err
			}
			continue
		}
		restored = append(restored, group)
	}
	return restored, firstFailure
}

// restoreOne rebuilds one group: the MLS state at the record's epoch, then the session over it.
func (self *Device) restoreOne(record *GroupRecord, nonce []byte, nonceEpoch uint64) (*Group, error) {
	group, err := mls.LoadGroup(&mls.GroupConfig{
		Crypto:  self.crypto,
		Store:   self.stateStore,
		GroupId: append([]byte(nil), record.GroupId...),
	}, record.Epoch, self.signer)
	if err != nil {
		return nil, fmt.Errorf("%w: group %x at epoch %d: %w", ErrRestore, record.GroupId, record.Epoch, err)
	}
	handle := &restoredHandle{group: group}
	if epoch := handle.Epoch(); epoch != record.Epoch {
		handle.Close()
		return nil, fmt.Errorf("%w: group %x restored at epoch %d and the record names %d",
			ErrRestore, record.GroupId, epoch, record.Epoch)
	}
	session, err := messagegroup.NewGroupSession(handle, record.PqSecret, record.GroupHandleKey,
		self.reserver, self.nowMs, nonce)
	if err != nil {
		handle.Close()
		return nil, fmt.Errorf("%w: group %x: the session at epoch %d: %w",
			ErrRestore, record.GroupId, record.Epoch, err)
	}
	restored := &Group{
		device:         self,
		id:             append([]byte(nil), record.GroupId...),
		handle:         handle,
		groupHandleKey: append([]byte(nil), record.GroupHandleKey...),
		pqSecret:       append([]byte(nil), record.PqSecret...),
		session:        session,
		sessionBound:   nonceEpoch,
		epoch:          record.Epoch,
		opened:         record.Opened,
		// AND NOT RECONCILED. This is the one place a [Group] is built over an identity that
		// existed before this process did, so it is the one place a SECOND copy of that
		// identity is possible. [Group.Send] refuses until [Group.Receive] has walked this
		// group's history once and held the stream indices it finds against this device's own
		// durable reserver. See Restore's header for what that covers and what it does not.
		reconciled: false,
	}
	restored.initTables()
	self.hold(restored)
	return restored, nil
}

// holdsGroup reports whether this device already has a live view of that group, so that a second
// Restore is a no-op rather than a second session over one durable reserver row.
func (self *Device) holdsGroup(groupId []byte) bool {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	_, held := self.groups[string(groupId)]
	return held
}

// persistGroup writes the urmessage-side record of one group, when the store can hold one.
//
// IT IS A NO-OP ON A STORE THAT IS NOT DURABLE, which is what keeps [MemoryStateStore] the exact
// behaviour it had: a device over a map goes on losing everything at exit and does not pay for a
// record nothing will read.
func (self *Device) persistGroup(record *GroupRecord) error {
	store, durable := self.stateStore.(DeviceStore)
	if !durable {
		return nil
	}
	return store.PutGroupRecord(record)
}

// ── the handle a restored group is seen through ──────────────────────────────────────────────

// restoredHandle is [messagegroup.GroupHandle] over an [mls.Group] that [mls.LoadGroup] rebuilt.
//
// IT EXISTS BECAUSE connect's ENGINE HAS NO DOOR FOR THIS, and that is J1-8 stated as code rather
// than as a comment. `messagegroup.GroupEngine` declares four methods -- Suite, NewKeyPackage,
// CreateGroup, JoinFromWelcome -- and NONE of them opens a persisted group, while
// `mls.LoadGroup(cfg, epoch, signer)` is a complete restore including the TreeKEM ladder and the
// own-leaf sender ratchets. The query, so the claim is checkable rather than quoted: over connect
// at the commit this lands against,
//
//	grep -n "^type GroupEngine interface" -A 8 messagegroup/engine.go
//
// answers those four. So a durable store in `sdk` writes rows that nothing in `connect` can read
// back, and this adapter is the only thing between that and S2-14 being write-only.
//
// THE EXACT CHANGE connect OWES, so that this file can be DELETED rather than maintained: a fifth
// `GroupEngine` method -- `LoadGroup(groupId []byte, epoch uint64) (GroupHandle, error)` -- plus
// something that answers WHICH epoch, since `mls.LoadGroup` takes it as a parameter and nothing on
// `mls.StateStore` enumerates. Until it lands this type is a SECOND site of `connectMlsHandle`, by
// construction of the visibility rules and not by preference: `connectMlsHandle` is unexported, so
// there is no way to reach it from here. It is filed rather than absorbed -- exactly as
// [storageExporterLabel] next door is filed -- and it is a Spec A §6 amendment, therefore Gate 5
// and an owner ruling.
//
// TWO METHODS ARE REFUSED BY NAME AND THE REST DELEGATE. Process and ApplyCommit are the pair that
// carries a STAGED COMMIT, and `messagegroup.EngineProcessed` holds it in an UNEXPORTED field that
// only a member of that package can write. So an implementation here could produce an
// `EngineProcessed` whose staged half is nil -- a value that looks like a processed commit and
// that `ApplyCommit` cannot apply -- which is precisely the plausible-result-read-as-built shape.
// It refuses instead, with [ErrRestoredHandle]. Nothing in this package calls either: the query is
// `grep -n "\.Process(\|\.ApplyCommit(" urmessage/*.go`, which answers nothing.
type restoredHandle struct {
	group *mls.Group
}

var _ messagegroup.GroupHandle = (*restoredHandle)(nil)

func (self *restoredHandle) GroupId() []byte { return self.group.GroupId() }

func (self *restoredHandle) Epoch() uint64 { return self.group.Epoch() }

func (self *restoredHandle) OwnLeafIndex() uint32 { return uint32(self.group.OwnLeafIndex()) }

func (self *restoredHandle) MemberCount() int { return len(self.group.Members()) }

// MemberAt is connectMlsHandle's projection, and the two refusals are its two refusals: an ordinal
// off the end, and a member whose leaf carries no urmessage_leaf_keys. A projection that answered
// a nil leafKeys would hand the epoch fan-out a member it silently cannot wrap to.
func (self *restoredHandle) MemberAt(i int) (uint32, []byte, []byte, error) {
	members := self.group.Members()
	if i < 0 || len(members) <= i {
		return 0, nil, nil, fmt.Errorf("%w: ordinal %d of %d members",
			messagegroup.ErrEngineMemberOrdinal, i, len(members))
	}
	member := members[i]
	if member.LeafKeys == nil {
		return 0, nil, nil, fmt.Errorf("%w: the member at ordinal %d carries no urmessage_leaf_keys extension",
			messagegroup.ErrEngineMemberLeafKeys, i)
	}
	leafKeys, err := member.LeafKeys.Encode()
	if err != nil {
		return 0, nil, nil, fmt.Errorf("%w: %w", messagegroup.ErrEngineMemberLeafKeys, err)
	}
	return uint32(member.LeafIndex), member.IdentityPub, leafKeys.ExtensionData, nil
}

func (self *restoredHandle) Export(label string, context []byte, length int) ([]byte, error) {
	return self.group.Export(label, context, length)
}

func (self *restoredHandle) SenderDataSecret() ([]byte, error) {
	return self.group.EpochSecret(mls.EpochSecretSenderData)
}

func (self *restoredHandle) EncryptionSecret() ([]byte, error) {
	return self.group.EpochSecret(mls.EpochSecretEncryption)
}

func (self *restoredHandle) EpochAuthenticator() []byte { return self.group.EpochAuthenticator() }

func (self *restoredHandle) RatchetTreeSnapshot() ([]byte, error) { return self.group.RatchetTree() }

func (self *restoredHandle) GroupContextBytes() ([]byte, error) { return self.group.GroupContext() }

func (self *restoredHandle) ProposeAdd(keyPackage []byte) ([]byte, error) {
	return self.group.ProposeAdd(keyPackage)
}

func (self *restoredHandle) ProposeRemove(leafIndex uint32) ([]byte, error) {
	return self.group.ProposeRemove(mls.LeafIndex(leafIndex))
}

func (self *restoredHandle) ProposeUpdate() ([]byte, error) { return self.group.ProposeUpdate() }

func (self *restoredHandle) ProposeGroupPolicy(policy []byte) ([]byte, error) {
	return self.group.ProposeGroupContextExtensions([]mls.Extension{{
		ExtensionType: mls.ExtensionTypeUrmessageGroupPolicy,
		ExtensionData: policy,
	}})
}

func (self *restoredHandle) Commit(byReference [][]byte) ([]byte, []byte, []byte, error) {
	result, err := self.group.CreateCommit(byReference, nil, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	return result.Commit, result.Welcome, result.RatchetTree, nil
}

func (self *restoredHandle) MergePendingCommit() error { return self.group.MergePendingCommit() }

func (self *restoredHandle) ClearPendingCommit() { self.group.ClearPendingCommit() }

// Process is REFUSED and not implemented. See this type's header: the staged commit it would have
// to carry lives in an unexported field of `messagegroup.EngineProcessed`, so the value this
// method could build is one `ApplyCommit` can never apply.
func (self *restoredHandle) Process(message []byte) (*messagegroup.EngineProcessed, error) {
	return nil, fmt.Errorf("%w: Process stages a commit and the staged half is messagegroup's own", ErrRestoredHandle)
}

// ApplyCommit is REFUSED for Process's reason, and refusing both is what keeps the pair honest: a
// Process that answered and an ApplyCommit that refused would read as a transient failure.
func (self *restoredHandle) ApplyCommit(processed *messagegroup.EngineProcessed) error {
	return fmt.Errorf("%w: ApplyCommit enters the epoch a staged commit opens", ErrRestoredHandle)
}

func (self *restoredHandle) Protect(aad []byte, plaintext []byte) ([]byte, error) {
	return self.group.Protect(aad, plaintext)
}

// Unprotect projects mls's application message down to three values, refusing the nil-with-nil-error
// shape mls cannot produce -- because the alternative to refusing it is three zero values that read
// as an empty message from leaf 0.
func (self *restoredHandle) Unprotect(message []byte) ([]byte, []byte, uint32, error) {
	application, err := self.group.Unprotect(message)
	if err != nil {
		return nil, nil, 0, err
	}
	if application == nil {
		return nil, nil, 0, fmt.Errorf("%w: an opened application message with no content",
			messagegroup.ErrEngineProcessedArm)
	}
	return application.AuthenticatedData, application.Plaintext, uint32(application.SenderLeaf), nil
}

func (self *restoredHandle) Close() error { return self.group.Close() }
