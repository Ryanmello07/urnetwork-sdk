package urmessage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/messagegroup"
	"github.com/urnetwork/connect/protocol"
)

// GroupIdBytes is the width of the identifier the server keys its rows by, and the width a record
// header carries. It is the same 32 octets on both sides and a group id of any other width names
// nothing.
const GroupIdBytes = 32

// The alg id an EpochAttachment announces: 0x0031, HKDF-SHA-256, which is what derived write_key
// and read_key out of storage_root.
//
// connect/message holds the same number in an UNEXPORTED table (attachmentAlgIds), and refuses an
// attachment that announces any other, so this is a second site by construction of the visibility
// rules exactly as storageExporterLabel is. The change connect owes is to export it.
const epochAttachmentAlgId uint16 = 0x0031

// What an alpha wrap record carries, in the clear inside its own AEAD, so that a reader who finds
// one knows what it is and what it is not.
//
// 6.1 publishes an epoch by fanning a wrap out to every member and then closing the fan-out with a
// marker, and the server will not accept an ordinary record until the marker lands. In the full
// design a wrap is how a member is handed the epoch's secret. IN THE ALPHA IT IS NOT: the epoch's
// key schedule is derived from the MLS exporter on both sides, and the material a joiner needs
// travels in the MLS Welcome. So these records carry NO KEY MATERIAL, they are the ceremony the
// server's step (2) requires, and a device that cannot process a Welcome cannot join this build
// however many wraps it reads.
const alphaWrapBody = "urmessage/v1 alpha epoch wrap: no key material, the epoch secret travels in the mls welcome"

// The body of the marker that closes 6.1's fan-out.
const alphaEpochCompleteBody = "urmessage/v1 alpha epoch complete"

// How many 4.3.4 pages one [Group.Receive] will walk before it stops and SAYS it stopped.
//
// It is a bound and not a limit on history: at the advertised default of 512 records per fetch
// this is more records than the alpha can produce, and reaching it means either a group with an
// enormous backlog or a server that is paging a client in circles. Either way the answer is the
// same and it is the whole reason the constant exists: [Group.Receive] returns what it read AND
// [ErrFetchIncomplete], so "that is all there is" and "I stopped early" are two readings.
//
// A LOOP WITH NO BOUND WOULD BE THE WORSE FAILURE. A server that answered complete=false forever
// would hang the call rather than answer it, and a UI holding that call would look like a network
// problem instead of like a server problem.
const maxFetchPages = 1024

// Message is one line of text that crossed the group.
type Message struct {
	// The server's own id for the record: per group, gapless, and the cursor a later fetch
	// resumes from. Zero on a message this device has sent and the server has not yet numbered.
	RecordId uint64

	// 3.1's sender_handle, 16 octets. It is the routing identity of the member that sealed the
	// record and is not a name: the alpha has no identity system.
	SenderHandle []byte

	// True when this device sealed it.
	Mine bool

	// The text.
	Text string

	// The sender's own clock reading, unix milliseconds, out of the head the AEAD authenticated.
	SentAtMs int64
}

// Stats is what a group has seen, so that "nothing arrived" and "something arrived and this build
// would not open it" are two readings rather than one silence.
type Stats struct {
	// Records the server answered a fetch with.
	Fetched uint64

	// Records opened into a [Message].
	Opened uint64

	// Records skipped because they are 6.1's ceremony rather than a message: the founding commit,
	// the epoch's wraps, the marker that closes them.
	SkippedCeremony uint64

	// Records skipped because this device sealed them. It holds its own plaintext already and
	// tracking its own ladder as a receiver would derive a second copy of keys it has.
	SkippedOwn uint64

	// Records skipped because they are not a class this build opens.
	SkippedClass uint64

	// Records from a member of this group that did not open. This is the number that must stay
	// zero, and [Group.Receive] returns an error naming the first one whenever it does not.
	FailedOpen uint64

	// Records submitted, and records the server refused on the first attempt and accepted after
	// S2-2's single re-Hello and re-MAC. The second is the cost of Finding E and is readable
	// rather than invisible.
	Submitted uint64
	Rebound   uint64

	// Fetch PAGES the server answered, across every [Group.Receive]. It is here because one
	// Receive is not one page: 4.3.4 truncates a page by `limit` or by `max_response_bytes`
	// and calls both NORMAL, so a conversation longer than the server's page is several
	// requests. A number bigger than the Receive count is the ordinary reading of a backlog.
	Pages uint64

	// Fetch pages this build could NOT verify the 4.3.4 attestation of, which today is every
	// page the deployed server answers. It is a counter rather than a silence because the
	// thing it measures -- a server that OMITS records -- is the one thing the AEAD does not
	// catch. See [Group.Receive] for what is and is not checked, and what closing it needs.
	Unattested uint64
}

// trackedKey is one receiver ladder this group has installed. A second TrackSender over a live
// ladder would reset it to its head index and re-derive rungs it has already committed, so each
// one is installed exactly once.
type trackedKey struct {
	leaf          uint32
	retentionWire byte
	ephWindow     uint64
}

// Group is one group on one device.
type Group struct {
	device         *Device
	id             []byte
	handle         messagegroup.GroupHandle
	groupHandleKey []byte
	pqSecret       []byte

	mutex sync.Mutex

	// The session at epoch zero, which exists on the FOUNDER only and only until the group is
	// open. It is what seals the founding commit: 4.3.2 self-certifies that record under
	// bootstrap_write_key, which is epoch zero's write key, and the session that holds epoch
	// zero's key schedule is the one constructed before the commit moved the handle.
	founding      *messagegroup.GroupSession
	foundingBound uint64

	// The session at the group's current epoch, and the one every message goes through.
	session      *messagegroup.GroupSession
	sessionBound uint64
	epoch        uint64

	// The MLS commit that opened the current epoch. It is the founding commit record's body, so
	// the record the server stores as is_commit actually carries a commit.
	commit []byte

	opened bool
	closed bool

	cursor  uint64
	log     []*Message
	tracked map[trackedKey]bool
	stats   Stats
}

// ── founding and joining ─────────────────────────────────────────────────────────────────────

// CreateGroup founds a group on this device. NOTHING REACHES THE SERVER HERE.
//
// The group is local and at MLS epoch zero, which is not an epoch any record can be written in:
// 6.1 opens a group at the epoch its first commit creates. [Group.AddMember] makes that commit and
// [Group.Open] publishes it. A caller that skips either is refused by name rather than by a
// REASON_REJECTED it has to decode.
//
// groupId is 32 octets and is the caller's to choose. It must be unpredictable -- the server keys
// its rows by it and anyone who can guess one can ask whether it exists -- so draw it from a
// CSPRNG.
func (self *Device) CreateGroup(ctx context.Context, groupId []byte) (*Group, error) {
	if len(groupId) != GroupIdBytes {
		return nil, fmt.Errorf("urmessage: a group id is %d octets and this one is %d", GroupIdBytes, len(groupId))
	}
	nonce, nonceEpoch, err := self.nonce()
	if err != nil {
		return nil, err
	}

	handle, err := self.createMlsGroup(groupId)
	if err != nil {
		return nil, err
	}
	if epoch := handle.Epoch(); epoch != 0 {
		handle.Close()
		return nil, fmt.Errorf("urmessage: a freshly created mls group is at epoch %d, want 0", epoch)
	}

	pqSecret, err := messagegroup.NewPqSecret(self.random)
	if err != nil {
		handle.Close()
		return nil, fmt.Errorf("urmessage: pq_secret: %w", err)
	}
	// AT EPOCH ZERO AND NOWHERE ELSE. group_handle_key is the epoch zero storage root's expansion
	// and it never moves; a value recomputed from a later root gives every epoch a different
	// sender_handle and ends every member's stream at every commit.
	mlsSecret, err := handle.Export(storageExporterLabel, nil, storageExporterBytes)
	if err != nil {
		handle.Close()
		return nil, fmt.Errorf("urmessage: the epoch zero exporter: %w", err)
	}
	groupHandleKey := messagegroup.GroupHandleKey(messagegroup.StorageRoot(mlsSecret, pqSecret))

	founding, err := messagegroup.NewGroupSession(handle, pqSecret, nil, self.reserver, self.nowMs, nonce)
	if err != nil {
		handle.Close()
		return nil, fmt.Errorf("urmessage: the session at epoch 0: %w", err)
	}
	group := &Group{
		device:         self,
		id:             append([]byte(nil), groupId...),
		handle:         handle,
		groupHandleKey: groupHandleKey,
		pqSecret:       pqSecret,
		founding:       founding,
		foundingBound:  nonceEpoch,
		tracked:        map[trackedKey]bool{},
	}
	self.hold(group)
	// NOTHING IS PERSISTED HERE AND THAT IS DELIBERATE. A group at epoch zero with no second
	// member cannot be restored into anything a caller can use -- [Group.AddMember] needs the
	// founding session, which is not persisted, and [Group.Open] needs the commit AddMember
	// makes -- so a record written here would describe a group that comes back dead. mls has
	// already written its own epoch-zero state by now; [DurableStateStore.GroupRecords] skips a
	// group directory with no record in it for exactly this state, and says so.
	return group, nil
}

// Join takes an [Invite] a founder handed over out of band and becomes a member.
//
// WHAT THIS DOES NOT CHECK, and it is MG-1 rather than an omission of this file: nothing here
// decides whether the device that built this Welcome is the device the user meant to talk to. The
// Welcome names a group and a membership, JoinFromWelcome joins it, and the identity a caller would
// read off the membership afterwards is whatever the Welcome's author put there. Deciding that is
// the contact card's job and contact cards are out of scope.
func (self *Device) Join(ctx context.Context, invite *Invite) (*Group, error) {
	if invite == nil {
		return nil, fmt.Errorf("urmessage: no invite")
	}
	if err := invite.check(); err != nil {
		return nil, err
	}
	nonce, nonceEpoch, err := self.nonce()
	if err != nil {
		return nil, err
	}
	handle, err := self.engine.JoinFromWelcome(invite.Welcome, invite.RatchetTree)
	if err != nil {
		return nil, fmt.Errorf("urmessage: JoinFromWelcome: %w", err)
	}
	if !bytes.Equal(handle.GroupId(), invite.GroupId) {
		handle.Close()
		return nil, fmt.Errorf("urmessage: the welcome joined group %x and the invite names %x",
			handle.GroupId(), invite.GroupId)
	}
	session, err := messagegroup.NewGroupSession(handle, invite.PqSecret, invite.GroupHandleKey,
		self.reserver, self.nowMs, nonce)
	if err != nil {
		handle.Close()
		return nil, fmt.Errorf("urmessage: the session at epoch %d: %w", handle.Epoch(), err)
	}
	group := &Group{
		device:         self,
		id:             append([]byte(nil), invite.GroupId...),
		handle:         handle,
		groupHandleKey: append([]byte(nil), invite.GroupHandleKey...),
		pqSecret:       append([]byte(nil), invite.PqSecret...),
		session:        session,
		sessionBound:   nonceEpoch,
		epoch:          handle.Epoch(),
		// The founder opened it. A joiner cannot observe that and does not pretend to: if it
		// has not, every send below is refused by the server and the refusal is returned.
		opened:  true,
		tracked: map[trackedKey]bool{},
	}
	if err := self.persistGroup(&GroupRecord{
		GroupId:        group.id,
		PqSecret:       group.pqSecret,
		GroupHandleKey: group.groupHandleKey,
		Epoch:          group.epoch,
		Opened:         true,
	}); err != nil {
		// the session first and the handle after it, which is [Group.Close]'s own order: the
		// session owns the loop that the handle is reached through.
		session.Close()
		handle.Close()
		return nil, fmt.Errorf(
			"urmessage: this group joined and its record could not be persisted, so a restart would not come back into it: %w", err)
	}
	self.hold(group)
	return group, nil
}

// AddMember adds one device to this group and answers the [Invite] it joins with.
//
// IT IS THE COMMIT THAT OPENS EPOCH ONE, which is why the alpha takes exactly one of them and
// takes it before [Group.Open]. A second add is a second epoch: every member's session has to
// advance, the server has to be handed the new epoch's keys in a new commit, and the wrap fan-out
// has to run again. None of that is built, so a second call is refused by name rather than half
// performed.
func (self *Group) AddMember(keyPackage []byte) (*Invite, error) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if self.closed {
		return nil, fmt.Errorf("urmessage: this group is closed")
	}
	if self.opened {
		return nil, ErrGroupOpen
	}
	if self.founding == nil {
		return nil, ErrAlphaOneAdd
	}
	if self.session != nil {
		return nil, ErrAlphaOneAdd
	}
	nonce, nonceEpoch, err := self.device.nonce()
	if err != nil {
		return nil, err
	}

	if _, err := self.handle.ProposeAdd(keyPackage); err != nil {
		return nil, fmt.Errorf("urmessage: ProposeAdd: %w", err)
	}
	commit, welcome, ratchetTree, err := self.handle.Commit(nil)
	if err != nil {
		self.handle.ClearPendingCommit()
		return nil, fmt.Errorf("urmessage: Commit: %w", err)
	}
	if err := self.handle.MergePendingCommit(); err != nil {
		return nil, fmt.Errorf("urmessage: MergePendingCommit: %w", err)
	}
	// THE HANDLE IS AT EPOCH ONE FROM HERE AND self.founding IS STILL AT EPOCH ZERO, which is the
	// one subtlety in this file and is load-bearing rather than incidental. A GroupSession
	// installs its epoch's whole key schedule at construction and reads NOTHING off the handle on
	// the seal path afterwards -- newRecordBuilderOnLoop takes the group id, the sender handle,
	// the epoch and the class keys out of its own fields -- so the founding session goes on
	// sealing epoch zero records after the handle has moved, which is exactly what 4.3.2's
	// self-certified founding commit needs. Delete that property in connect and this file starts
	// sealing the founding commit under epoch one's key, which the server refuses because it
	// verifies it under the bootstrap key the same request carries.
	session, err := messagegroup.NewGroupSession(self.handle, self.pqSecret, self.groupHandleKey,
		self.device.reserver, self.device.nowMs, nonce)
	if err != nil {
		return nil, fmt.Errorf("urmessage: the session at epoch %d: %w", self.handle.Epoch(), err)
	}
	self.session = session
	self.sessionBound = nonceEpoch
	self.epoch = self.handle.Epoch()
	self.commit = append([]byte(nil), commit...)
	// NOTHING IS PERSISTED HERE EITHER, for CreateGroup's reason carried one step further, and
	// it is written down because a record here LOOKS obviously right and is not.
	//
	// The handle is now at the epoch the commit opened and mls has persisted that epoch's state
	// inside MergePendingCommit above, so a restore could rebuild an MLS member. What it could
	// not rebuild is a group anybody can USE: [Group.Open] needs the epoch-zero founding session
	// to self-certify the founding commit, that session is not persisted, and a restored group
	// therefore answers ErrNoMemberAdded to Open and ErrGroupNotOpen to Send, for ever. A record
	// written here would make "a founder that died before Open" come back as a conversation the
	// user can see and cannot ever send in.
	//
	// MEASURED rather than reasoned: a record written here was deleted and the whole suite
	// stayed green, because [Group.Open] writes the founder's record and [Device.Join] writes
	// the joiner's, and those are the two moments a group becomes usable.
	return &Invite{
		GroupId:        append([]byte(nil), self.id...),
		Welcome:        append([]byte(nil), welcome...),
		RatchetTree:    append([]byte(nil), ratchetTree...),
		PqSecret:       append([]byte(nil), self.pqSecret...),
		GroupHandleKey: append([]byte(nil), self.groupHandleKey...),
	}, nil
}

// Open publishes this group on the message server: 6.1's founding commit, the epoch's wrap set,
// and the marker that closes the fan-out.
//
// ALL THREE, BECAUSE THE SERVER WILL NOT TAKE A MESSAGE UNTIL ALL THREE HAVE LANDED. CreateGroup
// leaves the group at epoch one with epoch_complete false, which step (2) makes
// readable-but-not-writable for everything except a wrap, a snapshot or the marker; an ordinary
// record before the marker is answered REASON_EPOCH_INCOMPLETE.
func (self *Group) Open(ctx context.Context) error {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if self.closed {
		return fmt.Errorf("urmessage: this group is closed")
	}
	if self.opened {
		return ErrGroupOpen
	}
	if self.session == nil || self.founding == nil {
		return ErrNoMemberAdded
	}
	if err := self.rebindLocked(); err != nil {
		return err
	}

	keys, err := self.session.EpochKeys()
	if err != nil {
		return fmt.Errorf("urmessage: this epoch's keys: %w", err)
	}
	defer keys.Destroy()
	writeKey, err := keys.WriteKey()
	if err != nil {
		return err
	}
	readKey, err := keys.ReadKey()
	if err != nil {
		return err
	}
	bootstrap, err := self.founding.EpochKeys()
	if err != nil {
		return fmt.Errorf("urmessage: epoch zero's keys: %w", err)
	}
	defer bootstrap.Destroy()
	bootstrapWriteKey, err := bootstrap.WriteKey()
	if err != nil {
		return err
	}

	groupContext, err := self.handle.GroupContextBytes()
	if err != nil {
		return fmt.Errorf("urmessage: the group context: %w", err)
	}
	contextHash := sha256.Sum256(groupContext)

	wrapTargets, err := self.wrapTargetsLocked()
	if err != nil {
		return err
	}
	if len(wrapTargets) == 0 {
		return ErrNoMemberAdded
	}

	// (1) the founding commit, sealed at epoch zero and carrying the epoch it opens.
	founding, err := self.founding.SealRecord(message.RetentionPermanent, 0, true,
		encodeHead(self.device.nowMs()), self.commit, 0, &message.ServerAttachment{
			Kind: message.AttachmentEpoch,
			Epoch: &message.EpochAttachment{
				Epoch:             self.epoch,
				AlgId:             epochAttachmentAlgId,
				WriteKey:          writeKey,
				ReadKey:           readKey,
				GroupContextHash:  contextHash[:],
				ExpectedWrapCount: uint32(len(wrapTargets)),
			},
		})
	if err != nil {
		return fmt.Errorf("urmessage: sealing the founding commit: %w", err)
	}
	created := append([]byte(nil), bootstrapWriteKey...)
	if _, err := self.sendSealedLocked(ctx, self.founding, founding, "the founding commit",
		func(record *protocol.Record) (protocol.Reason, uint64, error) {
			response, err := self.device.transport.Call(ctx, &protocol.CreateGroupRequest{
				GroupId:           self.id,
				InitialCommit:     record,
				BootstrapWriteKey: created,
			})
			if err != nil {
				return protocol.Reason_REASON_INTERNAL, 0, err
			}
			if response.GetReason() != protocol.Reason_REASON_OK {
				return response.GetReason(), 0, nil
			}
			body := response.GetCreateGroup()
			if body == nil {
				return protocol.Reason_REASON_INTERNAL, 0, fmt.Errorf("%w: the response carried no create_group arm", ErrCreateRefused)
			}
			if body.GetCurrentEpoch() != self.epoch {
				return protocol.Reason_REASON_INTERNAL, 0, fmt.Errorf(
					"%w: the group opened at epoch %d and this device is at %d",
					ErrCreateRefused, body.GetCurrentEpoch(), self.epoch)
			}
			return protocol.Reason_REASON_OK, body.GetRecordId(), nil
		}); err != nil {
		return err
	}

	// (2) the wrap set: one per member, carrying no key material. See [alphaWrapBody].
	for _, target := range wrapTargets {
		wrap, err := self.session.SealRecord(message.RetentionPermanent, 0, false,
			encodeHead(self.device.nowMs()), []byte(alphaWrapBody), 0, &message.ServerAttachment{
				Kind: message.AttachmentWrap,
				Wrap: &message.WrapTag{WrapTargetHandle: append([]byte(nil), target[:]...), Epoch: self.epoch},
			})
		if err != nil {
			return fmt.Errorf("urmessage: sealing an epoch wrap: %w", err)
		}
		if _, err := self.submitLocked(ctx, self.session, wrap, "an epoch wrap"); err != nil {
			return err
		}
	}

	// (3) the marker that closes the fan-out and makes the group writable.
	marker, err := self.session.SealRecord(message.RetentionDurable, 0, false,
		encodeHead(self.device.nowMs()), []byte(alphaEpochCompleteBody), 0, &message.ServerAttachment{
			Kind:     message.AttachmentComplete,
			Complete: &message.EpochComplete{Epoch: self.epoch, WrapCount: uint32(len(wrapTargets))},
		})
	if err != nil {
		return fmt.Errorf("urmessage: sealing the epoch complete marker: %w", err)
	}
	if _, err := self.submitLocked(ctx, self.session, marker, "the epoch complete marker"); err != nil {
		return err
	}

	self.opened = true
	// The opened bit, so that a restarted device knows the group is publishable rather than
	// finding out at its first send. The error says what actually happened: the group IS open
	// on the server, and it is the RECORD that did not land.
	if err := self.device.persistGroup(&GroupRecord{
		GroupId:        self.id,
		PqSecret:       self.pqSecret,
		GroupHandleKey: self.groupHandleKey,
		Epoch:          self.epoch,
		Opened:         true,
	}); err != nil {
		return fmt.Errorf("urmessage: this group is open on the server and its record could not be persisted, so a restart would refuse to send in it: %w", err)
	}
	return nil
}

// wrapTargetsLocked is one wrap_target_handle per member of the group at its current epoch.
func (self *Group) wrapTargetsLocked() ([][16]byte, error) {
	targets := [][16]byte{}
	for at := 0; at < self.handle.MemberCount(); at += 1 {
		leaf, _, _, err := self.handle.MemberAt(at)
		if err != nil {
			return nil, fmt.Errorf("urmessage: the group's member %d: %w", at, err)
		}
		targets = append(targets, messagegroup.WrapTargetHandle(self.groupHandleKey, self.epoch, leaf))
	}
	return targets, nil
}

// ── sending ──────────────────────────────────────────────────────────────────────────────────

// Send seals one line of text as a DURABLE record and submits it.
//
// The size bucket is whatever the text needs: [messagegroup.GroupSession.SealRecord] walks the
// ladder and takes the smallest rung the padded body fits, so a short message is padded to 256
// octets and leaks its rung rather than its length. A text too long for the largest inline rung is
// refused with [ErrTextTooLong]; blob-backed bodies are out of scope.
//
// IT NEVER RETURNS NIL ON A MESSAGE THAT DID NOT LAND. The record is accepted by the server, or
// this returns an error naming the refusal -- including after S2-2's single re-Hello and re-MAC.
func (self *Group) Send(ctx context.Context, text string) (*Message, error) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if self.closed {
		return nil, fmt.Errorf("urmessage: this group is closed")
	}
	if self.session == nil {
		return nil, ErrNoMemberAdded
	}
	if !self.opened {
		return nil, ErrGroupNotOpen
	}
	if err := self.rebindLocked(); err != nil {
		return nil, err
	}
	sentAtMs := self.device.nowMs()
	record, err := self.session.SealRecord(message.RetentionDurable, 0, false,
		encodeHead(sentAtMs), []byte(text), 0, nil)
	if err != nil {
		if errors.Is(err, messagegroup.ErrBodyTooLong) {
			return nil, fmt.Errorf("%w: %d octets: %w", ErrTextTooLong, len(text), err)
		}
		return nil, fmt.Errorf("urmessage: sealing this message: %w", err)
	}
	recordId, err := self.submitLocked(ctx, self.session, record, "a message")
	if err != nil {
		return nil, err
	}
	handle := append([]byte(nil), record.Header.SenderHandle[:]...)
	sent := &Message{
		RecordId:     recordId,
		SenderHandle: handle,
		Mine:         true,
		Text:         text,
		SentAtMs:     sentAtMs,
	}
	self.log = append(self.log, sent)
	return sent, nil
}

// submitLocked is 4.3.5's submit of one record, with S2-2's recovery around it.
func (self *Group) submitLocked(ctx context.Context, session *messagegroup.GroupSession,
	record *message.Record, what string) (uint64, error) {

	return self.sendSealedLocked(ctx, session, record, what,
		func(projection *protocol.Record) (protocol.Reason, uint64, error) {
			response, err := self.device.transport.Call(ctx, &protocol.SubmitRequest{
				GroupId: self.id,
				Records: []*protocol.Record{projection},
			})
			if err != nil {
				return protocol.Reason_REASON_INTERNAL, 0, err
			}
			if response.GetReason() != protocol.Reason_REASON_OK {
				return response.GetReason(), 0, nil
			}
			body := response.GetSubmit()
			if body == nil || len(body.GetResults()) != 1 {
				return protocol.Reason_REASON_INTERNAL, 0, fmt.Errorf(
					"%w: one record was submitted and %d results came back", ErrSubmitRefused, len(body.GetResults()))
			}
			return body.GetResults()[0].GetReason(), body.GetResults()[0].GetRecordId(), nil
		})
}

// sendSealedLocked submits an already sealed record, and performs S2-2's ONE recovery when the
// server refuses it.
//
// THE RECOVERY IS FOR THE HALF OF A RECONNECT NOTHING IN sdk CAN SEE. NonceEpoch counts Hellos, so
// a connection replaced underneath this binding without a Hello through it leaves a superseded
// nonce readable at an unchanged number and rebindLocked finds nothing to repair. A refusal is
// then the only evidence there is, so one refusal buys one Hello, one rebind, one ReauthRecord --
// which re-MACs the record that is already sealed, consumes no stream index and re-encrypts
// nothing -- and one resubmission.
//
// IT IS ONE AND IT IS NOT A LOOP. A second refusal is a fact about the group, the epoch or the
// record rather than about the nonce, and a client that kept trying would turn a visible failure
// into a busy one. Both reasons are carried in the error.
func (self *Group) sendSealedLocked(ctx context.Context, session *messagegroup.GroupSession,
	record *message.Record, what string,
	send func(*protocol.Record) (protocol.Reason, uint64, error)) (uint64, error) {

	projection, err := projectionOf(record)
	if err != nil {
		return 0, fmt.Errorf("urmessage: the projection of %s: %w", what, err)
	}
	reason, recordId, err := send(projection)
	if err != nil {
		return 0, fmt.Errorf("urmessage: submitting %s: %w", what, err)
	}
	if reason == protocol.Reason_REASON_OK {
		self.stats.Submitted += 1
		return recordId, nil
	}

	// S2-2: one Hello, one rebind, one re-MAC, one resubmission.
	helloReason, hello, err := self.device.transport.Hello(ctx)
	if err != nil {
		return 0, fmt.Errorf("%w: %s was answered %v, and the Hello that would have repaired the nonce failed: %w",
			ErrSubmitRefused, what, reason, err)
	}
	if helloReason != protocol.Reason_REASON_OK || len(hello.GetServerNonce()) == 0 {
		return 0, fmt.Errorf("%w: %s was answered %v, and the Hello that would have repaired the nonce was answered %v",
			ErrSubmitRefused, what, reason, helloReason)
	}
	if err := self.rebindLocked(); err != nil {
		return 0, err
	}
	if err := session.ReauthRecord(record); err != nil {
		return 0, fmt.Errorf("%w: %s was answered %v and could not be re-MAC'd against the new connection's nonce: %w",
			ErrSubmitRefused, what, reason, err)
	}
	retryProjection, err := projectionOf(record)
	if err != nil {
		return 0, fmt.Errorf("urmessage: the re-MAC'd projection of %s: %w", what, err)
	}
	retryReason, retryRecordId, err := send(retryProjection)
	if err != nil {
		return 0, fmt.Errorf("urmessage: resubmitting %s: %w", what, err)
	}
	if retryReason != protocol.Reason_REASON_OK {
		return 0, fmt.Errorf("%w: %s was answered %v, and %v again after a fresh Hello and a re-MAC",
			ErrSubmitRefused, what, reason, retryReason)
	}
	self.stats.Submitted += 1
	self.stats.Rebound += 1
	return retryRecordId, nil
}

// ── receiving ────────────────────────────────────────────────────────────────────────────────

// Receive fetches everything the server has for this group since the last call, opens what is a
// message, and answers the messages in record order.
//
// IT PAGES UNTIL THE SERVER SAYS complete, AND WHEN IT CANNOT IT SAYS SO. 4.3.4's FetchResponse
// carries `complete` -- "false when truncated by limit OR by max_response_bytes; both are NORMAL"
// -- `next_record_id` and `high_water_record_id`, and an earlier build of this method read none of
// the three. One page then read as the whole history with a nil error, which is the worst failure
// an alpha can have, because a user cannot tell half a conversation from a quiet one. So:
//
//   - a truncated page is followed by the next one, resuming from `next_record_id`, until the
//     server answers complete;
//   - a server that answers incomplete and advances NO cursor is refused with
//     [ErrFetchNoProgress] rather than looped on forever;
//   - and reaching [maxFetchPages] returns the messages read so far TOGETHER WITH
//     [ErrFetchIncomplete], so a caller that ignores the error still sees messages and a caller
//     that reads it knows there are more.
//
// WHAT IT SKIPS IS COUNTED RATHER THAN DROPPED. 6.1's ceremony, this device's own records and
// classes this build does not open are each their own counter on [Group.Stats]; a record from a
// member that DID NOT OPEN is counted too AND returns an error, because that is the one case where
// a message was sent and this device cannot show it.
//
// ---------------------------------------------------------------------------------------------
// 4.3.4'S FETCH ATTESTATION: WHAT IS CHECKED, WHAT IS NOT, AND WHY NOT.
// ---------------------------------------------------------------------------------------------
//
// The attestation is the server's Ed25519 signature over what it returned -- since, until, the
// record ids, the high water, its own time and its own id. The AEAD catches a server that TAMPERS;
// nothing but this catches a server that OMITS, so a page with records missing from it is
// invisible to a client that ignores it.
//
// TWO OF THE THREE CHECKS ARE MADE HERE AND THEY NEED NO KEY.
//
//  1. THE DOWNGRADE. If the server ADVERTISED `capabilities.attestation_supported` and then
//     answered a page with no attestation, that is refused with [ErrFetchAttestation]. A server
//     that can sign and did not is not the same server as one that never could.
//  2. THE DESCRIPTION. If an attestation IS present, its group_id, its since, its record id
//     vector and its high water are compared against the page it arrived with. An attestation
//     that describes a DIFFERENT page -- one replayed from another fetch, or one that lists
//     records this page does not carry -- is refused. This is what turns the value from
//     decoration into a statement about these records.
//
// THE THIRD -- THE SIGNATURE ITSELF -- IS NOT VERIFIED, AND THAT IS STATED RATHER THAN PAPERED
// OVER. Verifying it needs the fleet's public key, and 4.3.1 says where that comes from:
// `HelloResponse.server_keys`, each certified by a FLEET ROOT key the client holds compiled in
// (Spec A section 7.6). MEASURED against the server this alpha is deployed from, at msgrepo's
// committed HEAD:
//
//	msgrepo/peer/peer.go:392  -- "HelloResponse.server_keys and HelloResponse.kt_gossip ... This
//	                             process holds no fleet key and observes no log" (declared NotBuilt)
//	msgrepo/api/api.go:497    -- "FetchAttestation: an Ed25519 signature by the fleet key over
//	                             nine response fields, and this process holds no fleet key"
//	msgrepo/api/fetch.go:112  -- "4.3.4's FetchAttestation is absent, not empty"
//
// So the deployed server signs nothing, advertises `attestation_supported` false, and publishes no
// key chain; and there is no compiled-in fleet root anywhere in this workspace to chain one to.
// VERIFYING AGAINST A KEY THE SERVER ITSELF HANDED OVER WOULD BE WORSE THAN NOT VERIFYING: it
// would read as verified and would authenticate the server to itself. So it is not done, it is
// COUNTED -- [Stats.Unattested] moves once per page whose signature this build could not verify,
// which today is every page -- and the gap is filed. **S2-27: a client cannot verify a fetch
// attestation until the fleet ships a key chain and this build ships a root to verify it against.
// Until it does, a message server that silently omits records from a page is undetectable by this
// client.** It is not this package's to close: the key custody is Spec B section 9.1's, through
// `kt`, which is the owner msgrepo's own NotBuilt entry names.
func (self *Group) Receive(ctx context.Context) ([]*Message, error) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if self.closed {
		return nil, fmt.Errorf("urmessage: this group is closed")
	}
	if self.session == nil {
		return nil, ErrNoMemberAdded
	}
	if err := self.rebindLocked(); err != nil {
		return nil, err
	}
	nonce, _, err := self.device.nonce()
	if err != nil {
		return nil, err
	}
	keys, err := self.session.EpochKeys()
	if err != nil {
		return nil, fmt.Errorf("urmessage: this epoch's keys: %w", err)
	}
	defer keys.Destroy()
	readKey, err := keys.ReadKey()
	if err != nil {
		return nil, err
	}
	own, err := self.session.SenderHandle()
	if err != nil {
		return nil, fmt.Errorf("urmessage: this device's sender handle: %w", err)
	}
	leaves, err := self.leavesLocked()
	if err != nil {
		return nil, err
	}

	opened := []*Message{}
	var firstFailure error
	for page := 0; ; page += 1 {
		if maxFetchPages <= page {
			return opened, fmt.Errorf("%w: %d pages, cursor at record %d", ErrFetchIncomplete, page, self.cursor)
		}
		since := self.cursor
		request := &protocol.FetchRequest{
			GroupId:       self.id,
			SinceRecordId: since,
			ReadEpoch:     self.epoch,
		}
		if err := authorizeFetch(request, readKey, nonce); err != nil {
			return opened, err
		}
		response, err := self.device.transport.Call(ctx, request)
		if err != nil {
			return opened, fmt.Errorf("urmessage: Fetch: %w", err)
		}
		if response.GetReason() != protocol.Reason_REASON_OK {
			return opened, fmt.Errorf("%w: %v", ErrFetchRefused, response.GetReason())
		}
		fetched := response.GetFetch()
		if fetched == nil {
			return opened, fmt.Errorf("%w: the response carried no fetch arm", ErrFetchRefused)
		}
		self.stats.Pages += 1
		if err := self.checkAttestationLocked(since, fetched); err != nil {
			return opened, err
		}
		self.openPageLocked(fetched, own, leaves, &opened, &firstFailure)
		if fetched.GetComplete() {
			break
		}
		// 4.3.4's resume cursor. It is taken as a MAXIMUM against what the rows moved the
		// cursor to rather than as an assignment: a server that answered a next_record_id
		// BEHIND the records it just sent would otherwise walk this client backwards over
		// records it has already opened, forever.
		if self.cursor < fetched.GetNextRecordId() {
			self.cursor = fetched.GetNextRecordId()
		}
		if self.cursor <= since {
			return opened, fmt.Errorf("%w: %d records, next_record_id %d, cursor still %d",
				ErrFetchNoProgress, len(fetched.GetRecords()), fetched.GetNextRecordId(), self.cursor)
		}
	}
	return opened, firstFailure
}

// openPageLocked walks one page's records: it advances the cursor, counts what it skips, and opens
// what is a message.
//
// It is a method rather than the body of the loop above so that "one page" is a thing with a name
// -- and so that the paging decisions and the record decisions are not one forty-line block where
// a `continue` could mean either.
func (self *Group) openPageLocked(fetched *protocol.FetchResponse, own [16]byte,
	leaves map[[16]byte]uint32, opened *[]*Message, firstFailure *error) {

	fail := func(err error) {
		self.stats.FailedOpen += 1
		if *firstFailure == nil {
			*firstFailure = err
		}
	}
	for _, row := range fetched.GetRecords() {
		self.stats.Fetched += 1
		if self.cursor < row.GetRecordId() {
			self.cursor = row.GetRecordId()
		}
		parsed, err := message.ParseRecord(row.GetRecordBytes())
		if err != nil {
			fail(fmt.Errorf("%w: record %d does not parse: %w", ErrRecordOpen, row.GetRecordId(), err))
			continue
		}
		header := &parsed.Header
		if header.IsCommit || len(header.ServerAttachment) != 0 {
			self.stats.SkippedCeremony += 1
			continue
		}
		if header.SenderHandle == own {
			self.stats.SkippedOwn += 1
			continue
		}
		if header.RetentionClass != message.RetentionDurable {
			self.stats.SkippedClass += 1
			continue
		}
		leaf, known := leaves[header.SenderHandle]
		if !known {
			fail(fmt.Errorf("%w: record %d names sender_handle %x, which is no leaf of this group at epoch %d",
				ErrRecordOpen, row.GetRecordId(), header.SenderHandle, self.epoch))
			continue
		}
		if err := self.trackLocked(leaf, header); err != nil {
			fail(err)
			continue
		}
		headPlain, bodyPlain, err := self.session.OpenRecord(parsed)
		if err != nil {
			fail(fmt.Errorf("%w: record %d from leaf %d: %w", ErrRecordOpen, row.GetRecordId(), leaf, err))
			continue
		}
		sentAtMs, err := decodeHead(headPlain)
		if err != nil {
			fail(fmt.Errorf("%w: record %d: %w", ErrRecordOpen, row.GetRecordId(), err))
			continue
		}
		self.stats.Opened += 1
		received := &Message{
			RecordId:     row.GetRecordId(),
			SenderHandle: append([]byte(nil), header.SenderHandle[:]...),
			Mine:         false,
			Text:         string(bodyPlain),
			SentAtMs:     sentAtMs,
		}
		*opened = append(*opened, received)
		self.log = append(self.log, received)
	}
}

// checkAttestationLocked performs the two halves of 4.3.4 that need no key, and counts the half
// that does. See [Group.Receive] for the whole of the decision and for S2-27.
func (self *Group) checkAttestationLocked(since uint64, fetched *protocol.FetchResponse) error {
	attestation := fetched.GetAttestation()
	if attestation == nil {
		// THE DOWNGRADE CHECK, and it reads the server's OWN advertisement rather than a
		// setting of ours: a server that says it signs and then does not is refused, and a
		// server that never claimed to is counted.
		if self.device.transport.Capabilities().GetAttestationSupported() {
			return fmt.Errorf("%w: this server advertises attestation_supported and answered a page with no attestation",
				ErrFetchAttestation)
		}
		self.stats.Unattested += 1
		return nil
	}
	if !bytes.Equal(attestation.GetGroupId(), self.id) {
		return fmt.Errorf("%w: it names group %x and this fetch was for %x",
			ErrFetchAttestation, attestation.GetGroupId(), self.id)
	}
	if attestation.GetSinceRecordId() != since {
		return fmt.Errorf("%w: it names since_record_id %d and this fetch asked from %d",
			ErrFetchAttestation, attestation.GetSinceRecordId(), since)
	}
	if attestation.GetHighWaterRecordId() != fetched.GetHighWaterRecordId() {
		return fmt.Errorf("%w: it names high_water %d and the response carries %d",
			ErrFetchAttestation, attestation.GetHighWaterRecordId(), fetched.GetHighWaterRecordId())
	}
	attested := attestation.GetRecordIds()
	records := fetched.GetRecords()
	if len(attested) != len(records) {
		return fmt.Errorf("%w: it lists %d record ids and the page carries %d records",
			ErrFetchAttestation, len(attested), len(records))
	}
	for at, record := range records {
		if attested[at] != record.GetRecordId() {
			return fmt.Errorf("%w: its record id %d at position %d is not the page's record %d",
				ErrFetchAttestation, attested[at], at, record.GetRecordId())
		}
		if attestation.GetHighWaterRecordId() < record.GetRecordId() {
			return fmt.Errorf("%w: it names high_water %d and the page carries record %d",
				ErrFetchAttestation, attestation.GetHighWaterRecordId(), record.GetRecordId())
		}
	}
	// AND THE SIGNATURE IS NOT CHECKED. Counted, never claimed. S2-27.
	self.stats.Unattested += 1
	return nil
}

// trackLocked installs this sender's receiver ladder once and only once.
func (self *Group) trackLocked(leaf uint32, header *message.RecordHeader) error {
	retentionWire, err := message.RetentionClassWire(header.RetentionClass, header.EphBucket)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrRecordOpen, err)
	}
	key := trackedKey{leaf: leaf, retentionWire: retentionWire, ephWindow: header.EphWindow}
	if self.tracked[key] {
		return nil
	}
	// headIndex zero: the ladder is followed from its root, which is the only honest answer for a
	// device that has been in this group since the epoch opened. It is the CALLER'S state and
	// never a number off the record, so a peer cannot choose how far this device walks.
	if err := self.session.TrackSender(leaf, header.RetentionClass, header.EphBucket, header.EphWindow, 0); err != nil {
		return fmt.Errorf("%w: tracking leaf %d: %w", ErrRecordOpen, leaf, err)
	}
	self.tracked[key] = true
	return nil
}

// leavesLocked is every member's sender_handle at this epoch, mapped to its leaf index.
//
// It is DERIVED and never read off a record: SenderHandle(group_handle_key, leaf) is the only
// thing that says which leaf a handle belongs to, and a table built from what arrived would let a
// sender name any leaf it liked.
func (self *Group) leavesLocked() (map[[16]byte]uint32, error) {
	leaves := map[[16]byte]uint32{}
	for at := 0; at < self.handle.MemberCount(); at += 1 {
		leaf, _, _, err := self.handle.MemberAt(at)
		if err != nil {
			return nil, fmt.Errorf("urmessage: the group's member %d: %w", at, err)
		}
		leaves[messagegroup.SenderHandle(self.groupHandleKey, leaf)] = leaf
	}
	return leaves, nil
}

// ── the rest of what a caller reads ──────────────────────────────────────────────────────────

// Id is this group's 32 octet identifier. A copy.
func (self *Group) Id() []byte {
	return append([]byte(nil), self.id...)
}

// Epoch is the epoch this group's session is at.
func (self *Group) Epoch() uint64 {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return self.epoch
}

// Open reports whether this device has published the group on the server.
func (self *Group) IsOpen() bool {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return self.opened
}

// Messages is every message this group has sent or received, in the order it learned them. A copy
// of the slice; the messages themselves are shared and are not written after they are appended.
func (self *Group) Messages() []*Message {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return append([]*Message(nil), self.log...)
}

// Stats is what this group has seen.
func (self *Group) Stats() Stats {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return self.stats
}

// Close closes both sessions and the MLS handle under them.
func (self *Group) Close() error {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if self.closed {
		return nil
	}
	self.closed = true
	var first error
	if self.session != nil {
		if err := self.session.Close(); err != nil && first == nil {
			first = err
		}
	}
	if self.founding != nil {
		if err := self.founding.Close(); err != nil && first == nil {
			first = err
		}
	}
	if err := self.handle.Close(); err != nil && first == nil {
		first = err
	}
	return first
}

// rebind is [Group.rebindLocked] for a caller that does not hold the lock.
func (self *Group) rebind() error {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if self.closed {
		return nil
	}
	return self.rebindLocked()
}

// rebindLocked moves this group's sessions onto the connection's current nonce, when and only when
// the Hello count has moved since they were last bound.
//
// A FAILED REBIND IS RETURNED AND IS NEVER SWALLOWED. A session still MAC'ing under a nonce the
// server has destroyed produces records that are refused on the wire, and a caller that was told
// its send succeeded would have a message that silently never arrives.
func (self *Group) rebindLocked() error {
	nonce, nonceEpoch, err := self.device.nonce()
	if err != nil {
		return err
	}
	if self.founding != nil && self.foundingBound != nonceEpoch {
		if err := self.founding.RebindServerNonce(nonce); err != nil {
			return fmt.Errorf("%w: the founding session at epoch 0: %w", ErrNonceRebind, err)
		}
		self.foundingBound = nonceEpoch
	}
	if self.session != nil && self.sessionBound != nonceEpoch {
		if err := self.session.RebindServerNonce(nonce); err != nil {
			return fmt.Errorf("%w: the session at epoch %d: %w", ErrNonceRebind, self.epoch, err)
		}
		self.sessionBound = nonceEpoch
	}
	return nil
}
