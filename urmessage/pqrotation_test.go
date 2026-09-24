// pq_secret ROTATES PER EPOCH, AND THE MEMBER A COMMIT REMOVES DOES NOT GET THE NEXT ONE.
//
// WHAT THIS FILE MEASURES, and why each case is written as a PROPERTY rather than as a count.
// Ledger item 243 ruled pq_secret a group-lifetime value "on the explicit condition that rotating
// it is a prerequisite of shipping REMOVAL"; item 251's rulings 36-40 are that condition coming
// due, and the thing that has to be TRUE at the end of it is one sentence: every member a commit
// leaves in the group derives the same storage_root for the epoch it opens, and the member it
// takes out does not. Everything else here -- the table, the wrap, the three sentinels -- is
// machinery in service of that sentence, and a suite that counted the machinery would pass over a
// rotation that delivered the wrong secret to everybody equally.
//
// WHAT IS REAL. Every member is a [crossProcessDevice]: this package's own deviceIdentity over a
// durable store, the shipped messagegroup engine, a real GroupSession, and -- which is new and is
// what makes a wrap openable at all -- the X-Wing seed under the public half its leaf publishes
// (S2-26, sdk 48ee76e). Commits are the seam's by-value arms on real handles. The fan-out is
// built by the production functions [Group.wrapTargetsAtLocked] and [Group.sealEpochWrapLocked],
// and the receive leg is [Group.openPageLocked] driving [Group.ingestWrapLocked] and
// [Group.ingestCommitLocked], exactly as [Group.Receive] does below the fetch.
//
// WHAT IS NOT HERE IS THE SERVER, which is the cp3b module's. What that costs is stated rather
// than glossed: the ORDER of the records on the wire is a server-side fact -- ruling 37 has the
// wraps submitted at epoch n, before the commit, because a write is accepted only at the current
// epoch -- and no page assembled here can refuse a wrap for being late. cp3b's
// TestTheEpochFanOutIsSubmittedBeforeTheCommitAndCarriesTheEpochItOpens is where that half is
// measured, against a real server that answers REASON_EPOCH_STALE.
package urmessage

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/messagegroup"
	"github.com/urnetwork/connect/mls"
	"github.com/urnetwork/connect/protocol"
)

// ── the world ────────────────────────────────────────────────────────────────────────────────

type rotMember struct {
	name    string
	root    string
	dev     *crossProcessDevice
	handle  messagegroup.GroupHandle
	session *messagegroup.GroupSession
	group   *Group
	leaf    uint32
}

type rotWorld struct {
	t              *testing.T
	root           string
	groupId        []byte
	groupHandleKey []byte
	founding       []byte
	members        map[string]*rotMember
	order          []string
	nextRecordId   uint64
}

// newRotWorld founds a group with names[0] and admits every other name in ONE commit, so every
// member stands at epoch 1 holding the founding pq_secret -- the shape every live group has, and
// the shape the compatibility path is defined on.
func newRotWorld(t *testing.T, names ...string) *rotWorld {
	t.Helper()
	world := &rotWorld{
		t:            t,
		root:         t.TempDir(),
		groupId:      make([]byte, GroupIdBytes),
		members:      map[string]*rotMember{},
		nextRecordId: 1,
	}
	if _, err := rand.Read(world.groupId); err != nil {
		t.Fatalf("drawing a group id: %v", err)
	}
	founding, err := messagegroup.NewPqSecret(rand.Reader)
	if err != nil {
		t.Fatalf("pq_secret: %v", err)
	}
	world.founding = founding

	founder := world.device(names[0])
	founderHandle := founder.createGroup(t, world.groupId)
	t.Cleanup(func() { founderHandle.Close() })
	mlsSecret, err := founderHandle.Export(storageExporterLabel, nil, storageExporterBytes)
	if err != nil {
		t.Fatalf("the epoch zero exporter: %v", err)
	}
	world.groupHandleKey = messagegroup.GroupHandleKey(messagegroup.StorageRoot(mlsSecret, founding))

	joiners := []*crossProcessDevice{}
	keyPackages := [][]byte{}
	for _, name := range names[1:] {
		joiner := world.device(name)
		keyPackage, err := joiner.engine.NewKeyPackage()
		if err != nil {
			t.Fatalf("%s's key package: %v", name, err)
		}
		joiners = append(joiners, joiner)
		keyPackages = append(keyPackages, keyPackage)
	}
	_, welcome, ratchetTree, err := founderHandle.CommitAdd(keyPackages)
	if err != nil {
		t.Fatalf("the founding CommitAdd: %v", err)
	}
	if err := founderHandle.MergePendingCommit(); err != nil {
		t.Fatalf("the founding MergePendingCommit: %v", err)
	}
	world.enroll(names[0], founder, founderHandle)
	for at, joiner := range joiners {
		handle, err := joiner.engine.JoinFromWelcome(welcome, ratchetTree)
		if err != nil {
			t.Fatalf("%s's JoinFromWelcome: %v", names[at+1], err)
		}
		t.Cleanup(func() { handle.Close() })
		world.enroll(names[at+1], joiner, handle)
	}
	return world
}

func (self *rotWorld) device(name string) *crossProcessDevice {
	self.t.Helper()
	dev := openCrossProcessDevice(self.t, filepath.Join(self.root, name))
	self.t.Cleanup(dev.close)
	return dev
}

func (self *rotWorld) rootOf(name string) string {
	return filepath.Join(self.root, name)
}

// enroll gives one member a session and a receiving [Group]. THE WRAP SEED IS ON THE DEVICE, and
// that is the one field this world sets that the role world does not: without it every
// [Device.openWrapToOwnLeaf] answers [ErrNoDeviceWrapKey] and every case here would measure a
// device that cannot open its own wrap rather than a wrap that is wrong.
func (self *rotWorld) enroll(name string, dev *crossProcessDevice, handle messagegroup.GroupHandle) *rotMember {
	self.t.Helper()
	session := newCrossProcessSession(self.t, handle, self.founding, self.groupHandleKey, dev.reserver, name+"'s nonce")
	self.t.Cleanup(func() { session.Close() })
	group := &Group{
		device: &Device{
			stateStore:  dev.store,
			engine:      dev.engine,
			reserver:    dev.reserver,
			identityPub: append([]byte(nil), dev.identityPub...),
			wrapSeed:    dev.wrapSeed,
			nowMs:       func() int64 { return time.Now().UnixMilli() },
			random:      rand.Reader,
			groups:      map[string]*Group{},
		},
		id:             append([]byte(nil), self.groupId...),
		handle:         handle,
		groupHandleKey: self.groupHandleKey,
		pqSecrets:      map[uint64][]byte{handle.Epoch(): self.founding},
		session:        session,
		epoch:          handle.Epoch(),
		opened:         true,
		reconciled:     true,
	}
	group.initTables()
	if err := session.InstallPastEpochLoader(group.device.pastEpochLoader(group.id)); err != nil {
		self.t.Fatalf("%s's past epoch loader: %v", name, err)
	}
	if err := group.device.persistGroup(group.groupRecordLocked(true)); err != nil {
		self.t.Fatalf("%s's group record: %v", name, err)
	}
	member := &rotMember{name: name, root: self.rootOf(name), dev: dev, handle: handle,
		session: session, group: group, leaf: handle.OwnLeafIndex()}
	self.members[name] = member
	self.order = append(self.order, name)
	return member
}

func (self *rotWorld) member(name string) *rotMember {
	self.t.Helper()
	held, found := self.members[name]
	if !found {
		self.t.Fatalf("no member named %q", name)
	}
	return held
}

// rotation is one publication: the wrap rows in the order they go on the wire, then the commit.
type rotation struct {
	wraps    []*sealed
	commit   *sealed
	opens    uint64
	pqSecret []byte
	targets  []wrapTarget
}

// rotBend is one leaf's wrap built wrong on purpose: sealed to a key nobody holds, or carrying a
// secret this epoch was not opened with. Both are states the field produces -- a committer that
// encapsulated to the wrong leaf, and a committer that lost its CAS race -- and both are built by
// the production sealer rather than by editing octets, so what each case measures is the OPENER.
type rotBend struct {
	leaf        uint32
	toAStranger bool
	payload     []byte
}

// page is the publication as a receiver meets it, wraps first -- ruling 37's order.
func (self *rotation) page() []*sealed {
	return append(append([]*sealed{}, self.wraps...), self.commit)
}

// rotate runs [Group.publishCommitLocked]'s (2a) through (4) with no server in between: draw the
// epoch's own pq_secret, enumerate the targets off the live tree minus what the commit removes,
// seal one wrap per target PRE-MERGE, seal the commit that announces the epoch, then merge, file
// and advance.
//
// IT CALLS THE PRODUCTION FUNCTIONS FOR EVERY STEP THAT HAS ONE. What is re-spelled here is only
// what [Group.submitLocked] would have done -- handing a record to a transport and numbering it --
// because no transport exists in this package's tests.
func (self *rotWorld) rotate(committer *rotMember, removing []uint32,
	arm func() ([]byte, []byte, []byte, error), bends ...rotBend) *rotation {

	self.t.Helper()
	group := committer.group
	commit, _, _, err := arm()
	if err != nil {
		self.t.Fatalf("%s's commit: %v", committer.name, err)
	}
	pending, err := committer.handle.PendingEpoch()
	if err != nil {
		self.t.Fatalf("%s's pending epoch: %v", committer.name, err)
	}
	// THE PRODUCTION DECISION, THROUGH THE PRODUCTION CALL. The draw, the target enumeration
	// and the wrap records are [Group.stageEpochRotationLocked]'s and are not re-spelled here:
	// a harness that drew its own secret measures its own arithmetic, and it did -- a mutant
	// that replaced the draw with the group's existing secret passed this whole file.
	staged, err := group.stageEpochRotationLocked(pending.Epoch, removing)
	if err != nil {
		self.t.Fatalf("%s's staged rotation: %v", committer.name, err)
	}
	pqNext, targets := staged.pqSecret, staged.targets
	newMlsSecret, err := committer.handle.PendingExport(storageExporterLabel, nil, storageExporterBytes)
	if err != nil {
		self.t.Fatalf("%s's staged exporter: %v", committer.name, err)
	}
	newRoot := messagegroup.StorageRoot(newMlsSecret, pqNext)
	writeKey, readKey := message.WriteKey(newRoot), message.ReadKey(newRoot)

	one := &rotation{opens: pending.Epoch, pqSecret: pqNext, targets: targets}
	// THE BENDS ARE APPLIED BY RE-SEALING ONE ROW, WHILE THE COMMITTER IS STILL AT THE OLD
	// EPOCH, which is forced rather than tidy: a GroupSession seals at the epoch it was
	// constructed over, so a row rebuilt after the advance below would carry epoch n+1 in its
	// header and every receiver would refuse it as a record from an epoch it is not in -- a
	// different failure from the one each case is about. The UNBENT rows are production's own,
	// sealed by [Group.stageEpochRotationLocked] and not rebuilt here.
	for at, target := range targets {
		record := staged.wraps[at]
		for _, bend := range bends {
			if bend.leaf != target.leaf {
				continue
			}
			bent := target
			payload := pqNext
			if bend.toAStranger {
				stranger, err := messagegroup.XwingGenerateKey(rand.Reader)
				if err != nil {
					self.t.Fatalf("a stranger's x-wing key: %v", err)
				}
				bent.xwingPub = stranger.Public().Bytes()
			}
			if bend.payload != nil {
				payload = bend.payload
			}
			replacement, err := group.sealEpochWrapLocked(pending.Epoch, bent, payload)
			if err != nil {
				self.t.Fatalf("%s's bent wrap for leaf %d: %v", committer.name, target.leaf, err)
			}
			record = replacement
		}
		one.wraps = append(one.wraps, self.number(record))
	}

	groupId, err := epochDigestGroupId(group.id)
	if err != nil {
		self.t.Fatalf("the group id: %v", err)
	}
	contextHash := rotSha256(pending.GroupContext)
	digest, err := message.NewEpochDigestAttachment(groupId, message.EpochDigestAttachment{
		Epoch:             pending.Epoch,
		AlgId:             epochAttachmentAlgId,
		GroupContextHash:  contextHash[:],
		ExpectedWrapCount: uint32(len(targets)),
	}, writeKey, readKey)
	if err != nil {
		self.t.Fatalf("the epoch digest: %v", err)
	}
	record, err := group.session.SealRecord(message.RetentionPermanent, 0, true,
		encodeHead(time.Now().UnixMilli()), commit, 0, &message.ServerAttachment{
			Kind:        message.AttachmentEpochDigest,
			EpochDigest: digest,
		})
	if err != nil {
		self.t.Fatalf("%s sealing its commit record: %v", committer.name, err)
	}
	one.commit = self.number(record)

	if err := committer.handle.MergePendingCommit(); err != nil {
		self.t.Fatalf("%s's MergePendingCommit: %v", committer.name, err)
	}
	group.filePqSecretLocked(pending.Epoch, pqNext)
	if err := group.session.AdvanceEpoch(pqNext); err != nil {
		self.t.Fatalf("%s advancing to epoch %d: %v", committer.name, pending.Epoch, err)
	}
	if err := group.crossEpochLadderLocked(pending.Epoch); err != nil {
		self.t.Fatalf("%s crossing the epoch: %v", committer.name, err)
	}
	if err := group.enterEpochLocked(); err != nil {
		self.t.Fatalf("%s entering epoch %d: %v", committer.name, pending.Epoch, err)
	}
	return one
}

func (self *rotWorld) number(record *message.Record) *sealed {
	one := &sealed{recordId: self.nextRecordId, record: record}
	self.nextRecordId += 1
	return one
}

// deliver walks one page through a receiver's group, as [Group.Receive] does below the fetch.
func (self *rotWorld) deliver(receiver *rotMember, page ...*sealed) error {
	self.t.Helper()
	group := receiver.group
	own, err := group.session.SenderHandle()
	if err != nil {
		self.t.Fatalf("%s's sender handle: %v", receiver.name, err)
	}
	leaves, err := group.leavesLocked()
	if err != nil {
		self.t.Fatalf("%s's leaves: %v", receiver.name, err)
	}
	walk := &pageWalk{
		own:          own,
		leaves:       leaves,
		opened:       []*Message{},
		from:         group.cursor,
		reached:      group.cursor,
		resolvedTo:   group.cursor,
		reconciled:   group.reconciled,
		complete:     true,
		unobtainable: map[uint64]bool{},
	}
	rows := []*protocol.Record{}
	for _, one := range page {
		encoded, err := message.EncodeRecord(one.record)
		if err != nil {
			self.t.Fatalf("encoding record %d: %v", one.recordId, err)
		}
		rows = append(rows, &protocol.Record{RecordId: one.recordId, RecordBytes: encoded})
	}
	group.openPageLocked(&protocol.FetchResponse{Records: rows}, walk)
	return group.commitWalkLocked(walk)
}

// storageRootOf is the value the whole of item 243 is about: this member's own storage root at the
// epoch it stands in, from its OWN exporter and its OWN table.
func (self *rotWorld) storageRootOf(member *rotMember) []byte {
	self.t.Helper()
	mlsSecret, err := member.handle.Export(storageExporterLabel, nil, storageExporterBytes)
	if err != nil {
		self.t.Fatalf("%s's exporter at epoch %d: %v", member.name, member.handle.Epoch(), err)
	}
	secret := member.group.pqSecretLocked()
	if len(secret) == 0 {
		self.t.Fatalf("%s holds no pq_secret at epoch %d", member.name, member.group.epoch)
	}
	return messagegroup.StorageRoot(mlsSecret, secret)
}

func rotSha256(b []byte) [32]byte {
	return sha256.Sum256(b)
}

// ── 1. THE PROPERTY ──────────────────────────────────────────────────────────────────────────

// EVERY MEMBER A COMMIT LEAVES IN THE GROUP DERIVES THE SAME storage_root FOR THE EPOCH IT OPENS,
// AND THE MEMBER IT REMOVES CANNOT -- ACROSS TWO ROTATIONS.
//
// THE INLINE CONTROL IS THE PRE-ROTATION AGREEMENT AND IT FIRES FOR ITS OWN REASON: before the
// removal, the member about to be removed derives the SAME root as the survivors. Without it a
// build in which nobody ever agreed about anything would pass the second half of this property
// trivially, and the case would be measuring a broken group rather than a removal.
//
// THE COUNTERFACTUAL IS THE FINDING, and it is item 251's own measurement read from this side.
// A removed member keeps pq_secret[n] forever -- that is what item 243 ruled and what nothing can
// take back. So the question is not what it holds but what that holding BUYS, and the answer is
// measured directly: mls_secret[n+1] (which MLS's own post-compromise security already denies it,
// but which is GRANTED here so the pq half is the only variable) mixed with the RETAINED secret
// does NOT reproduce the survivors' root; mixed with the ROTATED one it does, exactly. That second
// clause is the second control: it pins that the difference is the post-quantum half and not the
// exporter, which is the one substitution a broken rotation could hide behind.
//
// WHAT WOULD GO RED: reuse one secret across epochs (the survivors still agree, and the
// counterfactual reproduces their root -- the removal buys nothing); leave the removed leaf in the
// fan-out (its wrap arrives and the "no wrap" assertion fails); seal every wrap to one leaf's key
// (the other survivors go dark and their roots diverge).
func TestThreeMembersRotateAcrossTwoEpochsAndAMemberRemovedByThatCommitCannotFollow(t *testing.T) {
	world := newRotWorld(t, "alice", "bob", "carol")
	alice, bob, carol := world.member("alice"), world.member("bob"), world.member("carol")

	// ── THE CONTROL, FIRST AND ON ITS OWN TERMS: at epoch 1 all three agree ─────────────────
	atOne := world.storageRootOf(alice)
	for _, who := range []*rotMember{bob, carol} {
		if !bytes.Equal(atOne, world.storageRootOf(who)) {
			t.Fatalf("CONTROL FAILED: at epoch 1 %s's storage root is not alice's, so this group "+
				"never agreed about anything and the removal below would prove nothing", who.name)
		}
	}
	t.Logf("CONTROL HELD: at epoch 1 all three members derive one storage root")

	// ── ROTATION ONE: a bare commit that removes nobody. Everyone follows. ───────────────────
	first := world.rotate(alice, nil, func() ([]byte, []byte, []byte, error) {
		return alice.handle.Commit(nil)
	})
	if first.opens != 2 {
		t.Fatalf("the first rotation opens epoch %d, want 2", first.opens)
	}
	for _, who := range []*rotMember{bob, carol} {
		if err := world.deliver(who, first.page()...); err != nil {
			t.Fatalf("%s's walk over the first rotation: %v", who.name, err)
		}
	}
	atTwo := world.storageRootOf(alice)
	if bytes.Equal(atOne, atTwo) {
		t.Fatalf("epoch 2's storage root is epoch 1's; nothing rotated")
	}
	for _, who := range []*rotMember{bob, carol} {
		if got := world.storageRootOf(who); !bytes.Equal(atTwo, got) {
			t.Fatalf("after the first rotation %s's storage root at epoch 2 is not alice's; "+
				"a member that followed the commit did not follow the secret", who.name)
		}
		if !bytes.Equal(who.group.pqSecretLocked(), first.pqSecret) {
			t.Fatalf("%s's pq_secret at epoch 2 is not the one the fan-out carried", who.name)
		}
		if got := who.group.Stats().WrapOpened; got != 1 {
			t.Errorf("%s opened %d wrap(s) across one rotation, want 1", who.name, got)
		}
	}

	// ── ROTATION TWO: the commit that REMOVES carol ─────────────────────────────────────────
	//
	// The retained secret is read BEFORE the commit, because that is all a removed member can
	// keep: pq_secret at the epoch it was removed at.
	retained := append([]byte(nil), carol.group.pqSecretLocked()...)
	if !bytes.Equal(retained, first.pqSecret) {
		t.Fatalf("carol's retained secret is not epoch 2's; the counterfactual would be about the wrong value")
	}
	second := world.rotate(alice, []uint32{carol.leaf}, func() ([]byte, []byte, []byte, error) {
		return alice.handle.CommitRemove([]uint32{carol.leaf})
	})
	if second.opens != 3 {
		t.Fatalf("the second rotation opens epoch %d, want 3", second.opens)
	}

	// THE FAN-OUT LEFT CAROL OUT, and the positive control is in the same loop: every surviving
	// leaf IS a target. A bare "carol is not a target" would pass against an empty fan-out.
	survivors, removedIsTarget := 0, false
	for _, target := range second.targets {
		if target.leaf == carol.leaf {
			removedIsTarget = true
			continue
		}
		survivors += 1
	}
	if removedIsTarget {
		t.Fatalf("the fan-out for epoch 3 addresses leaf %d, which is the leaf the commit removes", carol.leaf)
	}
	if survivors != 2 {
		t.Fatalf("the fan-out for epoch 3 addresses %d surviving leaves, want 2 (alice and bob); "+
			"the exclusion cannot be told from an empty fan-out", survivors)
	}

	if err := world.deliver(bob, second.page()...); err != nil {
		t.Fatalf("bob's walk over the removal: %v", err)
	}
	atThree := world.storageRootOf(alice)
	if got := world.storageRootOf(bob); !bytes.Equal(atThree, got) {
		t.Fatalf("after the removal bob's storage root at epoch 3 is not alice's")
	}
	if bytes.Equal(atThree, atTwo) {
		t.Fatalf("epoch 3's storage root is epoch 2's; the removal rotated nothing")
	}

	// ── THE COUNTERFACTUAL, WITH ITS OWN CONTROL BESIDE IT ──────────────────────────────────
	//
	// The exporter of the epoch the removal opened is GRANTED to the removed member here. That is
	// strictly more than MLS gives it -- a Remove forces an UpdatePath and blanks the path, so it
	// cannot derive this at all -- and granting it is the point: it leaves the post-quantum half
	// as the only variable, which is the half item 243 is about.
	granted, err := alice.handle.Export(storageExporterLabel, nil, storageExporterBytes)
	if err != nil {
		t.Fatalf("the epoch-3 exporter: %v", err)
	}
	withRetained := messagegroup.StorageRoot(granted, retained)
	withRotated := messagegroup.StorageRoot(granted, second.pqSecret)
	if !bytes.Equal(withRotated, atThree) {
		t.Fatalf("CONTROL FAILED: the epoch-3 exporter mixed with the epoch's OWN secret is not the " +
			"root the survivors derived, so the counterfactual below is not about the pq half")
	}
	if bytes.Equal(withRetained, atThree) {
		t.Fatalf("the removed member's RETAINED pq_secret, mixed with the epoch it was removed from, " +
			"reproduces the survivors' storage_root[3]. Item 243's whole subject: the removal removed nothing")
	}
	t.Logf("the removed member's retained secret does not reproduce storage_root[3]; the epoch's own secret does")

	// AND CAROL WAS HANDED NOTHING. Her table still stops at the epoch she was removed from.
	if _, held := carol.group.pqSecretAtLocked(3); held {
		t.Fatalf("the removed member holds a pq_secret for epoch 3")
	}
}

// ── 2. THE THREE FAILURE STATES ──────────────────────────────────────────────────────────────

// EACH OF THE THREE WAYS A WRAP FAILS IS REACHED, NAMED BY ITS OWN SENTINEL, AND COUNTED APART.
//
// RULING 38 IS WHY THIS IS THREE CASES AND NOT ONE. The day a wrap carries key material a member
// that never opens a readable one goes dark in both directions and permanently, with an
// undiagnosable REASON_REJECTED -- and the orphan case, a fan-out from a committer that lost its
// CAS race, "must be a typed refusal separable from this one, or the two are indistinguishable in
// the field". They have three different repairs, so they are three sentences.
//
// THE POSITIVE CONTROL IS THE FIRST SUBTEST: the same page, unmutated, installs the secret and
// moves [Stats.WrapOpened]. Without it every case below would be satisfiable by a build that
// refused every wrap.
func TestTheThreeWaysADeviceWrapFailsAreThreeSentinelsAndThreeCounters(t *testing.T) {
	for _, one := range []struct {
		what    string
		bend    func(victim *rotMember) []rotBend
		omit    bool
		want    error
		counter func(Stats) uint64
	}{
		{
			what:    "the control: an intact fan-out installs the epoch's secret",
			bend:    func(victim *rotMember) []rotBend { return nil },
			want:    nil,
			counter: func(stats Stats) uint64 { return stats.WrapOpened },
		},
		{
			// ITEM 132's OMISSION, built the way a lying committer builds it: the victim's row is
			// simply not on the wire, and expected_wrap_count is untouched, so the server and
			// every other member see a fan-out that adds up.
			what:    "no wrap arrived: the committer left this member out of the fan-out",
			bend:    func(victim *rotMember) []rotBend { return nil },
			omit:    true,
			want:    ErrNoWrapForEpoch,
			counter: func(stats Stats) uint64 { return stats.WrapMissing },
		},
		{
			// SEALED TO A KEY NOBODY HOLDS. The KEM does not say no -- ML-KEM-768 uses implicit
			// rejection, so this decapsulates SUCCESSFULLY to a pseudorandom secret -- and the
			// only thing that separates "mine" from "not mine" is the Poly1305 tag. That is why
			// this case is built by sealing to a stranger rather than by editing a ciphertext: the
			// record's own AEAD still authenticates, so the refusal comes from where this case
			// says it does.
			what: "a wrap arrived and did not open: it was sealed to a key this device does not hold",
			bend: func(victim *rotMember) []rotBend {
				return []rotBend{{leaf: victim.leaf, toAStranger: true}}
			},
			want:    ErrWrapUnreadable,
			counter: func(stats Stats) uint64 { return stats.WrapUnreadable },
		},
		{
			// THE ORPHAN. A second committer built the same epoch, wrote its fan-out, and lost the
			// race -- so what reaches this member is a perfectly READABLE wrap for epoch n+1
			// carrying a secret that epoch was never opened with. It is a state ruling 37's
			// pre-merge submit PRODUCES, which is why the detector ships in the same commit.
			what: "wraps arrived for an epoch that never opened: a committer lost its CAS race",
			bend: func(victim *rotMember) []rotBend {
				loser := make([]byte, messagegroup.PqSecretBytes)
				for at := range loser {
					loser[at] = 0x7C
				}
				return []rotBend{{leaf: victim.leaf, payload: loser}}
			},
			want:    ErrOrphanWrap,
			counter: func(stats Stats) uint64 { return stats.WrapOrphaned },
		},
	} {
		t.Run(one.what, func(t *testing.T) {
			world := newRotWorld(t, "alice", "bob")
			alice, bob := world.member("alice"), world.member("bob")
			published := world.rotate(alice, nil, func() ([]byte, []byte, []byte, error) {
				return alice.handle.Commit(nil)
			}, one.bend(bob)...)

			page := published.page()
			if one.omit {
				kept := []*sealed{}
				dropped := false
				for at, wrap := range published.wraps {
					if published.targets[at].leaf == bob.leaf {
						dropped = true
						continue
					}
					kept = append(kept, wrap)
				}
				if !dropped {
					t.Fatalf("the victim's wrap was not in the fan-out, so nothing was omitted")
				}
				page = append(kept, published.commit)
			}

			err := world.deliver(bob, page...)
			if one.want == nil {
				if err != nil {
					t.Fatalf("the control page was refused: %v", err)
				}
				if !bytes.Equal(bob.group.pqSecretLocked(), published.pqSecret) {
					t.Fatalf("the control page did not install the epoch's secret")
				}
				if bob.group.wrapDark != nil {
					t.Fatalf("the control page left the group dark: %v", bob.group.wrapDark)
				}
			} else {
				if !errors.Is(err, one.want) {
					t.Fatalf("the walk answered %v, want %v", err, one.want)
				}
				// AND THE STICKY COPY, which is what a caller meets on every LATER walk: the
				// diagnosis has to outlive the one page that produced it, or the next walk reports
				// an AEAD failure on an arbitrary record instead.
				if !errors.Is(bob.group.wrapDark, one.want) {
					t.Fatalf("the group's sticky diagnosis is %v, want %v", bob.group.wrapDark, one.want)
				}
				if _, refused := bob.group.sendableLocked(KindText); !errors.Is(refused, one.want) {
					t.Fatalf("a send from the dark group was refused %v, want %v", refused, one.want)
				}
				// AND THE GROUP STILL FOLLOWED THE COMMIT, which is what makes this a diagnosis
				// rather than a halt: the handle, the session and the persisted record all moved,
				// so nothing is left one epoch behind the tree it is standing in.
				if bob.group.epoch != published.opens {
					t.Fatalf("the group stands at epoch %d and the commit opened %d", bob.group.epoch, published.opens)
				}
			}
			if got := one.counter(bob.group.Stats()); got != 1 {
				t.Fatalf("the counter for this state is %d, want 1; a sentinel with no number "+
					"beside it cannot answer whether this is happening", got)
			}
			// AND NO OTHER STATE'S COUNTER MOVED, which is what makes the three SEPARABLE rather
			// than three names for one number. The control's own counter is excluded by value,
			// not by name, so a build that moved two of them at once is caught here.
			stats := bob.group.Stats()
			mine := one.counter(stats)
			for what, got := range map[string]uint64{
				"WrapMissing":    stats.WrapMissing,
				"WrapUnreadable": stats.WrapUnreadable,
				"WrapOrphaned":   stats.WrapOrphaned,
			} {
				if got != 0 && got != mine {
					t.Errorf("Stats.%s is %d and this case is about a different state", what, got)
				}
			}
		})
	}
}

// ── 3. THE RESTART ───────────────────────────────────────────────────────────────────────────

// A DEVICE THAT RESTARTS AFTER A ROTATION COMES BACK WITH THE WHOLE TABLE AND OPENS ITS BACKLOG.
//
// WHAT WOULD GO RED: persist the epoch without the table (the restore refuses the group, because
// the record's own epoch has no secret); persist the table and not the past rows (the restored
// member re-derives a prior epoch's storage root out of today's secret, which is ruling 40's
// defect, and the record of that epoch fails at the AEAD tag); forget
// [GroupSession.DeclarePqSecretRotated] (the same, through connect's compatibility path).
func TestARestartAfterARotationComesBackWithTheTableAndOpensItsBacklog(t *testing.T) {
	world := newRotWorld(t, "alice", "bob")
	alice, bob := world.member("alice"), world.member("bob")

	atOne := world.storageRootOf(bob)
	first := world.rotate(alice, nil, func() ([]byte, []byte, []byte, error) {
		return alice.handle.Commit(nil)
	})
	if err := world.deliver(bob, first.page()...); err != nil {
		t.Fatalf("bob's walk over the first rotation: %v", err)
	}
	if bytes.Equal(atOne, world.storageRootOf(bob)) {
		t.Fatalf("nothing rotated")
	}
	second := world.rotate(alice, nil, func() ([]byte, []byte, []byte, error) {
		return alice.handle.Commit(nil)
	})
	if err := world.deliver(bob, second.page()...); err != nil {
		t.Fatalf("bob's walk over the second rotation: %v", err)
	}

	// ── THE DISK, READ BACK ─────────────────────────────────────────────────────────────────
	records, err := bob.dev.store.GroupRecords()
	if err != nil {
		t.Fatalf("GroupRecords: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("the disk holds %d group record(s), want 1", len(records))
	}
	record := records[0]
	if record.Epoch != 3 {
		t.Fatalf("the persisted record names epoch %d, want 3", record.Epoch)
	}
	if len(record.PqSecrets) != 3 {
		t.Fatalf("the persisted table holds %d row(s), want 3 (epochs 1, 2 and 3)", len(record.PqSecrets))
	}
	for at, row := range record.PqSecrets {
		if row.Epoch != uint64(at)+1 {
			t.Fatalf("the persisted table's row %d names epoch %d; the table is not ascending from 1", at, row.Epoch)
		}
	}
	if !bytes.Equal(record.PqSecrets[1].PqSecret, first.pqSecret) ||
		!bytes.Equal(record.PqSecrets[2].PqSecret, second.pqSecret) {
		t.Fatalf("the persisted rows are not the secrets the two fan-outs delivered")
	}
	if bytes.Equal(record.PqSecrets[0].PqSecret, record.PqSecrets[1].PqSecret) {
		t.Fatalf("two of the persisted rows carry one value; a table of one secret is the scalar again")
	}

	// ── THE RESTORE, IN A DEVICE THAT DID NOT EXIST WHEN ANY OF IT HAPPENED ──────────────────
	revived := restoredRotDevice(t, bob)
	restored, err := revived.device.restoreOne(revived.store, record, restoreTestNonce(), 1)
	if err != nil {
		t.Fatalf("restoreOne: %v", err)
	}
	defer restored.Close()
	if restored.Epoch() != 3 {
		t.Fatalf("the restored group stands at epoch %d, want 3", restored.Epoch())
	}
	for _, row := range record.PqSecrets {
		held, found := restored.pqSecretAtLocked(row.Epoch)
		if !found {
			t.Fatalf("the restored group holds no pq_secret for epoch %d", row.Epoch)
		}
		if !bytes.Equal(held, row.PqSecret) {
			t.Fatalf("the restored group's pq_secret for epoch %d is not the one on the disk", row.Epoch)
		}
	}

	// AND THE BACKLOG. Epoch ONE's whole key schedule is rebuilt by the restored device, which
	// needs pq_secret[1] and cannot be done with pq_secret[3]: this is the assertion the table
	// exists for, and it is the one a restore that came back with the scalar alone cannot make.
	if err := rotPastEpochReachable(restored.session, 1, alice.leaf); err != nil {
		t.Fatalf("the restored device cannot rebuild epoch 1: %v", err)
	}

	// THE PLANTED NEGATIVE CONTROL, in the same case and on the same door: the same restore with
	// epoch one's ROW REMOVED must refuse that epoch BY NAME. Without it the clause above is
	// satisfiable by a session that answers every epoch out of whatever it holds -- which is
	// exactly connect's group-lifetime premise, and exactly the reading a rotated group must not
	// take. The two rows left behind carry two different values, so the premise is refuted by the
	// OCTETS and the refusal is the table's rather than a version flag's.
	trimmed := &GroupRecord{
		GroupId:        record.GroupId,
		PqSecret:       record.PqSecret,
		PqSecrets:      []EpochPqSecret{record.PqSecrets[1], record.PqSecrets[2]},
		GroupHandleKey: record.GroupHandleKey,
		Epoch:          record.Epoch,
		Opened:         true,
	}
	blind, err := revived.device.restoreOne(revived.store, trimmed, restoreTestNonce(), 1)
	if err != nil {
		t.Fatalf("restoreOne over a trimmed table: %v", err)
	}
	defer blind.Close()
	if err := rotPastEpochReachable(blind.session, 1, alice.leaf); !errors.Is(err, messagegroup.ErrPqSecretUnknownEpoch) {
		t.Fatalf("CONTROL FAILED: a restore whose table has no row for epoch 1 answered %v for that "+
			"epoch, want ErrPqSecretUnknownEpoch. The clause above is then measuring a door that "+
			"answers every epoch out of today's secret", err)
	}
}

// ── 4. AN OLD STORE ──────────────────────────────────────────────────────────────────────────

// A GROUP RECORD WRITTEN BEFORE THE TABLE RESTORES, AND THE DEVICE GOES ON WORKING -- INCLUDING
// THROUGH THE FIRST ROTATION IT MEETS.
//
// EVERY GROUP ON THE DEPLOYED ALPHA IS THIS SHAPE: five parts, one pq_secret scalar, no table. A
// restore that refused one is a device that can never start again, so the read path takes both
// arities and the scalar becomes the one row it is evidence for -- this record's own epoch.
//
// AND "KEEPS WORKING" IS MEASURED AS FOLLOWING THE NEXT ROTATION, not as a restore that returned
// nil. A device that came back perfectly and then could not open the wrap addressed to it at the
// next commit would have been dark ten seconds later, which is the failure this whole commit is
// about.
func TestAGroupRecordWrittenBeforeTheTableRestoresAndFollowsTheNextRotation(t *testing.T) {
	world := newRotWorld(t, "alice", "bob")
	alice, bob := world.member("alice"), world.member("bob")
	bobLeaf := bob.leaf

	records, err := bob.dev.store.GroupRecords()
	if err != nil {
		t.Fatalf("GroupRecords: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("the disk holds %d group record(s), want 1", len(records))
	}

	// THE OLD SHAPE, BUILT THE WAY THE OLD BUILD BUILT IT: PqSecrets nil is what a five-part
	// record decodes to, and it is the signal -- a six-part record with an empty table decodes to
	// an EMPTY SLICE, which is a different state and must not be answered the same way.
	old := &GroupRecord{
		GroupId:        records[0].GroupId,
		PqSecret:       append([]byte(nil), world.founding...),
		GroupHandleKey: records[0].GroupHandleKey,
		Epoch:          records[0].Epoch,
		Opened:         true,
	}
	if old.PqSecrets != nil {
		t.Fatalf("this case's fixture is not the old shape")
	}

	revived := restoredRotDevice(t, bob)
	restored, err := revived.device.restoreOne(revived.store, old, restoreTestNonce(), 1)
	if err != nil {
		t.Fatalf("restoreOne over a store written before the table: %v", err)
	}
	defer restored.Close()
	if restored.Epoch() != old.Epoch {
		t.Fatalf("the restored group stands at epoch %d, want %d", restored.Epoch(), old.Epoch)
	}
	held, found := restored.pqSecretAtLocked(old.Epoch)
	if !found || !bytes.Equal(held, world.founding) {
		t.Fatalf("the restored group does not hold the scalar at the epoch the record names")
	}
	if len(restored.pqSecrets) != 1 {
		t.Fatalf("the restored table holds %d row(s), want 1; the scalar is evidence for exactly "+
			"one epoch and a reader that invented more would be filing values nobody wrote",
			len(restored.pqSecrets))
	}
	// A RESTORED GROUP IS NOT RECONCILED, which is this package's standing rule and not this
	// case's subject; a Receive is what reconciles one, and the walk below is what a Receive does
	// under the fetch.
	restored.reconciled = true

	// ── AND NOW THE ROTATION IT MEETS ───────────────────────────────────────────────────────
	published := world.rotate(alice, nil, func() ([]byte, []byte, []byte, error) {
		return alice.handle.Commit(nil)
	})
	back := &rotMember{name: "bob after the restart", root: bob.root, dev: bob.dev,
		handle: restored.handle, session: restored.session, group: restored, leaf: bobLeaf}
	if err := world.deliver(back, published.page()...); err != nil {
		t.Fatalf("the restored device's walk over the first rotation it meets: %v", err)
	}
	if restored.Epoch() != published.opens {
		t.Fatalf("the restored device stands at epoch %d and the rotation opened %d",
			restored.Epoch(), published.opens)
	}
	if !bytes.Equal(restored.pqSecretLocked(), published.pqSecret) {
		t.Fatalf("the restored device did not install the secret the fan-out carried")
	}
	if restored.wrapDark != nil {
		t.Fatalf("the restored device went dark at the first rotation it met: %v", restored.wrapDark)
	}
	if got := world.storageRootOf(back); !bytes.Equal(got, world.storageRootOf(alice)) {
		t.Fatalf("after the rotation the restored device's storage root is not the committer's")
	}

	// AND IT WRITES THE NEW SHAPE BACK, so the compatibility path is a one-way door rather than a
	// state a group is stuck in: the record this device has now persisted carries the table.
	after, err := revived.store.GroupRecords()
	if err != nil {
		t.Fatalf("GroupRecords after the rotation: %v", err)
	}
	if len(after) != 1 || after[0].PqSecrets == nil {
		t.Fatalf("the record written after the rotation carries no table")
	}
	if len(after[0].PqSecrets) != 2 {
		t.Fatalf("the record written after the rotation holds %d row(s), want 2", len(after[0].PqSecrets))
	}
}

// restoredRotDevice closes one member's process and opens a SECOND over the same directories, the
// way a restart does: a device that did not exist when anything above happened, reading the same
// disk.
func restoredRotDevice(t *testing.T, member *rotMember) *restoreDevice {
	t.Helper()
	member.session.Close()
	member.handle.Close()
	member.dev.close()
	revived := openRestoreDevice(t, member.root)
	t.Cleanup(revived.close)
	return revived
}

// rotPastEpochReachable is whether a session can rebuild a PRIOR epoch's whole key schedule, which
// is the one observable that needs pq_secret AT THAT EPOCH and nothing else. connect exports no
// storage root, so this is the question asked through the door that consumes one: TrackSenderAt
// routes through pastEpochOnLoop, which asks pqSecretForOnLoop for the epoch and then extracts
// that epoch's root from it.
func rotPastEpochReachable(session *messagegroup.GroupSession, epoch uint64, leaf uint32) error {
	return session.TrackSenderAt(epoch, leaf, message.RetentionDurable, 0, 0, 0)
}

// ── 5. THE TWIN THIS TASK COULD NOT BUILD, MEASURED RATHER THAN EXCUSED ──────────────────────

// m1 TASK 14 PROPERTY 1 IS "EXACTLY TWO" AND connect REFUSES THE SECOND, AND THAT REFUSAL IS
// MEASURED HERE RATHER THAN DESCRIBED IN A COMMENT.
//
// The device wrap is ruled as two records per target -- a PERMANENT one carrying pq_secret[k] and
// an EPH(5) one carrying eph_root[k] -- which is what makes MASTER §8.1's disappearing-message
// promise cryptographic rather than behavioural, and it is what MASTER §8.2's
// expected_wrap_count = 2 x device_leaves + 1 counts. This commit ships ONE record per target,
// because connect's sealer answers ErrEphWrapWindowUnruled for any EPH record carrying a wrap tag:
// ledger open item 185 leaves that record's eph_window unstated, Spec A S19 and Spec B §5.1 check
// 3 refuse an implausible one, and a wrap head has no sent_at to divide.
//
// AN EXCUSE CAN BE FALSE AND NOT MERELY UNMEASURED, so this case runs the seal and holds the
// refusal by sentinel. IT GOES RED THE DAY ITEM 185 IS RULED AND THE REFUSAL LIFTS, which is
// exactly when the second record becomes due and expected_wrap_count has to change with it.
func TestTheEphRootTwinOfTheDeviceWrapIsRefusedByConnectAndNotByThisPackage(t *testing.T) {
	world := newRotWorld(t, "alice", "bob")
	alice := world.member("alice")

	// THE CONTROL, IN THE SAME QUERY: the PERMANENT half of the same pair, at the same target,
	// through the same door, is sealed. Without it a refusal here would be satisfiable by a
	// session that seals nothing at all.
	targets, err := alice.group.wrapTargetsAtLocked(alice.group.epoch, nil)
	if err != nil {
		t.Fatalf("the wrap targets: %v", err)
	}
	if len(targets) == 0 {
		t.Fatalf("this group has no wrap target")
	}
	if _, err := alice.group.sealEpochWrapLocked(alice.group.epoch, targets[0], world.founding); err != nil {
		t.Fatalf("CONTROL FAILED: the PERMANENT half of the pair did not seal either: %v", err)
	}

	_, err = alice.group.session.SealRecord(message.RetentionEph, 5, false,
		encodeHead(time.Now().UnixMilli()), []byte("an eph_root device wrap this build cannot publish"), 0,
		&message.ServerAttachment{
			Kind: message.AttachmentWrap,
			Wrap: &message.WrapTag{WrapTargetHandle: append([]byte(nil), targets[0].handle[:]...), Epoch: alice.group.epoch},
		})
	if !errors.Is(err, messagegroup.ErrEphWrapWindowUnruled) {
		t.Fatalf("connect answered %v to an EPH(5) record carrying a wrap tag, want ErrEphWrapWindowUnruled. "+
			"If ledger item 185 has been ruled and the refusal lifted, this package now owes the SECOND "+
			"record of m1 Task 14 Property 1 and expected_wrap_count owes MASTER §8.2's 2 x device_leaves + 1", err)
	}
	t.Logf("the eph_root twin is refused by connect: %v", err)
}

// ── 6. THE TABLE'S OWN DISCIPLINE ────────────────────────────────────────────────────────────

// THE TABLE IS BOUNDED BY PastEpochWindow AND AN EVICTED ENTRY IS ERASED, NOT DROPPED.
//
// An entry more than [messagegroup.PastEpochWindow] behind can serve no open connect would admit,
// so holding it is holding a retired epoch's post-quantum secret for nothing. The erase is the
// half a `delete` alone would miss, and it is measured on the OCTETS of the array that was
// evicted -- a map entry nobody blanked is a live secret with no owner.
func TestThePqSecretTableIsBoundedByTheWindowAndAnEvictedEntryIsErased(t *testing.T) {
	world := newRotWorld(t, "alice", "bob")
	alice := world.member("alice")
	group := alice.group

	const standing = uint64(messagegroup.PastEpochWindow) + 7
	evicted := append([]byte(nil), world.founding...)
	group.mutex.Lock()
	defer group.mutex.Unlock()
	group.pqSecrets[standing] = evicted
	group.epoch = standing
	group.dropPqSecretsBelowWindowLocked()
	if _, held := group.pqSecretAtLocked(standing); !held {
		t.Fatalf("CONTROL FAILED: an entry at the session's own epoch was dropped, so the " +
			"assertion below measures a function that drops everything")
	}

	// the entry the window moves past
	far := make([]byte, messagegroup.PqSecretBytes)
	for at := range far {
		far[at] = 0xA5
	}
	group.pqSecrets[standing-messagegroup.PastEpochWindow-1] = far
	group.dropPqSecretsBelowWindowLocked()
	if _, held := group.pqSecretAtLocked(standing - messagegroup.PastEpochWindow - 1); held {
		t.Fatalf("an entry %d epochs behind survived a window of %d",
			messagegroup.PastEpochWindow+1, messagegroup.PastEpochWindow)
	}
	if containsNonZeroOctet(far) {
		t.Fatalf("the evicted entry was dropped and not erased: %d non-zero octet(s) remain",
			countNonZeroOctets(far))
	}

	// AND THE EDGE IS EXACTLY THE WINDOW, held in the other direction so the bound is not simply
	// "drops everything old".
	edge := make([]byte, messagegroup.PqSecretBytes)
	for at := range edge {
		edge[at] = 0x5A
	}
	group.pqSecrets[standing-messagegroup.PastEpochWindow] = edge
	group.dropPqSecretsBelowWindowLocked()
	if _, held := group.pqSecretAtLocked(standing - messagegroup.PastEpochWindow); !held {
		t.Fatalf("an entry exactly %d epochs behind was dropped; the window is one short",
			messagegroup.PastEpochWindow)
	}
	if !containsNonZeroOctet(edge) {
		t.Fatalf("the entry at the window's edge was erased while it was still held")
	}
	_ = fmt.Sprint(evicted)
}

func containsNonZeroOctet(octets []byte) bool {
	return countNonZeroOctets(octets) != 0
}

func countNonZeroOctets(octets []byte) int {
	count := 0
	for _, one := range octets {
		if one != 0 {
			count += 1
		}
	}
	return count
}

// mls is imported for the seam's own types in the harness above.
var _ = mls.RoleOwner
