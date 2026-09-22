package urmessage

import (
	"crypto/rand"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"
	"time"

	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/messagegroup"
	"github.com/urnetwork/connect/mls"
	"github.com/urnetwork/connect/protocol"
)

// ── the receiving arm, end to end, through real devices and the seam's own commits ──────────
//
// WHAT IS REAL HERE. Every member is a [crossProcessDevice] -- the package's own deviceIdentity
// over a durable store, the shipped messagegroup engine, a real GroupSession -- and every
// receiver is a [Group] built the way newKindWalk builds one, driving [Group.openPageLocked] and
// [Group.commitWalkLocked] over a page of records exactly as [Group.Receive] does below the fetch.
// The HOSTILE committer is a real device too: it builds its commit through the seam's by-value
// arms (CommitRemove, CommitPolicy, CommitContextExtensions, CommitAdd), merges it, and seals the
// commit record through its session the way [Group.AddMemberAndPublish] seals one -- it has no
// send-side check, which is R2, so nothing stops it from committing what its role does not permit.
// What is NOT here is the server, which is the cp3b module's; the server accepts every commit
// anyway, so what a refusal costs (the receiver stays at n, the server has moved on) is the same
// with or without it.

// roleMember is one member of the role world: its device, handle, session and receiving group.
type roleMember struct {
	name    string
	dev     *crossProcessDevice
	handle  messagegroup.GroupHandle
	session *messagegroup.GroupSession
	group   *Group
	leaf    uint32
}

// roleWorld is one group of real members at a common epoch, with the server's record numbering
// assigned here because no server is present.
type roleWorld struct {
	t              *testing.T
	root           string
	groupId        []byte
	pqSecret       []byte
	groupHandleKey []byte
	members        map[string]*roleMember
	nextRecordId   uint64
}

// newRoleWorld founds a group with names[0] as its OWNER and adds every other name in ONE commit,
// so every member stands at epoch 1 with the founder the only named role -- exactly the shape
// every live group has (item 242: "every non-founder in every live group is UNNAMED").
func newRoleWorld(t *testing.T, names ...string) *roleWorld {
	t.Helper()
	world := &roleWorld{
		t:            t,
		root:         t.TempDir(),
		groupId:      make([]byte, GroupIdBytes),
		members:      map[string]*roleMember{},
		nextRecordId: 1,
	}
	if _, err := rand.Read(world.groupId); err != nil {
		t.Fatalf("drawing a group id: %v", err)
	}
	pqSecret, err := messagegroup.NewPqSecret(rand.Reader)
	if err != nil {
		t.Fatalf("pq_secret: %v", err)
	}
	world.pqSecret = pqSecret

	founder := world.device(names[0])
	founderHandle := founder.createGroup(t, world.groupId)
	t.Cleanup(func() { founderHandle.Close() })
	mlsSecret, err := founderHandle.Export(storageExporterLabel, nil, storageExporterBytes)
	if err != nil {
		t.Fatalf("the epoch zero exporter: %v", err)
	}
	world.groupHandleKey = messagegroup.GroupHandleKey(messagegroup.StorageRoot(mlsSecret, pqSecret))

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

func (self *roleWorld) device(name string) *crossProcessDevice {
	self.t.Helper()
	dev := openCrossProcessDevice(self.t, filepath.Join(self.root, name))
	self.t.Cleanup(dev.close)
	return dev
}

// enroll gives one member a session and a receiving [Group] over its handle, built field by field
// for newKindWalk's reason: everything below the fetch is what is under test.
func (self *roleWorld) enroll(name string, dev *crossProcessDevice, handle messagegroup.GroupHandle) *roleMember {
	self.t.Helper()
	session := newCrossProcessSession(self.t, handle, self.pqSecret, self.groupHandleKey, dev.reserver, name+"'s nonce")
	self.t.Cleanup(func() { session.Close() })
	group := &Group{
		device: &Device{
			stateStore:  dev.store,
			engine:      dev.engine,
			reserver:    dev.reserver,
			identityPub: append([]byte(nil), dev.identityPub...),
			nowMs:       func() int64 { return time.Now().UnixMilli() },
			random:      rand.Reader,
			groups:      map[string]*Group{},
		},
		id:             append([]byte(nil), self.groupId...),
		handle:         handle,
		groupHandleKey: self.groupHandleKey,
		pqSecret:       self.pqSecret,
		session:        session,
		epoch:          handle.Epoch(),
		opened:         true,
		reconciled:     true,
	}
	group.initTables()
	member := &roleMember{name: name, dev: dev, handle: handle, session: session, group: group, leaf: handle.OwnLeafIndex()}
	self.members[name] = member
	return member
}

func (self *roleWorld) member(name string) *roleMember {
	self.t.Helper()
	member, held := self.members[name]
	if !held {
		self.t.Fatalf("no member named %q", name)
	}
	return member
}

// publish seals one commit the committer has already built and MERGED as the record every other
// member walks, and moves the committer's session and group onto the epoch it opened: the (1)-(4)
// of [Group.AddMemberAndPublish] with no server in between. The record is sealed at the OLD epoch
// by the session, which is still there after the handle merged, exactly as production seals it.
func (self *roleWorld) publish(committer *roleMember, commit []byte) *sealed {
	self.t.Helper()
	record, err := committer.session.SealRecord(message.RetentionPermanent, 0, true,
		encodeHead(time.Now().UnixMilli()), commit, 0, nil)
	if err != nil {
		self.t.Fatalf("%s sealing its commit record: %v", committer.name, err)
	}
	newEpoch := committer.handle.Epoch()
	if err := committer.session.AdvanceEpoch(self.pqSecret); err != nil {
		self.t.Fatalf("%s advancing its session to epoch %d: %v", committer.name, newEpoch, err)
	}
	if err := committer.group.crossEpochLadderLocked(newEpoch); err != nil {
		self.t.Fatalf("%s crossing the epoch: %v", committer.name, err)
	}
	if err := committer.group.enterEpochLocked(); err != nil {
		self.t.Fatalf("%s entering epoch %d: %v", committer.name, newEpoch, err)
	}
	one := &sealed{recordId: self.nextRecordId, record: record}
	self.nextRecordId += 1
	return one
}

// deliver walks one page holding the records through a receiver's group, as newKindWalk.deliver
// does, and answers what [Group.Receive] would: the walk's first failure.
func (self *roleWorld) deliver(receiver *roleMember, page ...*sealed) error {
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

// commitAndPublish runs one of the seam's by-value arms on the committer's handle, merges, and
// publishes the record.
func (self *roleWorld) commitAndPublish(committer *roleMember, what string,
	arm func() ([]byte, []byte, []byte, error)) *sealed {

	self.t.Helper()
	commit, _, _, err := arm()
	if err != nil {
		self.t.Fatalf("%s's %s: %v", committer.name, what, err)
	}
	if err := committer.handle.MergePendingCommit(); err != nil {
		self.t.Fatalf("%s's MergePendingCommit after %s: %v", committer.name, what, err)
	}
	return self.publish(committer, commit)
}

// policyOf is a member's current policy, decoded off its own group context.
func (self *roleWorld) policyOf(member *roleMember) *mls.GroupPolicyExtension {
	self.t.Helper()
	extensions, err := member.group.contextExtensionsLocked()
	if err != nil {
		self.t.Fatalf("%s's group context: %v", member.name, err)
	}
	policy, err := mls.GroupPolicyOf(mlsExtensionsOf(extensions))
	if err != nil {
		self.t.Fatalf("%s's policy: %v", member.name, err)
	}
	return policy
}

// policyBody encodes a policy as the body CommitPolicy takes.
func (self *roleWorld) policyBody(policy *mls.GroupPolicyExtension) []byte {
	self.t.Helper()
	if err := policy.Canonicalize(); err != nil {
		self.t.Fatalf("canonicalizing: %v", err)
	}
	encoded, err := policy.Encode()
	if err != nil {
		self.t.Fatalf("encoding the policy: %v", err)
	}
	return encoded.ExtensionData
}

// refuse delivers one record to a receiver and holds the whole of what a refusal promises: the
// error wraps ErrCommitUnauthorized and the rule, the group and its handle stayed at the epoch
// they were at, nothing more was ingested, and the refusal was counted exactly once. It answers
// the error for a caller that wants to read more off it.
func (self *roleWorld) refuse(receiver *roleMember, record *sealed, rule error) error {
	self.t.Helper()
	epoch := receiver.group.Epoch()
	before := receiver.group.Stats()
	err := self.deliver(receiver, record)
	if err == nil {
		self.t.Fatalf("%s ingested the commit; it is now at epoch %d", receiver.name, receiver.group.Epoch())
	}
	if !errors.Is(err, ErrCommitUnauthorized) {
		self.t.Errorf("%s answered %v, which does not wrap ErrCommitUnauthorized", receiver.name, err)
	}
	if !errors.Is(err, rule) {
		self.t.Errorf("%s answered %v, which does not wrap the rule %v", receiver.name, err, rule)
	}
	if got := receiver.group.Epoch(); got != epoch {
		self.t.Errorf("%s's group is at epoch %d after a refusal, want %d", receiver.name, got, epoch)
	}
	if got := receiver.handle.Epoch(); got != epoch {
		self.t.Errorf("%s's handle is at epoch %d after a refusal, want %d: the commit was applied", receiver.name, got, epoch)
	}
	after := receiver.group.Stats()
	if after.CommitRefused != before.CommitRefused+1 {
		self.t.Errorf("%s's Stats.CommitRefused went %d -> %d, want one more", receiver.name, before.CommitRefused, after.CommitRefused)
	}
	if after.Ingested != before.Ingested {
		self.t.Errorf("%s's Stats.Ingested went %d -> %d over a refusal", receiver.name, before.Ingested, after.Ingested)
	}
	return err
}

// ingest delivers one record to a receiver and holds the allowed half: no error, the epoch moved
// by one, nothing was counted as refused, and the receiver's exporter agrees with the committer's
// -- which an epoch counter cannot say.
func (self *roleWorld) ingest(receiver *roleMember, committer *roleMember, record *sealed) {
	self.t.Helper()
	epoch := receiver.group.Epoch() + 1
	before := receiver.group.Stats()
	err := self.deliver(receiver, record)
	if err != nil {
		self.t.Fatalf("%s refused a commit the rules allow: %v", receiver.name, err)
	}
	if got := receiver.group.Epoch(); got != epoch {
		self.t.Fatalf("%s's group is at epoch %d, want %d", receiver.name, got, epoch)
	}
	after := receiver.group.Stats()
	if after.CommitRefused != before.CommitRefused {
		self.t.Errorf("%s counted a refusal over an allowed commit", receiver.name)
	}
	if after.Ingested != before.Ingested+1 {
		self.t.Errorf("%s's Stats.Ingested went %d -> %d, want one more", receiver.name, before.Ingested, after.Ingested)
	}
	mine, err := receiver.handle.Export(storageExporterLabel, nil, storageExporterBytes)
	if err != nil {
		self.t.Fatalf("%s's exporter: %v", receiver.name, err)
	}
	theirs, err := committer.handle.Export(storageExporterLabel, nil, storageExporterBytes)
	if err != nil {
		self.t.Fatalf("%s's exporter: %v", committer.name, err)
	}
	if string(mine) != string(theirs) {
		self.t.Errorf("%s and %s disagree about the epoch %d exporter", receiver.name, committer.name, epoch)
	}
}

// A MEMBER'S REMOVE OF THE OWNER IS REFUSED BY EVERY HONEST RECEIVER: item 242's Q2, the hole
// this arm exists to close. Before R1 every honest receiver applied it and the policy went on
// naming an identity with no leaf as owner.
func TestAMembersRemoveOfTheOwnerIsRefusedByEveryHonestReceiver(t *testing.T) {
	world := newRoleWorld(t, "owner", "mallory", "carol")
	owner, mallory, carol := world.member("owner"), world.member("mallory"), world.member("carol")

	record := world.commitAndPublish(mallory, "CommitRemove of the owner", func() ([]byte, []byte, []byte, error) {
		return mallory.handle.CommitRemove([]uint32{owner.leaf})
	})
	if mallory.group.Epoch() != 2 {
		t.Fatalf("the hostile committer is at epoch %d after its own merge, want 2", mallory.group.Epoch())
	}
	for _, honest := range []*roleMember{owner, carol} {
		world.refuse(honest, record, mls.ErrAdminRemovedByNonOwner)
	}
	// THE RECORD IS RETRIED LIKE ANY INGEST FAILURE AND THE RETRY NEVER REACHES THE RULES: the
	// first Process opened the commit's MLS frame and spent that generation of the committer's
	// ratchet, so the second walk is refused by mls at Process, as an ingest failure and not as
	// a second refusal. One refusal is counted once; the receiver is still at the epoch before.
	err := world.deliver(carol, record)
	if !errors.Is(err, ErrCommitIngest) || errors.Is(err, ErrCommitUnauthorized) {
		t.Errorf("the second walk over the refused commit answered %v, want an ingest failure at Process", err)
	}
	if got := carol.group.Stats().CommitRefused; got != 1 {
		t.Errorf("carol's Stats.CommitRefused is %d after two walks, want 1", got)
	}
	if carol.group.Epoch() != 1 {
		t.Errorf("carol moved to epoch %d", carol.group.Epoch())
	}
}

// A MEMBER'S POLICY NAMING ITSELF OWNER IS REFUSED: item 242's P2, R5.
func TestAMembersPolicyNamingItselfOwnerIsRefused(t *testing.T) {
	world := newRoleWorld(t, "owner", "mallory", "carol")
	owner, mallory, carol := world.member("owner"), world.member("mallory"), world.member("carol")

	coup := world.policyOf(mallory)
	coup.SetRole(owner.dev.identityPub, mls.RoleAdmin)
	coup.SetRole(mallory.dev.identityPub, mls.RoleOwner)
	record := world.commitAndPublish(mallory, "CommitPolicy naming itself owner", func() ([]byte, []byte, []byte, error) {
		return mallory.handle.CommitPolicy(world.policyBody(coup))
	})
	for _, honest := range []*roleMember{owner, carol} {
		world.refuse(honest, record, ErrCommitOwnerTransfer)
	}
}

// A CONTEXT EXTENSIONS COMMIT THAT DROPS 0xF001 IS REFUSED (R0a, item 242's P3), AND ONE THAT
// DROPS 0x0003 IS REFUSED (R0b, item 242's P4) -- each by every honest receiver, and each a
// commit the seam builds and mls accepts.
func TestAContextExtensionsCommitDroppingThePolicyOrTheCapabilitiesIsRefused(t *testing.T) {
	without := func(extensions []messagegroup.ExtensionBytes, dropped uint16) []messagegroup.ExtensionBytes {
		out := []messagegroup.ExtensionBytes{}
		for _, extension := range extensions {
			if extension.Type != dropped {
				out = append(out, extension)
			}
		}
		return out
	}
	rows := []struct {
		name    string
		dropped uint16
		rule    error
	}{
		{"dropping urmessage_group_policy", uint16(mls.ExtensionTypeUrmessageGroupPolicy), ErrCommitPolicyInvalid},
		{"dropping required_capabilities", 0x0003, ErrCommitExtensionChanged},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			world := newRoleWorld(t, "owner", "mallory", "carol")
			owner, mallory, carol := world.member("owner"), world.member("mallory"), world.member("carol")
			current, err := mallory.group.contextExtensionsLocked()
			if err != nil {
				t.Fatal(err)
			}
			// THE POSITIVE CONTROL: the list carries what is about to be dropped
			stripped := without(current, row.dropped)
			if len(stripped) != len(current)-1 {
				t.Fatalf("the group context carries %d extension(s) and none of type %#04x: %v", len(current), row.dropped, current)
			}
			record := world.commitAndPublish(mallory, "CommitContextExtensions", func() ([]byte, []byte, []byte, error) {
				return mallory.handle.CommitContextExtensions(stripped)
			})
			for _, honest := range []*roleMember{owner, carol} {
				err := world.refuse(honest, record, row.rule)
				if row.dropped == uint16(mls.ExtensionTypeUrmessageGroupPolicy) && !errors.Is(err, mls.ErrNoGroupPolicy) {
					t.Errorf("%s's refusal does not carry mls.ErrNoGroupPolicy: %v", honest.name, err)
				}
			}
		})
	}
}

// A POLICY NAMING AN IDENTITY WITH NO LEAF IS REFUSED (R0c), even from the owner.
func TestAPolicyNamingAnIdentityWithNoLeafIsRefused(t *testing.T) {
	world := newRoleWorld(t, "owner", "bob", "carol")
	owner, bob, carol := world.member("owner"), world.member("bob"), world.member("carol")

	phantom := world.policyOf(owner)
	phantom.SetRole(roleIdentity("nobody"), mls.RoleMember)
	record := world.commitAndPublish(owner, "CommitPolicy naming a phantom", func() ([]byte, []byte, []byte, error) {
		return owner.handle.CommitPolicy(world.policyBody(phantom))
	})
	for _, honest := range []*roleMember{bob, carol} {
		world.refuse(honest, record, ErrCommitPolicyPhantom)
	}
}

// THE OWNER'S PROMOTION IS ALLOWED, AND AFTERWARDS ONLY THE ADMIN MAY ADD: R4 lets the owner seat
// an admin, R1 lets that admin add a new identity, and R1 refuses the same add from a member. The
// allowed commits move every receiver and their exporters agree with the committer's.
func TestAnOwnersPromotionIsAllowedAndOnlyTheAdminMayThenAdd(t *testing.T) {
	world := newRoleWorld(t, "owner", "bob", "carol")
	owner, bob, carol := world.member("owner"), world.member("bob"), world.member("carol")

	// epoch 1 -> 2: the owner makes bob an admin
	promotion := world.policyOf(owner)
	promotion.SetRole(bob.dev.identityPub, mls.RoleAdmin)
	record := world.commitAndPublish(owner, "CommitPolicy promoting bob", func() ([]byte, []byte, []byte, error) {
		return owner.handle.CommitPolicy(world.policyBody(promotion))
	})
	for _, honest := range []*roleMember{bob, carol} {
		world.ingest(honest, owner, record)
	}
	if role, _ := world.policyOf(carol).RoleOf(bob.dev.identityPub); role != mls.RoleAdmin {
		t.Fatalf("carol reads bob as %s after the promotion", role)
	}

	// epoch 2 -> 3: bob, now an admin, adds dave
	dave := world.device("dave")
	daveKeyPackage, err := dave.engine.NewKeyPackage()
	if err != nil {
		t.Fatal(err)
	}
	record = world.commitAndPublish(bob, "CommitAdd of dave", func() ([]byte, []byte, []byte, error) {
		return bob.handle.CommitAdd([][]byte{daveKeyPackage})
	})
	for _, honest := range []*roleMember{owner, carol} {
		world.ingest(honest, bob, record)
	}

	// epoch 3 -> refused: carol, a member, adds erin
	erin := world.device("erin")
	erinKeyPackage, err := erin.engine.NewKeyPackage()
	if err != nil {
		t.Fatal(err)
	}
	record = world.commitAndPublish(carol, "CommitAdd of erin", func() ([]byte, []byte, []byte, error) {
		return carol.handle.CommitAdd([][]byte{erinKeyPackage})
	})
	for _, honest := range []*roleMember{owner, bob} {
		world.refuse(honest, record, ErrCommitAddByNonAdmin)
		if honest.group.Epoch() != 3 {
			t.Errorf("%s is at epoch %d, want 3", honest.name, honest.group.Epoch())
		}
	}
}

// claimingKeyPackage is a key package whose credential CLAIMS an identity it does not sign with:
// a fresh signer under another member's identity, which nothing in mls refuses (item 242's M7).
// It is also, with the claimed identity's own device committing it, what a second device of that
// identity looks like in this build.
func claimingKeyPackage(t *testing.T, root string, claimed []byte) []byte {
	t.Helper()
	store, err := OpenDurableStateStore(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	crypto, err := mls.NewCryptoProvider(deviceCipherSuite)
	if err != nil {
		t.Fatal(err)
	}
	signer, _, leafKeys, err := deviceIdentity(crypto, store, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := messagegroup.NewConnectMlsEngine(crypto, store, signer, mls.BasicCredential(claimed), leafKeys)
	if err != nil {
		t.Fatal(err)
	}
	keyPackage, err := engine.NewKeyPackage()
	if err != nil {
		t.Fatal(err)
	}
	return keyPackage
}

// AN ADD CLAIMING THE OWNER'S IDENTITY, COMMITTED BY AN ADMIN, IS REFUSED (R6a): the credential
// would otherwise inherit the owner's role at every member.
func TestAnAddClaimingTheOwnersIdentityByAnAdminIsRefused(t *testing.T) {
	world := newRoleWorld(t, "owner", "bob", "carol")
	owner, bob, carol := world.member("owner"), world.member("bob"), world.member("carol")

	promotion := world.policyOf(owner)
	promotion.SetRole(bob.dev.identityPub, mls.RoleAdmin)
	record := world.commitAndPublish(owner, "CommitPolicy promoting bob", func() ([]byte, []byte, []byte, error) {
		return owner.handle.CommitPolicy(world.policyBody(promotion))
	})
	for _, honest := range []*roleMember{bob, carol} {
		world.ingest(honest, owner, record)
	}

	claim := claimingKeyPackage(t, filepath.Join(world.root, "claimant"), owner.dev.identityPub)
	record = world.commitAndPublish(bob, "CommitAdd of a leaf claiming the owner", func() ([]byte, []byte, []byte, error) {
		return bob.handle.CommitAdd([][]byte{claim})
	})
	for _, honest := range []*roleMember{owner, carol} {
		world.refuse(honest, record, ErrCommitIdentityClaimed)
	}
}

// THE OWNER ADDING ITS OWN SECOND DEVICE IS ALLOWED (R6a's other arm), and afterwards the owner's
// identity holds two leaves at every receiver.
func TestTheOwnerAddingItsOwnSecondDeviceIsAllowed(t *testing.T) {
	world := newRoleWorld(t, "owner", "bob", "carol")
	owner, bob, carol := world.member("owner"), world.member("bob"), world.member("carol")

	second := claimingKeyPackage(t, filepath.Join(world.root, "owner-laptop"), owner.dev.identityPub)
	record := world.commitAndPublish(owner, "CommitAdd of its own second device", func() ([]byte, []byte, []byte, error) {
		return owner.handle.CommitAdd([][]byte{second})
	})
	for _, honest := range []*roleMember{bob, carol} {
		world.ingest(honest, owner, record)
		ownerLeaves := 0
		for at := 0; at < honest.handle.MemberCount(); at += 1 {
			_, identity, _, err := honest.handle.MemberAt(at)
			if err != nil {
				t.Fatal(err)
			}
			if string(identity) == string(owner.dev.identityPub) {
				ownerLeaves += 1
			}
		}
		if ownerLeaves != 2 {
			t.Errorf("%s holds %d leaf(s) for the owner's identity after the add, want 2", honest.name, ownerLeaves)
		}
	}
}

// A MEMBER OR AN OBSERVER MAY COMMIT ITS OWN DEVICE LEAVES AND NOTHING ELSE (R7): §11's table
// gives "commit epochs" to ADMIN and OWNER, and ruling 5 gives the OBSERVER "its own device add /
// remove and nothing else". Three commits the seam builds and mls accepts, each refused by every
// honest receiver, after the positive control -- a member's own second device, which the same
// rule allows and every receiver ingests. The Update by reference is the one that carries no
// membership change at all: the owner's own key rotation, committed by an observer, moves every
// honest receiver an epoch under a committer whose role does not commit epochs.
func TestAMemberOrAnObserverMayCommitOnlyItsOwnDeviceLeaves(t *testing.T) {
	t.Run("a member's own second device is ingested and its bare commit is refused", func(t *testing.T) {
		world := newRoleWorld(t, "owner", "bob", "carol")
		owner, bob, carol := world.member("owner"), world.member("bob"), world.member("carol")

		// epoch 1 -> 2: the positive control, through the real seam
		laptop := claimingKeyPackage(t, filepath.Join(world.root, "bob-laptop"), bob.dev.identityPub)
		record := world.commitAndPublish(bob, "CommitAdd of its own second device", func() ([]byte, []byte, []byte, error) {
			return bob.handle.CommitAdd([][]byte{laptop})
		})
		for _, honest := range []*roleMember{owner, carol} {
			world.ingest(honest, bob, record)
		}

		// epoch 2 -> refused: the same member's commit that changes no device leaf
		record = world.commitAndPublish(bob, "Commit(nil)", func() ([]byte, []byte, []byte, error) {
			return bob.handle.Commit(nil)
		})
		for _, honest := range []*roleMember{owner, carol} {
			world.refuse(honest, record, ErrCommitBeyondOwnDevices)
			if honest.group.Epoch() != 2 {
				t.Errorf("%s is at epoch %d, want 2", honest.name, honest.group.Epoch())
			}
		}
	})

	t.Run("an observer's bare commit is refused", func(t *testing.T) {
		world := newRoleWorld(t, "owner", "olive", "carol")
		owner, olive, carol := world.member("owner"), world.member("olive"), world.member("carol")
		world.demoteToObserver(owner, olive, carol)

		record := world.commitAndPublish(olive, "Commit(nil)", func() ([]byte, []byte, []byte, error) {
			return olive.handle.Commit(nil)
		})
		for _, honest := range []*roleMember{owner, carol} {
			world.refuse(honest, record, ErrCommitBeyondOwnDevices)
		}
	})

	t.Run("an observer committing the owner's update by reference is refused", func(t *testing.T) {
		world := newRoleWorld(t, "owner", "olive", "carol")
		owner, olive, carol := world.member("owner"), world.member("olive"), world.member("carol")
		world.demoteToObserver(owner, olive, carol)

		// the owner's own key rotation, cached at every member as a proposal record would leave it
		proposal, err := owner.handle.ProposeUpdate()
		if err != nil {
			t.Fatalf("the owner's ProposeUpdate: %v", err)
		}
		for _, receiver := range []*roleMember{olive, carol} {
			processed, err := receiver.handle.Process(proposal)
			if err != nil {
				t.Fatalf("%s processing the owner's update proposal: %v", receiver.name, err)
			}
			if processed.Kind != messagegroup.EngineProcessedProposal {
				t.Fatalf("%s processed the owner's update as kind %d, want a proposal", receiver.name, processed.Kind)
			}
		}
		// Commit(nil) folds in every cached proposal: the commit carries the owner's Update by
		// reference and nothing else
		record := world.commitAndPublish(olive, "Commit(nil) over the owner's cached update", func() ([]byte, []byte, []byte, error) {
			return olive.handle.Commit(nil)
		})
		for _, honest := range []*roleMember{owner, carol} {
			world.refuse(honest, record, ErrCommitBeyondOwnDevices)
		}
	})
}

// demoteToObserver has the owner commit a policy making one member an OBSERVER, and every member
// ingest it -- R4's "set MEMBER/OBSERVER" arm, which the owner holds.
func (self *roleWorld) demoteToObserver(owner *roleMember, who *roleMember, others ...*roleMember) {
	self.t.Helper()
	demotion := self.policyOf(owner)
	demotion.SetRole(who.dev.identityPub, mls.RoleObserver)
	record := self.commitAndPublish(owner, "CommitPolicy demoting "+who.name, func() ([]byte, []byte, []byte, error) {
		return owner.handle.CommitPolicy(self.policyBody(demotion))
	})
	for _, receiver := range append([]*roleMember{who}, others...) {
		self.ingest(receiver, owner, record)
	}
	if role, _ := self.policyOf(who).RoleOf(who.dev.identityPub); role != mls.RoleObserver {
		self.t.Fatalf("%s reads itself as %s after the demotion, want observer", who.name, role)
	}
}

// A CONFIGURED AUTHORIZER THAT ALLOWS CANNOT ALLOW WHAT THE RULES REFUSE, and one that refuses
// refuses what the rules allow: the two compose, the rules first.
func TestAConfiguredAuthorizerComposesWithTheRulesAndCannotLoosenThem(t *testing.T) {
	world := newRoleWorld(t, "owner", "mallory", "carol")
	owner, mallory, carol := world.member("owner"), world.member("mallory"), world.member("carol")

	asked := 0
	carol.group.device.commitAuthorizer = func(*CommitAuthorization) error {
		asked += 1
		return nil
	}
	record := world.commitAndPublish(mallory, "CommitRemove of the owner", func() ([]byte, []byte, []byte, error) {
		return mallory.handle.CommitRemove([]uint32{owner.leaf})
	})
	world.refuse(carol, record, mls.ErrAdminRemovedByNonOwner)
	if asked != 0 {
		t.Errorf("the configured authorizer was asked %d time(s) about a commit the rules refused", asked)
	}

	// the other direction, on a fresh world: an allowed commit reaches the hook, and the hook's
	// refusal is carried
	world = newRoleWorld(t, "owner", "bob", "carol")
	bob := world.member("bob")
	owner, carol = world.member("owner"), world.member("carol")
	productRule := errors.New("this product refuses every promotion")
	var seen *CommitAuthorization
	carol.group.device.commitAuthorizer = func(decision *CommitAuthorization) error {
		seen = decision
		return productRule
	}
	promotion := world.policyOf(owner)
	promotion.SetRole(bob.dev.identityPub, mls.RoleAdmin)
	record = world.commitAndPublish(owner, "CommitPolicy promoting bob", func() ([]byte, []byte, []byte, error) {
		return owner.handle.CommitPolicy(world.policyBody(promotion))
	})
	world.ingest(bob, owner, record)
	world.refuse(carol, record, productRule)
	if seen == nil {
		t.Fatal("the configured authorizer was never asked about an allowed commit")
	}
	// and it was handed the filled value: committer, roles on both sides, both policies
	if string(seen.CommitterIdentity) != string(owner.dev.identityPub) || seen.CommitterRole != mls.RoleOwner.String() {
		t.Errorf("the hook saw committer %x as %q, want the owner", seen.CommitterIdentity, seen.CommitterRole)
	}
	if seen.PolicyBefore == nil || seen.PolicyAfter == nil {
		t.Fatalf("the hook saw policies before=%v after=%v", seen.PolicyBefore, seen.PolicyAfter)
	}
	if role, _ := seen.PolicyAfter.RoleOf(bob.dev.identityPub); role != mls.RoleAdmin {
		t.Errorf("the hook's PolicyAfter reads bob as %s", role)
	}
	if len(seen.Members) != 3 || len(seen.MembersAfter) != 3 {
		t.Errorf("the hook saw %d members before and %d after, want 3 and 3", len(seen.Members), len(seen.MembersAfter))
	}
	for _, member := range seen.MembersAfter {
		if string(member.IdentityPub) == string(bob.dev.identityPub) && member.Role != mls.RoleAdmin.String() {
			t.Errorf("MembersAfter reads bob as %q", member.Role)
		}
	}
}

// THE INGEST PATH ERASES THE STAGED EPOCH ON EVERY EXIT, read off the source: a refused commit is
// a fully derived second epoch that nothing else would erase, and the seam's door for it is
// DiscardProcessed. The pin is that [Group.ingestCommitLocked] defers that call, so no return
// between Process and ApplyCommit -- the refusal's included -- can leave it out.
func TestTheIngestPathDefersTheDiscardOfTheStagedEpoch(t *testing.T) {
	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(fileSet, "group.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	deferred := false
	found := false
	for _, declaration := range parsed.Decls {
		function, isFunction := declaration.(*ast.FuncDecl)
		if !isFunction || function.Name.Name != "ingestCommitLocked" {
			continue
		}
		found = true
		ast.Inspect(function.Body, func(node ast.Node) bool {
			statement, isDefer := node.(*ast.DeferStmt)
			if !isDefer {
				return true
			}
			ast.Inspect(statement.Call, func(inner ast.Node) bool {
				call, isCall := inner.(*ast.CallExpr)
				if !isCall {
					return true
				}
				if selector, isSelector := call.Fun.(*ast.SelectorExpr); isSelector && selector.Sel.Name == "DiscardProcessed" {
					deferred = true
				}
				return true
			})
			return true
		})
	}
	if !found {
		t.Fatal("group.go declares no ingestCommitLocked")
	}
	if !deferred {
		t.Fatal(fmt.Sprintf("ingestCommitLocked defers no DiscardProcessed: a refused commit's staged epoch is left in the heap"))
	}
}
