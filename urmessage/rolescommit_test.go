package urmessage

import (
	"bytes"
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/connect/messagegroup"
	"github.com/urnetwork/connect/mls"
)

// ── the committing arm: the same predicate, over the same value, before the commit exists ────
//
// WHAT IS REAL HERE is what rolesingest_test.go's header says: every member is a real device over
// the shipped engine with a real session and a receiving [Group]. What is NEW is that the
// committer's own [Group] is now asked, through the production verbs, and refuses -- and the world's
// devices carry NO TRANSPORT, so a verb that reached the connection over a refusal would panic
// rather than pass. The allowed path is [TestTheSendSideJudgesTheSameValueEveryReceiverWillJudge]'s
// comparison in this package and cp3b's real server in that module.

// outgoingDecision builds the send-side decision on a member's group for one intent, as the verbs
// do, failing the test on a build error rather than a refusal.
func (self *roleWorld) outgoingDecision(member *roleMember, intent *outgoingCommit) *CommitAuthorization {
	self.t.Helper()
	decision, err := member.group.outgoingAuthorizationLocked(intent)
	if err != nil {
		self.t.Fatalf("%s building its send-side decision: %v", member.name, err)
	}
	return decision
}

// receivedDecision processes commit bytes at a receiver and answers the decision the receiving arm
// would judge, WITHOUT applying it: Process, the decision, then the seam's erase. The receiver's
// ratchet generation for the committer is spent by the Process, which is the cost every refusal
// pays and is why the receiver is not asked to ingest anything afterwards.
func (self *roleWorld) receivedDecision(receiver *roleMember, commit []byte) *CommitAuthorization {
	self.t.Helper()
	processed, err := receiver.handle.Process(commit)
	if err != nil {
		self.t.Fatalf("%s processing the commit: %v", receiver.name, err)
	}
	defer func() {
		if err := receiver.handle.DiscardProcessed(processed); err != nil {
			self.t.Fatalf("%s erasing the staged epoch: %v", receiver.name, err)
		}
	}()
	if processed.Kind != messagegroup.EngineProcessedCommit {
		self.t.Fatalf("%s processed kind %d, want a commit", receiver.name, processed.Kind)
	}
	decision, err := receiver.group.commitAuthorizationLocked(processed)
	if err != nil {
		self.t.Fatalf("%s building its receiving-side decision: %v", receiver.name, err)
	}
	return decision
}

// sameDecision holds two decisions to one value, field for field, naming the first field that
// differs. Nil and empty slices are one value; a policy is compared as the structure its bytes
// decode to.
func sameDecision(t *testing.T, what string, sent *CommitAuthorization, received *CommitAuthorization) {
	t.Helper()
	sameMembers := func(field string, a []CommitMember, b []CommitMember) {
		if len(a) != len(b) {
			t.Errorf("%s: %s has %d entries on the send side and %d at the receiver", what, field, len(a), len(b))
			return
		}
		for at := range a {
			if a[at].Leaf != b[at].Leaf || !bytes.Equal(a[at].SenderHandle, b[at].SenderHandle) ||
				!bytes.Equal(a[at].IdentityPub, b[at].IdentityPub) || a[at].Role != b[at].Role ||
				a[at].HasLeafKeys != b[at].HasLeafKeys {
				t.Errorf("%s: %s[%d] is %+v on the send side and %+v at the receiver", what, field, at, a[at], b[at])
			}
		}
	}
	if !bytes.Equal(sent.GroupId, received.GroupId) {
		t.Errorf("%s: GroupId differs", what)
	}
	if sent.Epoch != received.Epoch {
		t.Errorf("%s: Epoch is %d on the send side and %d at the receiver", what, sent.Epoch, received.Epoch)
	}
	if sent.CommitterLeaf != received.CommitterLeaf {
		t.Errorf("%s: CommitterLeaf is %d on the send side and %d at the receiver", what, sent.CommitterLeaf, received.CommitterLeaf)
	}
	if !bytes.Equal(sent.CommitterIdentity, received.CommitterIdentity) {
		t.Errorf("%s: CommitterIdentity is %x on the send side and %x at the receiver", what, sent.CommitterIdentity, received.CommitterIdentity)
	}
	if sent.CommitterRole != received.CommitterRole {
		t.Errorf("%s: CommitterRole is %q on the send side and %q at the receiver", what, sent.CommitterRole, received.CommitterRole)
	}
	if !slices.Equal(sent.AddedLeaves, received.AddedLeaves) {
		t.Errorf("%s: AddedLeaves is %v on the send side and %v at the receiver", what, sent.AddedLeaves, received.AddedLeaves)
	}
	if !slices.Equal(sent.RemovedLeaves, received.RemovedLeaves) {
		t.Errorf("%s: RemovedLeaves is %v on the send side and %v at the receiver", what, sent.RemovedLeaves, received.RemovedLeaves)
	}
	if !slices.Equal(sent.UpdatedLeaves, received.UpdatedLeaves) {
		t.Errorf("%s: UpdatedLeaves is %v on the send side and %v at the receiver", what, sent.UpdatedLeaves, received.UpdatedLeaves)
	}
	sameMembers("Members", sent.Members, received.Members)
	sameMembers("MembersAfter", sent.MembersAfter, received.MembersAfter)
	if !reflect.DeepEqual(sent.PolicyBefore, received.PolicyBefore) {
		t.Errorf("%s: PolicyBefore is %+v on the send side and %+v at the receiver", what, sent.PolicyBefore, received.PolicyBefore)
	}
	if !reflect.DeepEqual(sent.PolicyAfter, received.PolicyAfter) {
		t.Errorf("%s: PolicyAfter is %+v on the send side and %+v at the receiver", what, sent.PolicyAfter, received.PolicyAfter)
	}
	if (sent.PolicyBeforeErr == nil) != (received.PolicyBeforeErr == nil) || (sent.PolicyAfterErr == nil) != (received.PolicyAfterErr == nil) {
		t.Errorf("%s: the policy errors differ: send side %v / %v, receiver %v / %v", what,
			sent.PolicyBeforeErr, sent.PolicyAfterErr, received.PolicyBeforeErr, received.PolicyAfterErr)
	}
	if !extensionsEqual(sent.ExtensionsBefore, received.ExtensionsBefore) {
		t.Errorf("%s: ExtensionsBefore differs", what)
	}
	if !extensionsEqual(sent.ExtensionsAfter, received.ExtensionsAfter) {
		t.Errorf("%s: ExtensionsAfter differs: send side %v, receiver %v", what, sent.ExtensionsAfter, received.ExtensionsAfter)
	}
}

// THE SEND SIDE JUDGES THE SAME VALUE EVERY RECEIVER WILL JUDGE, which is the whole of what makes
// one predicate two arms: for each shape a verb builds -- an Add of a stranger, an Add of the
// committer's own second device, a policy commit promoting a member, a transfer, and a Remove
// through the builder's own arm -- the decision built BEFORE the commit exists, off the live
// tree and the intent, equals field for field the decision a receiver builds off the staged
// commit the seam then produces. The leaves an Add lands on, the identities and leaf-key facts
// read off the key package, the post-commit list with 0xF001 replaced and 0x0003 kept, the
// committer's leaf, identity and role: all of it.
//
// WHAT WOULD GO RED: an Add placed anywhere but the leftmost blank leaf, a key package's identity
// or leaf keys read differently from how the staged tree reports them, a policy body replaced by
// anything but the seam's own helper, or the committer read off the device rather than the tree.
func TestTheSendSideJudgesTheSameValueEveryReceiverWillJudge(t *testing.T) {
	type shape struct {
		name   string
		intent func(t *testing.T, world *roleWorld, owner *roleMember) *outgoingCommit
		build  func(t *testing.T, world *roleWorld, owner *roleMember, intent *outgoingCommit) []byte
	}
	shapes := []shape{
		{
			name: "an Add of a stranger",
			intent: func(t *testing.T, world *roleWorld, owner *roleMember) *outgoingCommit {
				dave := world.device("dave")
				keyPackage, err := dave.engine.NewKeyPackage()
				if err != nil {
					t.Fatal(err)
				}
				return &outgoingCommit{addKeyPackages: [][]byte{keyPackage}}
			},
			build: func(t *testing.T, world *roleWorld, owner *roleMember, intent *outgoingCommit) []byte {
				commit, _, _, err := owner.handle.CommitAdd(intent.addKeyPackages)
				if err != nil {
					t.Fatalf("CommitAdd: %v", err)
				}
				return commit
			},
		},
		{
			name: "an Add of the committer's own second device",
			intent: func(t *testing.T, world *roleWorld, owner *roleMember) *outgoingCommit {
				laptop := claimingKeyPackage(t, filepath.Join(world.root, "owner-laptop"), owner.dev.identityPub)
				return &outgoingCommit{addKeyPackages: [][]byte{laptop}}
			},
			build: func(t *testing.T, world *roleWorld, owner *roleMember, intent *outgoingCommit) []byte {
				commit, _, _, err := owner.handle.CommitAdd(intent.addKeyPackages)
				if err != nil {
					t.Fatalf("CommitAdd: %v", err)
				}
				return commit
			},
		},
		{
			name: "a policy commit promoting a member",
			intent: func(t *testing.T, world *roleWorld, owner *roleMember) *outgoingCommit {
				promotion := world.policyOf(owner)
				promotion.SetRole(world.member("bob").dev.identityPub, mls.RoleAdmin)
				body, err := policyBodyOf(promotion)
				if err != nil {
					t.Fatal(err)
				}
				return &outgoingCommit{policy: body}
			},
			build: func(t *testing.T, world *roleWorld, owner *roleMember, intent *outgoingCommit) []byte {
				commit, _, _, err := owner.handle.CommitPolicy(intent.policy)
				if err != nil {
					t.Fatalf("CommitPolicy: %v", err)
				}
				return commit
			},
		},
		{
			name: "a transfer of ownership",
			intent: func(t *testing.T, world *roleWorld, owner *roleMember) *outgoingCommit {
				transfer := world.policyOf(owner)
				transfer.SetRole(world.member("bob").dev.identityPub, mls.RoleOwner)
				transfer.SetRole(owner.dev.identityPub, mls.RoleAdmin)
				body, err := policyBodyOf(transfer)
				if err != nil {
					t.Fatal(err)
				}
				return &outgoingCommit{policy: body}
			},
			build: func(t *testing.T, world *roleWorld, owner *roleMember, intent *outgoingCommit) []byte {
				commit, _, _, err := owner.handle.CommitPolicy(intent.policy)
				if err != nil {
					t.Fatalf("CommitPolicy: %v", err)
				}
				return commit
			},
		},
		{
			name: "a Remove of a member, through the builder's own arm",
			intent: func(t *testing.T, world *roleWorld, owner *roleMember) *outgoingCommit {
				return &outgoingCommit{removeLeaves: []uint32{world.member("carol").leaf}}
			},
			build: func(t *testing.T, world *roleWorld, owner *roleMember, intent *outgoingCommit) []byte {
				commit, _, _, err := owner.handle.CommitRemove(intent.removeLeaves)
				if err != nil {
					t.Fatalf("CommitRemove: %v", err)
				}
				return commit
			},
		},
	}
	for _, one := range shapes {
		t.Run(one.name, func(t *testing.T) {
			world := newRoleWorld(t, "owner", "bob", "carol")
			owner, bob := world.member("owner"), world.member("bob")
			intent := one.intent(t, world, owner)

			// the decision, BEFORE the commit exists, and the rules' answer to it
			sent := world.outgoingDecision(owner, intent)
			if err := authorizeCommit(sent); err != nil {
				t.Fatalf("the rules refuse the owner's %s on the send side: %v", one.name, err)
			}
			if owner.handle.Epoch() != 1 {
				t.Fatalf("building the decision moved the owner's handle to epoch %d", owner.handle.Epoch())
			}

			// the commit the seam builds from the same intent, judged at a receiver
			commit := one.build(t, world, owner, intent)
			received := world.receivedDecision(bob, commit)
			sameDecision(t, one.name, sent, received)

			// THE POSITIVE CONTROL that the comparison is over a filled value: the intent's own
			// shape is visible in what both sides built
			if len(sent.AddedLeaves) != len(intent.addKeyPackages) || len(sent.RemovedLeaves) != len(intent.removeLeaves) {
				t.Errorf("the send-side decision declares %d add(s) and %d removal(s) for an intent of %d and %d",
					len(sent.AddedLeaves), len(sent.RemovedLeaves), len(intent.addKeyPackages), len(intent.removeLeaves))
			}
			if intent.policy != nil && reflect.DeepEqual(sent.PolicyBefore, sent.PolicyAfter) {
				t.Errorf("a policy intent left PolicyAfter equal to PolicyBefore")
			}
			owner.handle.ClearPendingCommit()
		})
	}
}

// A MEMBER'S SetRole, TransferOwnership AND AddMemberAndPublish ARE REFUSED ON THE SEND SIDE, WITH
// NOTHING BUILT: each answers ErrCommitUnauthorized wrapping the receivers' own rule, the handle and
// the group stay at their epoch, Stats.CommitRefusedOwn moves once per refusal, and the connection
// is never consulted -- the world's devices carry a nil transport, so a verb that reached it over a
// refusal would panic here rather than return. An ADMIN is judged the same way: it may set a
// member's role and may not touch the admin set or the ownership.
func TestAMembersRoleVerbsAreRefusedOnTheSendSideAndNothingIsBuilt(t *testing.T) {
	ctx := context.Background()
	world := newRoleWorld(t, "owner", "bob", "carol")
	owner, bob, carol := world.member("owner"), world.member("bob"), world.member("carol")
	stranger := world.device("stranger")
	strangerKeyPackage, err := stranger.engine.NewKeyPackage()
	if err != nil {
		t.Fatal(err)
	}

	refused := func(t *testing.T, who *roleMember, what string, rule error, verb func() error) {
		t.Helper()
		epoch, before := who.group.Epoch(), who.group.Stats()
		err := verb()
		if err == nil {
			t.Fatalf("%s's %s was allowed on the send side; %s is at epoch %d", who.name, what, who.name, who.group.Epoch())
		}
		if !errors.Is(err, ErrCommitUnauthorized) {
			t.Errorf("%s's %s answered %v, which does not wrap ErrCommitUnauthorized", who.name, what, err)
		}
		if !errors.Is(err, rule) {
			t.Errorf("%s's %s answered %v, which does not wrap the rule %v", who.name, what, err, rule)
		}
		if who.handle.Epoch() != epoch || who.group.Epoch() != epoch {
			t.Errorf("%s's %s moved the handle to %d and the group to %d after a refusal, want %d: something was built",
				who.name, what, who.handle.Epoch(), who.group.Epoch(), epoch)
		}
		after := who.group.Stats()
		if after.CommitRefusedOwn != before.CommitRefusedOwn+1 {
			t.Errorf("%s's Stats.CommitRefusedOwn went %d -> %d over its %s, want one more", who.name, before.CommitRefusedOwn, after.CommitRefusedOwn, what)
		}
		if after.CommitRefused != before.CommitRefused || after.Submitted != before.Submitted {
			t.Errorf("%s's %s moved CommitRefused or Submitted", who.name, what)
		}
	}

	// bob, an unnamed non-founder: a MEMBER (ruling 8)
	refused(t, bob, "SetRole(carol, observer)", ErrCommitPolicyChangeByNonAdmin, func() error {
		return bob.group.SetRole(ctx, carol.dev.identityPub, "observer")
	})
	refused(t, bob, "SetRole(carol, admin)", ErrCommitRoleChangeByNonOwner, func() error {
		return bob.group.SetRole(ctx, carol.dev.identityPub, "admin")
	})
	refused(t, bob, "SetRole(bob, member), a naming that changes no role", ErrCommitBeyondOwnDevices, func() error {
		return bob.group.SetRole(ctx, bob.dev.identityPub, "member")
	})
	refused(t, bob, "TransferOwnership(carol)", ErrCommitOwnerTransfer, func() error {
		return bob.group.TransferOwnership(ctx, carol.dev.identityPub)
	})
	refused(t, bob, "AddMemberAndPublish of a stranger", ErrCommitAddByNonAdmin, func() error {
		_, err := bob.group.AddMemberAndPublish(ctx, strangerKeyPackage)
		return err
	})
	if got := bob.group.Stats().CommitRefusedOwn; got != 5 {
		t.Errorf("bob's Stats.CommitRefusedOwn is %d after five refusals, want 5", got)
	}
	// and every honest member is still at epoch 1: nothing was published for anybody to ingest
	for _, member := range []*roleMember{owner, bob, carol} {
		if member.group.Epoch() != 1 || member.handle.Epoch() != 1 {
			t.Errorf("%s is at group epoch %d / handle epoch %d after bob's refused verbs, want 1 / 1", member.name, member.group.Epoch(), member.handle.Epoch())
		}
	}

	// the owner promotes bob, ingested by everybody; bob is now an ADMIN
	promotion := world.policyOf(owner)
	promotion.SetRole(bob.dev.identityPub, mls.RoleAdmin)
	record := world.commitAndPublish(owner, "CommitPolicy promoting bob", func() ([]byte, []byte, []byte, error) {
		return owner.handle.CommitPolicy(world.policyBody(promotion))
	})
	for _, honest := range []*roleMember{bob, carol} {
		world.ingest(honest, owner, record)
	}
	if role, err := bob.group.MyRole(); err != nil || role != mls.RoleAdmin.String() {
		t.Fatalf("bob's MyRole after the promotion is %q, %v; want admin", role, err)
	}

	// an ADMIN may not touch the admin set or the ownership
	refused(t, bob, "SetRole(carol, admin) as an admin", ErrCommitRoleChangeByNonOwner, func() error {
		return bob.group.SetRole(ctx, carol.dev.identityPub, "admin")
	})
	refused(t, bob, "TransferOwnership(carol) as an admin", ErrCommitOwnerTransfer, func() error {
		return bob.group.TransferOwnership(ctx, carol.dev.identityPub)
	})
	// and the owner may not crown a stranger (ruling 10): the policy names an identity with no
	// leaf, which R0c refuses before R5 is reached, at the send side as at every receiver
	refused(t, owner, "TransferOwnership(a stranger)", ErrCommitPolicyPhantom, func() error {
		return owner.group.TransferOwnership(ctx, stranger.identityPub)
	})

	// THE CONTROLS, on the same world: what each role MAY do passes the send-side decision with
	// nothing counted. The verbs themselves cannot run to completion here (no transport, which is
	// cp3b's), so the decision is asked directly.
	allowed := func(t *testing.T, who *roleMember, what string, intent *outgoingCommit) {
		t.Helper()
		before := who.group.Stats()
		if err := who.group.authorizeOutgoingLocked(intent); err != nil {
			t.Errorf("%s's %s was refused on the send side: %v", who.name, what, err)
		}
		if after := who.group.Stats(); after.CommitRefusedOwn != before.CommitRefusedOwn {
			t.Errorf("%s's %s was allowed and counted as refused", who.name, what)
		}
	}
	demotion := world.policyOf(bob)
	demotion.SetRole(carol.dev.identityPub, mls.RoleObserver)
	demotionBody, err := policyBodyOf(demotion)
	if err != nil {
		t.Fatal(err)
	}
	allowed(t, bob, "SetRole(carol, observer) as an admin", &outgoingCommit{policy: demotionBody})
	allowed(t, bob, "an Add of a stranger as an admin", &outgoingCommit{addKeyPackages: [][]byte{strangerKeyPackage}})
	laptop := claimingKeyPackage(t, filepath.Join(world.root, "carol-laptop"), carol.dev.identityPub)
	allowed(t, carol, "an Add of its own second device as a member", &outgoingCommit{addKeyPackages: [][]byte{laptop}})
	transfer := world.policyOf(owner)
	transfer.SetRole(carol.dev.identityPub, mls.RoleOwner)
	transfer.SetRole(owner.dev.identityPub, mls.RoleAdmin)
	transferBody, err := policyBodyOf(transfer)
	if err != nil {
		t.Fatal(err)
	}
	allowed(t, owner, "TransferOwnership(carol) as the owner", &outgoingCommit{policy: transferBody})
}

// THE OWNER'S VERBS PASS THE SEND-SIDE DECISION AND STOP AT THE CONNECTION, which pins the policy
// each verb BUILDS -- SetRole's one entry set, TransferOwnership's new owner up and old owner to
// ADMIN -- against the predicate, through the real verb: over a transport that has said no Hello,
// an allowed verb answers ErrNotConnected from the rebind that follows the decision, and never
// ErrCommitUnauthorized; nothing is counted and the handle does not move, because the rebind
// precedes the seam. A verb that built a policy the rules refuse -- a transfer leaving the old
// owner a member -- would answer the refusal here instead.
func TestTheOwnersVerbsPassTheSendSideAndStopAtTheConnection(t *testing.T) {
	ctx := context.Background()
	world := newRoleWorld(t, "owner", "bob", "carol")
	owner, bob, carol := world.member("owner"), world.member("bob"), world.member("carol")
	owner.group.device.transport = newSilentTransport(t)

	for _, verb := range []struct {
		name string
		call func() error
	}{
		{"SetRole(bob, admin)", func() error { return owner.group.SetRole(ctx, bob.dev.identityPub, "admin") }},
		{"SetRole(carol, observer)", func() error { return owner.group.SetRole(ctx, carol.dev.identityPub, "observer") }},
		{"TransferOwnership(bob)", func() error { return owner.group.TransferOwnership(ctx, bob.dev.identityPub) }},
	} {
		err := verb.call()
		if !errors.Is(err, ErrNotConnected) {
			t.Errorf("the owner's %s answered %v, want ErrNotConnected: the decision passed and the connection was the next thing asked", verb.name, err)
		}
		if errors.Is(err, ErrCommitUnauthorized) {
			t.Errorf("the owner's %s was refused on the send side: %v", verb.name, err)
		}
	}
	if got := owner.group.Stats().CommitRefusedOwn; got != 0 {
		t.Errorf("the owner's Stats.CommitRefusedOwn is %d over three allowed verbs, want 0", got)
	}
	if owner.handle.Epoch() != 1 || owner.group.Epoch() != 1 {
		t.Errorf("the owner's handle is at epoch %d and its group at %d after verbs that stopped at the connection, want 1 and 1",
			owner.handle.Epoch(), owner.group.Epoch())
	}
	// THE CONTROL that the connection is what stopped them: the same verb by a member answers the
	// rule and not the connection, on the same silent transport
	bob.group.device.transport = newSilentTransport(t)
	err := bob.group.SetRole(ctx, carol.dev.identityPub, "observer")
	if !errors.Is(err, ErrCommitUnauthorized) || errors.Is(err, ErrNotConnected) {
		t.Errorf("bob's SetRole over a silent transport answered %v, want the rule's refusal and not the connection's", err)
	}
}

// THE VERBS REFUSE A MALFORMED REQUEST BY NAME BEFORE ANY RULE IS REACHED, and count nothing:
// SetRole to "owner" or to a name this profile does not define is ErrRoleNotSettable, and a
// transfer to the identity that already owns the group is ErrAlreadyOwner. Each is asked of the
// OWNER, whose role permits every policy change, so that the refusal cannot be a rule's.
func TestTheVerbsRefuseAMalformedRequestByNameAndCountNothing(t *testing.T) {
	ctx := context.Background()
	world := newRoleWorld(t, "owner", "bob")
	owner, bob := world.member("owner"), world.member("bob")

	if err := owner.group.SetRole(ctx, bob.dev.identityPub, "owner"); !errors.Is(err, ErrRoleNotSettable) {
		t.Errorf("SetRole to owner answered %v, want ErrRoleNotSettable", err)
	}
	err := owner.group.SetRole(ctx, bob.dev.identityPub, "king")
	if !errors.Is(err, ErrRoleNotSettable) || !errors.Is(err, mls.ErrMalformedExtension) {
		t.Errorf("SetRole to an unknown name answered %v, want ErrRoleNotSettable wrapping mls.ErrMalformedExtension", err)
	}
	if err := owner.group.TransferOwnership(ctx, owner.dev.identityPub); !errors.Is(err, ErrAlreadyOwner) {
		t.Errorf("a transfer to the current owner answered %v, want ErrAlreadyOwner", err)
	}
	stats := owner.group.Stats()
	if stats.CommitRefusedOwn != 0 || stats.CommitRefused != 0 {
		t.Errorf("a malformed request was counted as a refusal: %+v", stats)
	}
	if owner.handle.Epoch() != 1 {
		t.Errorf("the owner's handle moved to epoch %d", owner.handle.Epoch())
	}
	// the control: the same request with a settable role reaches the rules, and the owner's
	// decision on it is allowed
	if err := owner.group.authorizeOutgoingLocked(&outgoingCommit{policy: func() []byte {
		promotion := world.policyOf(owner)
		promotion.SetRole(bob.dev.identityPub, mls.RoleAdmin)
		body, err := policyBodyOf(promotion)
		if err != nil {
			t.Fatal(err)
		}
		return body
	}()}); err != nil {
		t.Errorf("the owner's promotion of bob was refused on the send side: %v", err)
	}
}

// A CONFIGURED AUTHORIZER RUNS ON THE SEND SIDE AS ON THE OTHER, after the rules and only over a
// commit the rules allow: a product that refuses every promotion on receipt must not build one.
// Its cause is carried out through ErrCommitUnauthorized, the refusal is counted, and it is never
// asked about a commit the rules refused.
func TestAConfiguredAuthorizerAlsoRefusesOnTheSendSide(t *testing.T) {
	ctx := context.Background()
	world := newRoleWorld(t, "owner", "bob", "carol")
	owner, bob, carol := world.member("owner"), world.member("bob"), world.member("carol")

	productRule := errors.New("this product refuses every promotion")
	asked := 0
	owner.group.device.commitAuthorizer = func(decision *CommitAuthorization) error {
		asked += 1
		if role, _ := decision.PolicyAfter.RoleOf(bob.dev.identityPub); role == mls.RoleAdmin {
			return productRule
		}
		return nil
	}
	err := owner.group.SetRole(ctx, bob.dev.identityPub, "admin")
	if !errors.Is(err, ErrCommitUnauthorized) || !errors.Is(err, productRule) {
		t.Errorf("the owner's promotion answered %v, want ErrCommitUnauthorized wrapping the product's rule", err)
	}
	if asked != 1 {
		t.Errorf("the hook was asked %d time(s) about an allowed commit, want 1", asked)
	}
	if got := owner.group.Stats().CommitRefusedOwn; got != 1 {
		t.Errorf("Stats.CommitRefusedOwn is %d, want 1", got)
	}
	if owner.handle.Epoch() != 1 {
		t.Errorf("the owner's handle moved to epoch %d over the hook's refusal", owner.handle.Epoch())
	}

	// the rules refuse first, and the hook is not asked
	asked = 0
	carol.group.device.commitAuthorizer = func(*CommitAuthorization) error {
		asked += 1
		return nil
	}
	if err := carol.group.SetRole(ctx, bob.dev.identityPub, "observer"); !errors.Is(err, ErrCommitPolicyChangeByNonAdmin) {
		t.Errorf("carol's demotion of bob answered %v, want R4's refusal", err)
	}
	if asked != 0 {
		t.Errorf("the hook was asked %d time(s) about a commit the rules refused", asked)
	}
}

// Members AND MyRole READ THE LIVE POLICY AT EVERY MEMBER: the founder owner, every other member
// unnamed and so "member" (ruling 8), each leaf's sender_handle the derived one, Mine set at
// exactly one leaf, in leaf order -- and after the owner's promotion is ingested, every member
// reads bob as admin and bob reads itself so.
func TestMembersAndMyRoleReadTheLivePolicy(t *testing.T) {
	world := newRoleWorld(t, "owner", "bob", "carol")
	owner, bob, carol := world.member("owner"), world.member("bob"), world.member("carol")
	all := []*roleMember{owner, bob, carol}

	for _, reader := range all {
		members, err := reader.group.Members()
		if err != nil {
			t.Fatalf("%s's Members: %v", reader.name, err)
		}
		if len(members) != 3 {
			t.Fatalf("%s reads %d members, want 3", reader.name, len(members))
		}
		mine := 0
		for at, member := range members {
			if at > 0 && members[at-1].LeafIndex >= member.LeafIndex {
				t.Errorf("%s's Members is not in leaf order: %v", reader.name, members)
			}
			handle := messagegroup.SenderHandle(world.groupHandleKey, member.LeafIndex)
			if !bytes.Equal(member.SenderHandle, handle[:]) {
				t.Errorf("%s reads leaf %d's sender_handle as %x, want %x", reader.name, member.LeafIndex, member.SenderHandle, handle)
			}
			want := mls.RoleMember.String()
			if bytes.Equal(member.IdentityPub, owner.dev.identityPub) {
				want = mls.RoleOwner.String()
			}
			if member.Role != want {
				t.Errorf("%s reads %x as %q, want %q", reader.name, member.IdentityPub, member.Role, want)
			}
			if member.Mine {
				mine += 1
				if !bytes.Equal(member.IdentityPub, reader.dev.identityPub) || member.LeafIndex != reader.leaf {
					t.Errorf("%s marks leaf %d (%x) as its own; its leaf is %d", reader.name, member.LeafIndex, member.IdentityPub, reader.leaf)
				}
			}
		}
		if mine != 1 {
			t.Errorf("%s marks %d leaves as its own, want 1", reader.name, mine)
		}
		role, err := reader.group.MyRole()
		if err != nil {
			t.Fatalf("%s's MyRole: %v", reader.name, err)
		}
		want := mls.RoleMember.String()
		if reader == owner {
			want = mls.RoleOwner.String()
		}
		if role != want {
			t.Errorf("%s's MyRole is %q, want %q", reader.name, role, want)
		}
	}

	promotion := world.policyOf(owner)
	promotion.SetRole(bob.dev.identityPub, mls.RoleAdmin)
	record := world.commitAndPublish(owner, "CommitPolicy promoting bob", func() ([]byte, []byte, []byte, error) {
		return owner.handle.CommitPolicy(world.policyBody(promotion))
	})
	for _, honest := range []*roleMember{bob, carol} {
		world.ingest(honest, owner, record)
	}
	for _, reader := range all {
		members, err := reader.group.Members()
		if err != nil {
			t.Fatalf("%s's Members after the promotion: %v", reader.name, err)
		}
		for _, member := range members {
			if bytes.Equal(member.IdentityPub, bob.dev.identityPub) && member.Role != mls.RoleAdmin.String() {
				t.Errorf("%s reads bob as %q after the promotion, want admin", reader.name, member.Role)
			}
		}
	}
	if role, _ := bob.group.MyRole(); role != mls.RoleAdmin.String() {
		t.Errorf("bob's MyRole after the promotion is %q, want admin", role)
	}
}

// ── ruling 13: the sdk never commits by reference in production ──────────────────────────────

// byReferenceCommitCalls is every call of a method named exactly Commit in a parsed file -- the
// seam's by-reference arm, `handle.Commit(byReference)` -- and, beside it, every call of a method
// whose name merely starts with Commit, so a reader sees what the narrowing kept out.
func byReferenceCommitCalls(fileSet *token.FileSet, file *ast.File) (byReference []string, byValue []string) {
	ast.Inspect(file, func(node ast.Node) bool {
		call, isCall := node.(*ast.CallExpr)
		if !isCall {
			return true
		}
		selector, isSelector := call.Fun.(*ast.SelectorExpr)
		if !isSelector || !strings.HasPrefix(selector.Sel.Name, "Commit") {
			return true
		}
		where := fileSet.Position(call.Pos()).String() + " " + selector.Sel.Name
		if selector.Sel.Name == "Commit" {
			byReference = append(byReference, where)
		} else {
			byValue = append(byValue, where)
		}
		return true
	})
	return byReference, byValue
}

// NO PRODUCTION SITE OF THIS PACKAGE COMMITS BY REFERENCE (ruling 13). Attribution to the
// committer (ruling 3) means a fold of cached proposals -- the seam's Commit(nil) -- would let
// another member's cached Add claiming the owner's identity ride this device's commit under its
// authority; the bypass lens showed it. So every commit this package builds is one of the seam's
// by-value arms (CommitAdd, CommitPolicy, CommitContextExtensions, CommitRemove), and this test
// reads every production file and refuses a call of a method named exactly Commit.
//
// THE POSITIVE CONTROL IS INLINE: the same walker over a source string that DOES call Commit(nil)
// must report it, or the search over the package could pass by reading nothing. And the complement
// is printed: every Commit-prefixed call the narrowing kept, so an empty by-reference list is
// read beside a non-empty by-value one rather than beside nothing.
func TestNoProductionSiteCommitsByReference(t *testing.T) {
	fileSet := token.NewFileSet()
	control, err := parser.ParseFile(fileSet, "control.go", `package p
type seam interface {
	Commit(byReference [][]byte) ([]byte, []byte, []byte, error)
	CommitAdd(keyPackages [][]byte) ([]byte, []byte, []byte, error)
}
func fold(handle seam) { handle.Commit(nil); handle.CommitAdd(nil) }
`, 0)
	if err != nil {
		t.Fatalf("parsing the control: %v", err)
	}
	controlByReference, controlByValue := byReferenceCommitCalls(fileSet, control)
	if len(controlByReference) != 1 || len(controlByValue) != 1 {
		t.Fatalf("the walker found %v by reference and %v by value in the control, want one of each", controlByReference, controlByValue)
	}

	sources := stateTestProductionSources(t)
	byReference, byValue := []string{}, []string{}
	for _, name := range sources {
		parsed, err := parser.ParseFile(fileSet, name, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		fileByReference, fileByValue := byReferenceCommitCalls(fileSet, parsed)
		byReference = append(byReference, fileByReference...)
		byValue = append(byValue, fileByValue...)
	}
	t.Logf("%d production file(s); the by-value commit calls the narrowing kept: %v", len(sources), byValue)
	if len(byValue) < 2 {
		t.Fatalf("the package holds %d Commit-prefixed call(s) -- the seam's by-value arms are called from AddMember, AddMemberAndPublish and the policy verbs, so fewer than two means the walk read the wrong tree", len(byValue))
	}
	if len(byReference) != 0 {
		t.Errorf("a production site commits by reference, which ruling 13 forbids: %v", byReference)
	}
}
