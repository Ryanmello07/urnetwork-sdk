// The role model's committing arm: MASTER §11's "refused by the committing client", ledger item
// 242's R2, 2026-09-21. R1 (roles.go, the receiving arm) is the other half.
//
// THE SAME PREDICATE, CALLED BEFORE THE COMMIT EXISTS. §11 rules that a bad commit "is refused by
// the committing client, and is rejected by every receiving client on validation", and a build in
// which the two arms could disagree would let this device build a commit its peers refuse -- which
// is the halt item 242's cost paragraph describes, caused by an honest client. So there is no second
// rule set here: every verb below builds the [CommitAuthorization] the commit WOULD produce
// ([Group.outgoingAuthorizationLocked]), hands it to [authorizeCommit], the one pure function the
// receivers judge by, and on a refusal answers [ErrCommitUnauthorized] wrapping the rule -- the
// receivers' own sentence -- having built, merged and published nothing. The refusal is counted in
// [Stats.CommitRefusedOwn].
//
// WHAT THE SEND SIDE KNOWS THAT THE RECEIVER READS OFF THE STAGED COMMIT, and how each is derived so
// the two decisions are the same value: the committer is this device's own leaf as the PRE-commit
// tree carries it (the seam's OwnLeafIndex, the identity MemberAt answers there, the role the live
// policy gives it); the post-commit extension list is mls.ExtensionsWithGroupPolicy over the live
// list, which is the one helper the seam's CommitPolicy itself uses, so the list judged is the list
// the commit will install; and the post-commit membership is the live membership minus the removes,
// plus one leaf per key package at the leftmost blank leaf (RFC 9420 §12.1.1, the placement mls
// makes), each carrying the identity its credential claims and whether its leaf node carries
// urmessage_leaf_keys, read by the same mls.LeafKeysOf both send doors refuse with. The test that
// holds the two arms to one value builds the commit after the decision, processes it at a receiver,
// and compares the receiver's decision field for field.
//
// THE VERBS. [Group.AddMemberAndPublish] (group.go) is gated on it for ruling 1; [Group.SetRole]
// and [Group.TransferOwnership] are new and are the two policy commits §11's table names, each
// one CommitPolicy through the seam, merged and published down the road the add already walks.
// There is no Remove verb: removal is its own track, gated on ledger items 243, 244 and 245.
//
// THE READ SURFACE. [Group.Members] and [Group.MyRole] are the roles as this device reads them,
// under the live policy with an unnamed identity a MEMBER (ruling 8): what a roster shows, and what
// this device is about to be judged as. The cgo and Windows legs of the surface are R3's.
//
// NOTHING HERE COMMITS BY REFERENCE (ruling 13): a fold of cached proposals would let another
// member's cached Add claiming the owner's identity ride this device's commit under its authority,
// so every commit this package builds is one of the seam's by-value arms, and a source test over the
// package's production files holds it to that.
package urmessage

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"slices"

	"github.com/urnetwork/connect/messagegroup"
	"github.com/urnetwork/connect/mls"
	"github.com/urnetwork/connect/mls/syntax"
)

// ── the read surface ─────────────────────────────────────────────────────────────────────────

// Member is one member of a group as a caller reads it: the leaf a role is read at, the
// sender_handle its records carry, the credential identity the policy keys the role by, that role,
// and whether the leaf is this device's own.
type Member struct {
	// LeafIndex is the member's leaf in the ratchet tree.
	LeafIndex uint32

	// SenderHandle is the 16 octets this member's records carry, derived from the group_handle_key
	// and the leaf. A copy.
	SenderHandle []byte

	// IdentityPub is the credential identity the leaf carries -- the member's Ed25519 identity
	// public key, which urmessage_group_policy keys a role by. A copy. One identity may hold
	// several leaves (its devices) and then appears once per leaf, with the same role on each.
	IdentityPub []byte

	// Role is the role the live policy gives IdentityPub, as the wire stable name: "owner",
	// "admin", "member" or "observer". An identity the policy does not name is "member" (MASTER
	// §11, ruling 8), and so is every member of a group whose context carries no readable policy.
	Role string

	// Mine is whether the leaf is this device's own.
	Mine bool
}

// Members is this group's membership at its current epoch, in leaf order, each with the role the
// live policy gives it. It is the roster a UI shows and it is exactly what this device would be
// judged by were it to commit now: the same membership door and the same policy reading the
// committing arm builds its decision from.
func (self *Group) Members() ([]Member, error) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if self.closed {
		return nil, fmt.Errorf("urmessage: this group is closed")
	}
	return self.membersLocked()
}

// MyRole is the role the live policy gives this device's own identity: what this device may
// commit. It is read at this device's own leaf -- the seam's OwnLeafIndex -- and not off the
// device's identity, so that what it answers is the role the tree's own credential at that leaf
// holds, which is the reading every receiver takes of a commit this device makes.
func (self *Group) MyRole() (string, error) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if self.closed {
		return "", fmt.Errorf("urmessage: this group is closed")
	}
	members, err := self.membersLocked()
	if err != nil {
		return "", err
	}
	for _, member := range members {
		if member.Mine {
			return member.Role, nil
		}
	}
	return "", fmt.Errorf("urmessage: this device's leaf %d is not among the group's %d members",
		self.handle.OwnLeafIndex(), len(members))
}

// membersLocked is [Group.Members] under the lock: the pre-commit membership the receiving arm
// reads, projected onto [Member] with the live policy's roles and this device's leaf marked.
func (self *Group) membersLocked() ([]Member, error) {
	live, err := self.liveContextLocked()
	if err != nil {
		return nil, err
	}
	members, err := self.membershipLocked(live.policy)
	if err != nil {
		return nil, err
	}
	own := self.handle.OwnLeafIndex()
	out := make([]Member, 0, len(members))
	for _, member := range members {
		out = append(out, Member{
			LeafIndex:    member.Leaf,
			SenderHandle: member.SenderHandle,
			IdentityPub:  member.IdentityPub,
			Role:         member.Role,
			Mine:         member.Leaf == own,
		})
	}
	return out, nil
}

// liveContext is the group context at this group's current epoch as the two arms read it: the
// full extension list, and the urmessage_group_policy decoded out of it -- nil, with the reason
// in policyErr, when the list carries none or one that does not parse or validate, which is
// exactly how the receiving arm reads the pre-commit side ([Group.commitAuthorizationLocked]): a
// nil policy names nobody, so every member is a MEMBER.
type liveContext struct {
	extensions []messagegroup.ExtensionBytes
	policy     *mls.GroupPolicyExtension
	policyErr  error
}

// liveContextLocked reads the [liveContext]. The one error it answers is the context's own
// failing to decode; a missing or invalid policy is a fact about the group, carried in the value.
func (self *Group) liveContextLocked() (*liveContext, error) {
	extensions, err := self.contextExtensionsLocked()
	if err != nil {
		return nil, err
	}
	policy, policyErr := mls.GroupPolicyOf(mlsExtensionsOf(extensions))
	return &liveContext{extensions: extensions, policy: policy, policyErr: policyErr}, nil
}

// ── the send-side decision ───────────────────────────────────────────────────────────────────

// outgoingCommit is what a commit this device is about to build WOULD do: the Adds it carries as
// the encoded key packages, the leaves it removes, and the policy body it installs -- nil for a
// commit that keeps the list the group has. It is the send side's spelling of the three vectors
// and the post-commit list [messagegroup.EngineProcessed] reports for an ingested commit. No verb
// writes removeLeaves until the removal track lands (ledger items 243, 244, 245); it is on the
// shape so that the decision built here is the receiver's whole decision and not two thirds of it.
type outgoingCommit struct {
	addKeyPackages [][]byte
	removeLeaves   []uint32
	policy         []byte
}

// authorizeOutgoingLocked is the committing-client decision on a commit this device is about to
// build: [authorizeCommit] over the value the commit would produce, then this device's configured
// [CommitAuthorizer] for the reason the receiving arm runs it -- a commit this device's own
// product would refuse on receipt is one it must not build. A refusal is counted in
// [Stats.CommitRefusedOwn] and answered as [ErrCommitUnauthorized] wrapping the rule, exactly as a
// receiver would answer the same commit, and the caller builds nothing.
func (self *Group) authorizeOutgoingLocked(intent *outgoingCommit) error {
	decision, err := self.outgoingAuthorizationLocked(intent)
	if err != nil {
		return err
	}
	if err := authorizeCommit(decision); err != nil {
		self.stats.CommitRefusedOwn += 1
		return fmt.Errorf("%w: %w", ErrCommitUnauthorized, err)
	}
	if authorizer := self.device.commitAuthorizer; authorizer != nil {
		if err := authorizer(decision); err != nil {
			self.stats.CommitRefusedOwn += 1
			return fmt.Errorf("%w: %w", ErrCommitUnauthorized, err)
		}
	}
	return nil
}

// outgoingAuthorizationLocked builds the [CommitAuthorization] a commit doing what intent says
// would produce at every receiver, from what this device holds BEFORE building it. Every field is
// derived the way the file header says, and every slice is this value's own.
func (self *Group) outgoingAuthorizationLocked(intent *outgoingCommit) (*CommitAuthorization, error) {
	live, err := self.liveContextLocked()
	if err != nil {
		return nil, err
	}
	extensionsBefore, policyBefore, policyBeforeErr := live.extensions, live.policy, live.policyErr
	members, err := self.membershipLocked(policyBefore)
	if err != nil {
		return nil, err
	}

	// the committer: this device's own leaf, as the pre-commit tree carries it
	ownLeaf := self.handle.OwnLeafIndex()
	var committer *CommitMember
	for at := range members {
		if members[at].Leaf == ownLeaf {
			committer = &members[at]
		}
	}
	if committer == nil {
		return nil, fmt.Errorf("urmessage: this device's leaf %d is not among the group's %d members", ownLeaf, len(members))
	}

	// the post-commit extension list: the seam's own replacement over the live list, so what is
	// judged is what CommitPolicy installs -- 0xF001 replaced in its position and every other
	// entry kept -- or the live list itself for a commit that carries no policy
	extensionsAfter := cloneExtensionBytes(extensionsBefore)
	if intent.policy != nil {
		replaced, err := mls.ExtensionsWithGroupPolicy(mlsExtensionsOf(extensionsBefore), intent.policy)
		if err != nil {
			return nil, fmt.Errorf("urmessage: the policy this commit would install: %w", err)
		}
		extensionsAfter = seamExtensionsOf(replaced)
	}
	policyAfter, policyAfterErr := mls.GroupPolicyOf(mlsExtensionsOf(extensionsAfter))

	// the post-commit membership: every kept leaf under the post-commit policy, then one leaf per
	// key package at the leftmost blank leaf, which is where mls places an Add after the removes
	// have blanked theirs (RFC 9420 §12.1.1; apply_proposals.go applies Adds last)
	removed := leafSetOf(intent.removeLeaves)
	occupied := map[uint32]bool{}
	after := make([]CommitMember, 0, len(members)+len(intent.addKeyPackages))
	for _, member := range members {
		if removed[member.Leaf] {
			continue
		}
		occupied[member.Leaf] = true
		after = append(after, self.commitMemberLocked(member.Leaf, member.IdentityPub, member.HasLeafKeys, policyAfter))
	}
	added := make([]uint32, 0, len(intent.addKeyPackages))
	next := uint32(0)
	for at, encoded := range intent.addKeyPackages {
		var keyPackage mls.KeyPackage
		if err := syntax.Unmarshal(encoded, &keyPackage); err != nil {
			return nil, fmt.Errorf("urmessage: key package %d of %d does not decode: %w", at, len(intent.addKeyPackages), err)
		}
		for occupied[next] {
			next += 1
		}
		occupied[next] = true
		_, keysErr := mls.LeafKeysOf(&keyPackage.LeafNode)
		after = append(after, self.commitMemberLocked(next, keyPackage.LeafNode.Credential.Identity, keysErr == nil, policyAfter))
		added = append(added, next)
	}
	slices.SortFunc(after, func(a CommitMember, b CommitMember) int {
		return cmp.Compare(a.Leaf, b.Leaf)
	})

	return &CommitAuthorization{
		GroupId:           append([]byte(nil), self.id...),
		Epoch:             self.epoch + 1,
		CommitterLeaf:     ownLeaf,
		CommitterIdentity: append([]byte(nil), committer.IdentityPub...),
		CommitterRole:     committer.Role,
		AddedLeaves:       added,
		RemovedLeaves:     append([]uint32(nil), intent.removeLeaves...),
		UpdatedLeaves:     []uint32{},
		Members:           members,
		MembersAfter:      after,
		PolicyBefore:      policyBefore,
		PolicyAfter:       policyAfter,
		PolicyBeforeErr:   policyBeforeErr,
		PolicyAfterErr:    policyAfterErr,
		ExtensionsBefore:  extensionsBefore,
		ExtensionsAfter:   extensionsAfter,
	}, nil
}

// seamExtensionsOf is an mls extension list as the seam spells it, every body cloned: the inverse
// of [mlsExtensionsOf], for the one place this package takes a list back from mls's own helper.
func seamExtensionsOf(extensions []mls.Extension) []messagegroup.ExtensionBytes {
	out := make([]messagegroup.ExtensionBytes, 0, len(extensions))
	for _, extension := range extensions {
		out = append(out, messagegroup.ExtensionBytes{
			Type: uint16(extension.ExtensionType),
			Data: append([]byte(nil), extension.ExtensionData...),
		})
	}
	return out
}

// ── the two policy verbs ─────────────────────────────────────────────────────────────────────

// SetRole makes one identity an "admin", a "member" or an "observer" in one commit, and publishes
// the epoch it opens: the live policy with that one entry set, canonicalized, committed by value
// through the seam's CommitPolicy so that 0x0003 required_capabilities and every other entry
// survive (item 242's P4), and published down the road [Group.AddMemberAndPublish] walks -- merged
// only once the server has taken it, so a lost epoch race answers [ErrCommitLost] and moves nothing.
//
// WHO MAY, is the predicate's to say and not this method's: §11's table gives the OWNER the admin
// set and an ADMIN "set MEMBER/OBSERVER", so any role to admin or admin to anything is the
// owner's (R4, [ErrCommitRoleChangeByNonOwner]) and member to observer and back is an admin's or
// the owner's (R4, [ErrCommitPolicyChangeByNonAdmin]); a MEMBER calling this at all is refused by
// R4, or by R7 for a change no role can see, and each refusal is [ErrCommitUnauthorized] wrapping
// the rule with nothing built. An identity that holds no leaf is refused as a phantom (R0c).
//
// "owner" IS NOT A ROLE THIS SETS: [ErrRoleNotSettable], and [Group.TransferOwnership] is the door.
func (self *Group) SetRole(ctx context.Context, identityPub []byte, role string) error {
	wanted, err := mls.ParseRole(role)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrRoleNotSettable, err)
	}
	if wanted == mls.RoleOwner {
		return fmt.Errorf("%w: %q", ErrRoleNotSettable, role)
	}
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if err := self.committableLocked(); err != nil {
		return err
	}
	policy, err := self.editablePolicyLocked()
	if err != nil {
		return err
	}
	policy.SetRole(identityPub, wanted)
	body, err := policyBodyOf(policy)
	if err != nil {
		return err
	}
	return self.commitPolicyAndPublishLocked(ctx, body)
}

// TransferOwnership makes one identity the OWNER and this device's identity -- the outgoing owner
// -- an ADMIN, in one commit (§11: "the outgoing owner becomes an ADMIN", ruling 4), and publishes
// the epoch it opens. The new owner must hold a leaf BEFORE the commit (ruling 10): "ownership
// transfers only to a current member", and R5 refuses a stranger. Only the owner may call this
// with effect -- R5's [ErrCommitOwnerTransfer] answers everybody else, with nothing built -- and
// naming the identity that already owns the group is [ErrAlreadyOwner].
func (self *Group) TransferOwnership(ctx context.Context, identityPub []byte) error {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if err := self.committableLocked(); err != nil {
		return err
	}
	policy, err := self.editablePolicyLocked()
	if err != nil {
		return err
	}
	ownerBefore, named := policy.OwnerId()
	if !named {
		// unreachable past editablePolicyLocked, whose decode validated exactly one owner
		return fmt.Errorf("urmessage: this group's policy names no owner: %w", mls.ErrNoOwner)
	}
	if bytes.Equal(ownerBefore, identityPub) {
		return ErrAlreadyOwner
	}
	policy.SetRole(identityPub, mls.RoleOwner)
	policy.SetRole(ownerBefore, mls.RoleAdmin)
	body, err := policyBodyOf(policy)
	if err != nil {
		return err
	}
	return self.commitPolicyAndPublishLocked(ctx, body)
}

// editablePolicyLocked is the live policy as a value the verbs may write into: freshly decoded off
// this group's own context, so nothing it shares is the epoch the group is running. A group whose
// context carries no valid policy has no policy to edit and is refused with the decode's reason:
// there is no owner for a change to be judged against, and a policy commit that installed one
// would be a transfer by an unnamed committer, which R5 refuses at every receiver anyway.
func (self *Group) editablePolicyLocked() (*mls.GroupPolicyExtension, error) {
	live, err := self.liveContextLocked()
	if err != nil {
		return nil, err
	}
	if live.policy == nil {
		return nil, fmt.Errorf("urmessage: this group's context carries no policy a role change could edit: %w", live.policyErr)
	}
	return live.policy, nil
}

// policyBodyOf is a policy canonicalized and encoded as the body CommitPolicy takes -- the octets
// under the 0xF001 tag -- through mls's own validating encoder, so a policy that would not
// validate is refused here with mls's reason rather than built.
func policyBodyOf(policy *mls.GroupPolicyExtension) ([]byte, error) {
	if err := policy.Canonicalize(); err != nil {
		return nil, fmt.Errorf("urmessage: the policy this commit would install: %w", err)
	}
	encoded, err := policy.Encode()
	if err != nil {
		return nil, fmt.Errorf("urmessage: the policy this commit would install: %w", err)
	}
	return encoded.ExtensionData, nil
}

// commitPolicyAndPublishLocked is the one road both policy verbs take: the send-side decision
// over the policy the commit would install, then the seam's by-value CommitPolicy, which STAGES
// the commit, and [Group.publishCommitLocked], which submits it and merges it only on the server's
// REASON_OK. The order is [Group.AddMemberAndPublish]'s: the decision before the connection is
// consulted, the rebind before anything is sealed, and the merge after the server has answered --
// so a policy commit that loses MASTER §9.3's race is answered [ErrCommitLost] with the group
// exactly where it was, the live policy still the one every receiver holds, and the verb ready to
// be asked again after [Group.Receive] has followed the winner.
func (self *Group) commitPolicyAndPublishLocked(ctx context.Context, policy []byte) error {
	if err := self.authorizeOutgoingLocked(&outgoingCommit{policy: policy}); err != nil {
		return err
	}
	if err := self.rebindLocked(); err != nil {
		return err
	}
	commit, _, _, err := self.handle.CommitPolicy(policy)
	if err != nil {
		return fmt.Errorf("urmessage: CommitPolicy: %w", err)
	}
	return self.publishCommitLocked(ctx, commit)
}
