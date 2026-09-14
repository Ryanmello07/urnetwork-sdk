package urmessage

import (
	"fmt"

	"github.com/urnetwork/connect/mls/syntax"
)

// InviteVersion is the version byte every [Invite] this build encodes carries. A blob written by a
// later build is refused by [ParseInvite] rather than read as this one.
const InviteVersion uint16 = 0x0001

// Invite is everything a second device needs in order to join a group, and it is a HAND-OFF rather
// than a message: this package has no channel to carry it and does not invent one, because the
// rendezvous and the contact card are out of scope for the alpha.
//
// IT IS SECRET IN FULL. Two of its four fields are key material -- pq_secret is the IKM of every
// storage root this group will ever extract, and the Welcome carries the MLS init secret -- so an
// invite that reaches a third party is a group that third party is in. Move it the way you would
// move a private key: over a channel that is already authenticated and already confidential, once,
// and destroy it afterwards.
//
// WHAT EACH FIELD IS AND WHOSE OPEN ITEM ITS DELIVERY IS. Every one is a value a PRODUCTION
// function of connect produced; what does not exist is a carrier.
//
//   - Welcome and RatchetTree: connect/mls's own, from GroupHandle.Commit. Ledger 44a's named,
//     gated hand-off.
//   - PqSecret: messagegroup.NewPqSecret. Its delivery is M1-20 and m1 task 14.
//   - GroupHandleKey: GroupHandleKey(StorageRoot(mls_secret[0], pq_secret)), computed at epoch zero
//     and never recomputed. Its carrier is M1-2. It is in here because a session opened at any
//     epoch after zero is REFUSED without it -- a value recomputed from a later root would give
//     every epoch a different sender_handle and end every member's stream at every commit.
//   - GroupId: the 32 octets the server keys its rows by.
type Invite struct {
	GroupId        []byte
	Welcome        []byte
	RatchetTree    []byte
	PqSecret       []byte
	GroupHandleKey []byte
}

// check refuses an invite that is missing a half nothing downstream could recover.
func (self *Invite) check() error {
	if len(self.GroupId) != GroupIdBytes {
		return fmt.Errorf("urmessage: an invite names a %d octet group id, want %d", len(self.GroupId), GroupIdBytes)
	}
	if len(self.Welcome) == 0 {
		return fmt.Errorf("urmessage: an invite carries no welcome, and there is nothing else to join from")
	}
	if len(self.RatchetTree) == 0 {
		return fmt.Errorf("urmessage: an invite carries no ratchet tree")
	}
	if len(self.PqSecret) == 0 {
		return fmt.Errorf("urmessage: an invite carries no pq_secret, which is the ikm of every storage root this group extracts")
	}
	if len(self.GroupHandleKey) == 0 {
		return fmt.Errorf("urmessage: an invite carries no group_handle_key, and a session at any epoch after zero is refused without it")
	}
	return nil
}

// Encode is the invite as octets a caller can move.
//
// The encoding is connect/mls/syntax's length prefixes, which is the one length prefix this corpus
// writes, so a field added to [Invite] later is a version bump here rather than a second framing.
func (self *Invite) Encode() ([]byte, error) {
	if err := self.check(); err != nil {
		return nil, err
	}
	writer := syntax.NewWriter()
	writer.WriteUint16(InviteVersion)
	writer.WriteOpaqueLP(self.GroupId)
	writer.WriteOpaqueLP(self.Welcome)
	writer.WriteOpaqueLP(self.RatchetTree)
	writer.WriteOpaqueLP(self.PqSecret)
	writer.WriteOpaqueLP(self.GroupHandleKey)
	encoded, err := writer.Bytes()
	if err != nil {
		return nil, fmt.Errorf("urmessage: encoding an invite: %w", err)
	}
	return encoded, nil
}

// ParseInvite reads back what [Invite.Encode] wrote.
func ParseInvite(encoded []byte) (*Invite, error) {
	reader := syntax.NewReader(encoded)
	version, err := reader.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("urmessage: an invite with no version: %w", err)
	}
	if version != InviteVersion {
		return nil, fmt.Errorf("urmessage: an invite at version %#04x, and this build writes %#04x",
			version, InviteVersion)
	}
	invite := &Invite{}
	for _, field := range []struct {
		name string
		into *[]byte
	}{
		{"group_id", &invite.GroupId},
		{"welcome", &invite.Welcome},
		{"ratchet_tree", &invite.RatchetTree},
		{"pq_secret", &invite.PqSecret},
		{"group_handle_key", &invite.GroupHandleKey},
	} {
		value, err := reader.ReadOpaqueLP()
		if err != nil {
			return nil, fmt.Errorf("urmessage: an invite with no %s: %w", field.name, err)
		}
		*field.into = value
	}
	if err := reader.Done(); err != nil {
		return nil, fmt.Errorf("urmessage: an invite with octets after its last field: %w", err)
	}
	if err := invite.check(); err != nil {
		return nil, err
	}
	return invite, nil
}
