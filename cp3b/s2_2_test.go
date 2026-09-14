package cp3b

import (
	"bytes"
	"context"
	"testing"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/sdk"
	"github.com/urnetwork/sdk/urmessage"
)

// S2-2, CLAUSE 1: A RECONNECT THIS BINDING PERFORMED COSTS NOTHING BUT A REBIND.
//
// A second [urmessage.Device.Connect] is a reconnect: 4.3.1 issues a new server_nonce and destroys
// the one before it, so every session that was MAC'ing write_auth under the old one is now sealing
// records the server will refuse. The seam compares the Hello count it was last bound at against
// the one the transport now holds and calls RebindServerNonce before it seals.
//
// THE ASSERTION THAT DISTINGUISHES A REPAIR FROM A LUCKY SEND IS Rebound == 0. That counter moves
// only on the refusal-driven recovery path, so zero means the FIRST submit after the reconnect was
// accepted -- which it can only have been if the session was already sealing under the new nonce.
// Delete the rebind and this case does not merely fail: it fails with Rebound == 1, which is the
// other clause doing the repair a round trip later.
func TestAMessageSentAfterAReconnectThisBindingPerformedIsReboundBeforeItIsSealed(t *testing.T) {
	world := newWorld(t)
	ctx := context.Background()
	pair := twoDevicesInOneGroup(t, world, ctx)

	epochBefore := pair.aliceTransport.NonceEpoch()
	held := append([]byte(nil), pair.aliceTransport.Nonce()...)

	// THE RECONNECT, through this binding, which is the half NonceEpoch can see.
	if err := pair.alice.Connect(ctx); err != nil {
		t.Fatalf("alice's second Connect: %v", err)
	}
	if now := pair.aliceTransport.NonceEpoch(); now != epochBefore+1 {
		t.Fatalf("the second Connect left the Hello count at %d, want %d, so no reconnect was observed",
			now, epochBefore+1)
	}
	if bytes.Equal(pair.aliceTransport.Nonce(), held) {
		t.Fatal("the second connection was issued the nonce the first held, so there is nothing to rebind onto")
	}

	const text = "a line sent after a reconnect this binding performed"
	sent, err := pair.aliceGroup.Send(ctx, text)
	if err != nil {
		t.Fatalf("alice's Send after a reconnect: %v", err)
	}
	if rebound := pair.aliceGroup.Stats().Rebound; rebound != 0 {
		t.Fatalf("the send after a reconnect took %d refusal-driven recoveries; the rebind was supposed to happen before the seal",
			rebound)
	}

	received, err := pair.bobGroup.Receive(ctx)
	if err != nil {
		t.Fatalf("bob's Receive: %v", err)
	}
	if len(received) != 1 || received[0].Text != text {
		t.Fatalf("bob received %d messages and the first is %q, want one %q",
			len(received), textOf(received), text)
	}
	if received[0].RecordId != sent.RecordId {
		t.Fatalf("bob opened record %d and alice was told %d", received[0].RecordId, sent.RecordId)
	}
}

// S2-2, CLAUSE 2: A CONNECTION REPLACED UNDERNEATH THIS BINDING, WHICH IS FINDING E REPRODUCED.
//
// NonceEpoch counts HELLOS, NOT CONNECTIONS. peer.Connections keys a connection by connect.Id, so a
// SECOND transport over the SAME connect client is the same connection to the server: its Hello
// mints a new nonce and destroys the one the first transport holds, and the first transport's Hello
// count does not move. That is the state a reconnected connect.Client would leave the seam in, and
// it is reachable here with no test-only seam into the binding at all -- the shadow transport is
// the shipped one, built through the shipped door.
//
// The case asserts the reproduction BEFORE it asserts the repair: the nonce alice holds is not the
// nonce the server now has, and her Hello count is unchanged. Without those two clauses, "the
// message arrived" would be equally consistent with nothing having gone wrong.
//
// THEN THE REPAIR: one refusal buys one Hello, one rebind, one ReauthRecord and one resubmission,
// and the message arrives. Rebound == 1 is what says the recovery path ran rather than the send
// having been fine all along.
func TestAMessageSentOnAConnectionNothingToldThisBindingWasReplacedStillArrives(t *testing.T) {
	world := newWorld(t)
	ctx := context.Background()
	pair := twoDevicesInOneGroup(t, world, ctx)

	held := append([]byte(nil), pair.aliceTransport.Nonce()...)
	epochBefore := pair.aliceTransport.NonceEpoch()
	if len(held) == 0 {
		t.Fatal("alice holds no server_nonce, so there is nothing for a replacement to supersede")
	}

	// THE REPLACEMENT, through a second binding on the same connect client.
	shadow, err := sdk.NewMessageTransport(&sdk.MessageTransportConfig{
		Client:          pair.aliceClient,
		Server:          world.serverClient.ClientId(),
		ProtocolVersion: worldProtocolVersion,
	})
	if err != nil {
		t.Fatalf("the shadow transport: %v", err)
	}
	defer shadow.Close()
	reason, hello, err := shadow.Hello(ctx)
	if err != nil {
		t.Fatalf("the shadow Hello: %v", err)
	}
	if reason != protocol.Reason_REASON_OK {
		t.Fatalf("the shadow Hello was answered %v", reason)
	}

	// ── the reproduction, asserted before the repair ─────────────────────────────────────
	if bytes.Equal(hello.GetServerNonce(), held) {
		t.Fatal("the second connection of one client_id was issued the nonce the first holds, so nothing was superseded and this case observes nothing")
	}
	if !bytes.Equal(pair.aliceTransport.Nonce(), held) {
		t.Fatal("alice's transport noticed the replacement by itself, so Finding E is not what this case is reproducing")
	}
	if now := pair.aliceTransport.NonceEpoch(); now != epochBefore {
		t.Fatalf("alice's Hello count moved from %d to %d without alice saying Hello, so the seam CAN see this replacement",
			epochBefore, now)
	}
	t.Logf("Finding E reproduced: alice holds %x..., the server now holds %x..., and alice's Hello count is still %d",
		held[:8], hello.GetServerNonce()[:8], epochBefore)

	// ── the repair ───────────────────────────────────────────────────────────────────────
	const text = "a line sent on a connection nothing told this binding was replaced"
	sent, err := pair.aliceGroup.Send(ctx, text)
	if err != nil {
		t.Fatalf("alice's Send over a superseded nonce: %v", err)
	}
	if rebound := pair.aliceGroup.Stats().Rebound; rebound != 1 {
		t.Fatalf("the send took %d refusal-driven recoveries, want exactly 1; without one the first submit was never refused and this case proves nothing",
			rebound)
	}
	if now := pair.aliceTransport.NonceEpoch(); now != epochBefore+1 {
		t.Fatalf("the recovery left alice's Hello count at %d, want %d", now, epochBefore+1)
	}

	received, err := pair.bobGroup.Receive(ctx)
	if err != nil {
		t.Fatalf("bob's Receive: %v", err)
	}
	if len(received) != 1 || received[0].Text != text {
		t.Fatalf("bob received %d messages and the first is %q, want one %q",
			len(received), textOf(received), text)
	}
	if received[0].RecordId != sent.RecordId {
		t.Fatalf("bob opened record %d and alice was told %d", received[0].RecordId, sent.RecordId)
	}
}

// ── the fixture these two share ──────────────────────────────────────────────────────────────

// twoDevices is one published group and both sides of it, with alice's connection kept beside her
// device because [urmessage.Group] deliberately publishes no handle onto either: a group is a
// group, and a caller that wanted the connection would be holding the connection.
type twoDevices struct {
	alice          *urmessage.Device
	aliceClient    *connect.Client
	aliceTransport *sdk.MessageTransport
	aliceGroup     *urmessage.Group

	bob      *urmessage.Device
	bobGroup *urmessage.Group
}

// twoDevicesInOneGroup is the main case's setup up to the point where a message can be sent: two
// devices, one real MLS group, published on the server and writable, and bob already past 6.1's
// ceremony so that the records a case is about are the only ones left for it to find.
func twoDevicesInOneGroup(t *testing.T, world *world, ctx context.Context) *twoDevices {
	t.Helper()
	alice, aliceClient, aliceTransport := world.device(t, "alice")
	bob, _, _ := world.device(t, "bob")

	if err := alice.Connect(ctx); err != nil {
		t.Fatalf("alice's Connect: %v", err)
	}
	if err := bob.Connect(ctx); err != nil {
		t.Fatalf("bob's Connect: %v", err)
	}
	aliceGroup, err := alice.CreateGroup(ctx, newGroupId(t))
	if err != nil {
		t.Fatalf("alice's CreateGroup: %v", err)
	}
	keyPackage, err := bob.KeyPackage()
	if err != nil {
		t.Fatalf("bob's KeyPackage: %v", err)
	}
	invite, err := aliceGroup.AddMember(keyPackage)
	if err != nil {
		t.Fatalf("alice's AddMember: %v", err)
	}
	if err := aliceGroup.Open(ctx); err != nil {
		t.Fatalf("alice's Open: %v", err)
	}
	bobGroup, err := bob.Join(ctx, invite)
	if err != nil {
		t.Fatalf("bob's Join: %v", err)
	}
	if _, err := bobGroup.Receive(ctx); err != nil {
		t.Fatalf("bob's catch-up Receive: %v", err)
	}
	return &twoDevices{
		alice:          alice,
		aliceClient:    aliceClient,
		aliceTransport: aliceTransport,
		aliceGroup:     aliceGroup,
		bob:            bob,
		bobGroup:       bobGroup,
	}
}

func textOf(messages []*urmessage.Message) string {
	if len(messages) == 0 {
		return ""
	}
	return messages[0].Text
}
