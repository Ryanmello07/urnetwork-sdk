// Three real URnetwork accounts, three real platform connections, one DEPLOYED message server, and
// the whole of what the alpha can do, scenario by scenario -- including the membership change that
// makes a group chat a group chat.
//
// Everything before this ran two connect.Clients over in-process Routes in one binary. This
// crosses the operator's mesh to a server it did not start.
//
// EVERY STEP PRINTS WHAT IT ASSERTED. A probe that prints "OK" without naming what it checked is
// useless at 2am, so each check() below carries the sentence a reader needs in order to know what
// went wrong, and fail() names the step, the expectation and what actually came back.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/sdk"
	"github.com/urnetwork/sdk/urmessage"
)

type party struct {
	name string
	dir  string

	client      *sdk.MessageClient
	transport   *sdk.MessageTransport
	streamStore *sdk.StreamStore
	stateStore  *urmessage.DurableStateStore
	device      *urmessage.Device
}

// dialer is everything dial() needs that does not change across a restart. It is a struct so that
// a restart is "the same dialer, the same directory, everything else new" rather than eight
// arguments threaded through by hand.
type dialer struct {
	ctx     context.Context
	server  connect.Id
	host    string
	root    string
	timeout time.Duration

	// connect is handed to every device this dialer stands up, so that a re-dial rides out the
	// operator's reconnect window instead of reporting it as a failure.
	connect urmessage.ConnectPolicy
}

var (
	steps   int
	checks  int
	current string
)

func main() {
	aJwt := flag.String("a", "", "file holding party A's by_client_jwt")
	bJwt := flag.String("b", "", "file holding party B's by_client_jwt")
	cJwt := flag.String("c", "", "file holding party C's by_client_jwt; C is the third member step 5 adds, so it is required")
	serverId := flag.String("server", "", "the message server's client_id")
	host := flag.String("host", "beta-test.net", "operator host")
	dir := flag.String("dir", "/var/lib/urmessage/probe", "where each party's durable state lives")
	text := flag.String("text", "the first message over the real mesh", "what A sends first")
	lines := flag.Int("lines", 600, "how many messages step 4 sends; must exceed the server's max_records_per_fetch to reach the truncation path")
	bigBytes := flag.Int("big", 40000, "how many octets step 6's message carries; anything over 2048 crosses the fragmentation cut")
	timeout := flag.Duration("timeout", 60*time.Second, "per-request transport timeout")
	reconnect := flag.Duration("reconnect", 0,
		"how long Device.Connect rides out the ~60s reconnect window; 0 takes urmessage's own default")
	flag.Parse()

	server, err := connect.ParseId(*serverId)
	if err != nil {
		fail("parse server id: %v", err)
	}
	// REFUSED HERE AND NOT IN STEP 5, because step 5 is four minutes and six hundred records in,
	// and a probe that spends them before saying it needed a third credential has wasted them.
	if *cJwt == "" {
		fail("-c is required: step 5 adds a THIRD real device to the group, and a third device is a third credential")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lineCount := *lines
	// THE RECONNECT WINDOW IS THE OPERATOR'S AND THIS PROBE HAS TO SURVIVE IT RATHER THAN TRIP
	// OVER IT. Measured on the deployed server: a client_id that has just re-dialled is NOT
	// ROUTED TO for about sixty seconds -- the connection attaches, the Hello goes out and
	// nothing comes back. Step 7 re-dials B for the same client_id, so step 7 lands in that
	// window every time, and before urmessage.Device.Connect retried, step 7 reported a hard
	// failure for something that was simply not ready. Filed against the operator as item 5 of
	// docs/reports/2026-09-15-operator-and-connect-findings.md; NOT closed by this, and the
	// user still waits the sixty seconds.
	mesh := &dialer{ctx: ctx, server: server, host: *host, root: *dir, timeout: *timeout,
		connect: urmessage.ConnectPolicy{Budget: *reconnect, OnAttempt: printConnectAttempt}}

	a := mesh.dial("A", *aJwt)
	b := mesh.dial("B", *bJwt)
	defer a.close()
	defer b.close()

	// ── 1 ────────────────────────────────────────────────────────────────────────────────
	step("Hello on both parties, and the capabilities the server advertises")
	for _, p := range []*party{a, b} {
		hctx, hcancel := context.WithTimeout(ctx, *timeout)
		reason, hello, err := p.transport.Hello(hctx, 1)
		hcancel()
		if err != nil {
			fail("%s hello: %v", p.name, err)
		}
		check(reason == protocol.Reason_REASON_OK, "%s: Hello answered %v, want REASON_OK", p.name, reason)
		check(len(hello.GetServerNonce()) != 0,
			"%s: Hello issued no server_nonce, and every authenticator this client computes is a MAC over one", p.name)
		capabilities := hello.GetCapabilities()
		fmt.Printf("  %s  nonce %d octets; max_records_per_fetch=%d max_request_bytes=%d attestation_supported=%v\n",
			p.name, len(hello.GetServerNonce()), capabilities.GetMaxRecordsPerFetch(),
			capabilities.GetMaxRequestBytes(), capabilities.GetAttestationSupported())
		if !capabilities.GetAttestationSupported() {
			fmt.Printf("  %s  NOTE: this server advertises NO 4.3.4 attestation, so a server that OMITS\n"+
				"        records from a fetch page is undetectable by this client. S2-27, and it is\n"+
				"        counted per page in Stats.Unattested rather than assumed away.\n", p.name)
		}
		if err := p.device.Connect(ctx); err != nil {
			fail("%s Connect: %v", p.name, err)
		}
	}

	// ── 2 ────────────────────────────────────────────────────────────────────────────────
	step("A founds a group, adds B, and publishes it on the server")
	groupId := make([]byte, urmessage.GroupIdBytes)
	if _, err := rand.Read(groupId); err != nil {
		fail("group id: %v", err)
	}
	aGroup, err := a.device.CreateGroup(ctx, groupId)
	if err != nil {
		fail("A CreateGroup: %v", err)
	}
	check(aGroup.Epoch() == 0, "a freshly founded group is at epoch %d, want 0", aGroup.Epoch())
	keyPackage, err := b.device.KeyPackage()
	if err != nil {
		fail("B KeyPackage: %v", err)
	}
	invite, err := aGroup.AddMember(keyPackage)
	if err != nil {
		fail("A AddMember: %v", err)
	}
	check(aGroup.Epoch() == 1, "the commit that added B left the group at epoch %d, want 1", aGroup.Epoch())
	encoded, err := invite.Encode()
	if err != nil {
		fail("encode invite: %v", err)
	}
	if err := aGroup.Open(ctx); err != nil {
		fail("A Open: %v", err)
	}
	check(aGroup.IsOpen(), "Open returned no error and the group does not say it is open")
	fmt.Printf("  group %x epoch %d; invite %d octets, carried out of band as the design says\n",
		aGroup.Id()[:8], aGroup.Epoch(), len(encoded))

	// ── 3 ────────────────────────────────────────────────────────────────────────────────
	step("B joins from the invite and reads the string A typed")
	carried, err := urmessage.ParseInvite(encoded)
	if err != nil {
		fail("parse invite: %v", err)
	}
	sent, err := aGroup.Send(ctx, *text)
	if err != nil {
		fail("A Send: %v", err)
	}
	bGroup, err := b.device.Join(ctx, carried)
	if err != nil {
		fail("B Join: %v", err)
	}
	got := receive(bGroup, ctx, "B")
	check(len(got) == 1, "B read %d messages for the one A sent: %s", len(got), texts(got))
	check(got[0].Text == *text, "B read %q and A typed %q", got[0].Text, *text)
	check(got[0].RecordId == sent.RecordId, "B opened record %d and A was told hers is record %d",
		got[0].RecordId, sent.RecordId)
	check(!got[0].Mine, "a message B received from A came back marked as B's own")
	reply := "and the answer came back"
	if _, err := bGroup.Send(ctx, reply); err != nil {
		fail("B Send: %v", err)
	}
	back := receive(aGroup, ctx, "A")
	check(len(back) == 1 && back[0].Text == reply, "A read %s for B's one answer", texts(back))
	fmt.Printf("  the string crossed both ways; B's sender_handle %x\n", back[0].SenderHandle)

	// ── 4 ────────────────────────────────────────────────────────────────────────────────
	step(fmt.Sprintf("%d messages in order, which is what crosses a fetch page", lineCount))
	fmt.Printf("  WHAT THIS IS FOR: 4.3.4 truncates a page by `limit` OR by `max_response_bytes` and\n" +
		"  calls both NORMAL. Receive must page until the server says complete. A build that read\n" +
		"  one page returns the first screenful of a conversation with a NIL ERROR, which a user\n" +
		"  cannot tell from a quiet room.\n")
	typed := make([]string, 0, lineCount)
	for at := 0; at < lineCount; at += 1 {
		line := fmt.Sprintf("line %d of %d over the real mesh", at+1, lineCount)
		if _, err := aGroup.Send(ctx, line); err != nil {
			fail("A Send line %d: %v", at+1, err)
		}
		typed = append(typed, line)
	}
	pagesBefore := bGroup.Stats().Pages
	bulk := receive(bGroup, ctx, "B")
	pages := bGroup.Stats().Pages - pagesBefore
	check(len(bulk) == len(typed), "A sent %d lines and ONE Receive answered %d", len(typed), len(bulk))
	for at := range typed {
		check(bulk[at].Text == typed[at], "message %d came back as %q and was typed as %q",
			at, bulk[at].Text, typed[at])
		if 0 < at {
			check(bulk[at-1].RecordId < bulk[at].RecordId,
				"message %d is record %d and message %d is record %d, so the order is not the server's",
				at, bulk[at].RecordId, at-1, bulk[at-1].RecordId)
		}
	}
	fmt.Printf("  %d lines came back in record order, in ONE Receive, over %d fetch page(s)\n", len(bulk), pages)
	if pages < 2 {
		fmt.Printf("  WARNING: one page carried all of it, so the truncation path was NOT exercised.\n" +
			"  Raise -lines above this server's max_records_per_fetch (printed in step 1) and run again.\n")
	}

	// ── 5 ────────────────────────────────────────────────────────────────────────────────
	step("a THIRD member is added to a group that has been chatting: a second epoch, on the real mesh")
	fmt.Printf("  WHAT THIS IS FOR: this is where group chats start to exist. Everything above ran at\n" +
		"  epoch 1, the one epoch the founding add opened. A adds C to the OPEN group, which is a\n" +
		"  commit sealed at epoch 1 announcing epoch 2, a wrap fan-out for the new epoch and a marker\n" +
		"  -- all submitted to the deployed server. C joins from a Welcome. B, who authored nothing,\n" +
		"  learns of it only by fetching the commit and INGESTING it, and must follow into epoch 2.\n" +
		"  Then one line from each device opens on both others, which is the assertion that says the\n" +
		"  three share one epoch-2 key schedule rather than merely agreeing on the number 2. The\n" +
		"  founding-time AddMember still refuses a second add by name; this is the other door.\n")
	// THE EPOCH-ONE LINES ARE COUNTED HERE, once, because two later assertions are about what became
	// of them: A's first text, B's answer, and step 4's lines. Nothing else at epoch 1 is a line.
	epochOneLines := 2 + lineCount
	c := mesh.dial("C", *cJwt)
	defer c.close()
	if err := c.device.Connect(ctx); err != nil {
		fail("C Connect: %v", err)
	}
	thirdKeyPackage, err := c.device.KeyPackage()
	if err != nil {
		fail("C KeyPackage: %v", err)
	}
	epochBefore := aGroup.Epoch()
	thirdInvite, err := aGroup.AddMemberAndPublish(ctx, thirdKeyPackage)
	if err != nil {
		fail("A AddMemberAndPublish: %v", err)
	}
	check(aGroup.Epoch() == epochBefore+1, "the commit that added C left A at epoch %d, want %d", aGroup.Epoch(), epochBefore+1)
	check(aGroup.Epoch() == 2, "A is at epoch %d after the second add, want 2", aGroup.Epoch())
	thirdEncoded, err := thirdInvite.Encode()
	if err != nil {
		fail("encode C's invite: %v", err)
	}
	thirdCarried, err := urmessage.ParseInvite(thirdEncoded)
	if err != nil {
		fail("parse C's invite: %v", err)
	}
	cGroup, err := c.device.Join(ctx, thirdCarried)
	if err != nil {
		fail("C Join: %v", err)
	}
	check(cGroup.Epoch() == 2, "C joined at epoch %d, want 2", cGroup.Epoch())
	check(string(cGroup.Id()) == string(groupId), "C joined group %x and A founded %x", cGroup.Id()[:8], groupId[:8])
	fmt.Printf("  A's commit opened epoch %d on the server; C joined from a %d octet invite at epoch %d\n",
		aGroup.Epoch(), len(thirdEncoded), cGroup.Epoch())

	// B INGESTS THE COMMIT. This is the one arm neither the committer (who merges its own commit)
	// nor the joiner (who is handed a Welcome) exercises, and it is asserted on B's own counters:
	// Ingested moves once, the epoch follows, and NOTHING of B's history goes out of reach, because
	// B was current when the epoch moved. A commit is not a line, so the Receive hands back none.
	ingestedBefore := bGroup.Stats().Ingested
	atIngest := receive(bGroup, ctx, "B")
	check(bGroup.Epoch() == 2, "B did not follow A's commit into epoch 2: B is at epoch %d", bGroup.Epoch())
	check(bGroup.Stats().Ingested == ingestedBefore+1, "B's Stats.Ingested is %d after following one commit, want %d",
		bGroup.Stats().Ingested, ingestedBefore+1)
	check(bGroup.Stats().Ingested == 1, "B has ingested %d commit(s) in its life and there has been exactly one", bGroup.Stats().Ingested)
	check(len(atIngest) == 0, "B's ingesting Receive handed back %d entries and a commit is not a line: %s", len(atIngest), texts(atIngest))
	check(bGroup.Stats().GapOutOfWindow == 0,
		"B was current when the epoch moved and still has %d out_of_window gap(s); an up-to-date member must lose nothing to a commit",
		bGroup.Stats().GapOutOfWindow)
	fmt.Printf("  B ingested the commit on its next Receive and followed into epoch %d (Stats.Ingested=%d), with 0 gaps\n",
		bGroup.Epoch(), bGroup.Stats().Ingested)

	// C DRAINS THE PRE-JOIN HISTORY. C holds no epoch-1 key schedule, so every epoch-1 line is a
	// record it cannot open -- an out_of_window GAP, one per line, and NOT a failure. Counted
	// exactly rather than tolerated: it is the number item 241's history-for-new-members owes.
	drained := receive(cGroup, ctx, "C")
	cGaps, cOpened, cOtherGaps := gapCount(drained)
	check(cOpened == 0, "C opened %d line(s) from before it was a member; it holds no key that could", cOpened)
	check(cOtherGaps == 0, "C's drain produced %d gap(s) of a reason other than out_of_window", cOtherGaps)
	check(cGaps == epochOneLines, "C's drain produced %d out_of_window gap(s) and the group exchanged %d line(s) at epoch 1",
		cGaps, epochOneLines)
	check(cGroup.Stats().GapOutOfWindow == uint64(cGaps), "C's Stats.GapOutOfWindow is %d and the drain handed back %d gaps",
		cGroup.Stats().GapOutOfWindow, cGaps)
	fmt.Printf("  C drained %d pre-join record(s) as out_of_window gaps, opened 0, failed 0 -- the history it was not there for\n", cGaps)

	// ALL THREE AT EPOCH TWO.
	check(aGroup.Epoch() == 2 && bGroup.Epoch() == 2 && cGroup.Epoch() == 2,
		"epochs did not converge: A %d, B %d, C %d", aGroup.Epoch(), bGroup.Epoch(), cGroup.Epoch())

	// SIX DIRECTIONS. One line from each device, opened on both others, every one asserted on the
	// FAR side against the exact text and against being a line rather than a gap.
	const (
		aAtTwo = "epoch two: A, to a group that now has three members"
		bAtTwo = "epoch two: B, who followed a commit it did not author"
		cAtTwo = "epoch two: C, the third member, sealing under its own new leaf"
	)
	if _, err := aGroup.Send(ctx, aAtTwo); err != nil {
		fail("A Send at epoch 2: %v", err)
	}
	opens(bGroup, ctx, "B", "A", aAtTwo)
	opens(cGroup, ctx, "C", "A", aAtTwo)
	if _, err := bGroup.Send(ctx, bAtTwo); err != nil {
		fail("B Send at epoch 2: %v", err)
	}
	opens(aGroup, ctx, "A", "B", bAtTwo)
	opens(cGroup, ctx, "C", "B", bAtTwo)
	if _, err := cGroup.Send(ctx, cAtTwo); err != nil {
		fail("C Send at epoch 2: %v", err)
	}
	opens(aGroup, ctx, "A", "C", cAtTwo)
	opens(bGroup, ctx, "B", "C", cAtTwo)
	for _, member := range []struct {
		name  string
		group *urmessage.Group
	}{{"A", aGroup}, {"B", bGroup}, {"C", cGroup}} {
		check(member.group.Stats().FailedOpen == 0, "%s failed to open %d record(s) across the epoch change",
			member.name, member.group.Stats().FailedOpen)
	}
	fmt.Printf("  six directions at epoch 2: A->B A->C B->A B->C C->A C->B, each opened on the far side with the exact text\n")

	// ── 6 ────────────────────────────────────────────────────────────────────────────────
	step(fmt.Sprintf("a %d octet message, which no live test has ever fragmented", *bigBytes))
	fmt.Printf("  WHAT THIS IS FOR: 4.6 cuts a request into 2048 octet parts, so this one crosses as\n"+
		"  roughly %d frames and is reassembled on the far side. Everything before it fitted one\n"+
		"  frame. If the text comes back with a single octet changed, the reassembler is joining\n"+
		"  parts in the wrong order and no AEAD downstream would ever have told you which.\n",
		(*bigBytes/2048)+1)
	big := strings.Repeat("0123456789abcdef", (*bigBytes/16)+1)[:*bigBytes]
	bigSent, err := aGroup.Send(ctx, big)
	if err != nil {
		fail("A Send of %d octets: %v -- if this is ErrTextTooLong the text is above the largest inline size bucket and -big must come down",
			*bigBytes, err)
	}
	bigGot := receive(bGroup, ctx, "B")
	check(len(bigGot) == 1, "B read %d messages for the one large one A sent", len(bigGot))
	check(bigGot[0].Text == big, "the %d octet text came back changed: %d octets, first difference at %d",
		len(big), len(bigGot[0].Text), firstDifference(big, bigGot[0].Text))
	fmt.Printf("  %d octets crossed and came back identical, record %d\n", len(big), bigSent.RecordId)

	// ── 7 ────────────────────────────────────────────────────────────────────────────────
	step("B's client is KILLED mid-conversation and started again over the same directory")
	fmt.Printf("  WHAT THIS IS FOR: this is S2-14. Everything B holds in memory is dropped -- the\n" +
		"  device, both durable stores, the transport and the connect client -- and a NEW everything\n" +
		"  is opened over the same directory. The only thing that crosses is the disk. If the MLS\n" +
		"  state did not survive, B is not in the group at all and the record below is undecryptable\n" +
		"  rather than merely unlisted.\n")
	const beforeTheRestart = "typed by A while B's app was about to be killed"
	if _, err := aGroup.Send(ctx, beforeTheRestart); err != nil {
		fail("A Send before B's restart: %v", err)
	}
	// AND TWO LINES OF B'S OWN, which is the half this step used to be blind to. It asserted
	// only that B could read what A sealed -- and `Receive` skipped every record whose
	// sender_handle was its own while a restored group's log started empty, so a user who
	// closed the app and reopened it got the other side's half of the conversation and none of
	// their own, with a nil error. A probe that checks only the far side's half cannot see that.
	bsOwn := []string{
		"typed by B ITSELF before the kill -- if this does not come back the user has lost their own half",
		"and a second line of B's own, before the kill",
	}
	for _, text := range bsOwn {
		if _, err := bGroup.Send(ctx, text); err != nil {
			fail("B Send before its own restart: %v", err)
		}
	}
	if _, err := aGroup.Receive(ctx); err != nil {
		fail("A Receive before B's restart: %v", err)
	}
	bHandle := append([]byte(nil), back[0].SenderHandle...)
	bEpoch := bGroup.Epoch()
	b = mesh.restart(b)
	defer b.close()
	// THIS IS THE CALL THAT MEETS THE RECONNECT WINDOW, every run: B has just re-dialled under
	// the same client_id. It retries with backoff across the window and prints each attempt, so
	// an operator watching this sees "reconnecting" rather than a probe that looks hung and then
	// fails. If it comes back ErrReconnecting the WINDOW outlasted the budget, which is a
	// different finding from a broken restore and is named as one.
	restartConnect := time.Now()
	if err := b.device.Connect(ctx); err != nil {
		if errors.Is(err, urmessage.ErrReconnecting) {
			fail("the restarted B was still not routed to after %v of retrying: %v\n"+
				"  THIS IS THE OPERATOR WINDOW AND NOT A RESTORE FAILURE (operator item 5).\n"+
				"  Raise -reconnect above the window and run again; the restore itself is untested\n"+
				"  until this call returns.", time.Since(restartConnect).Round(time.Second), err)
		}
		fail("the restarted B Connect: %v", err)
	}
	fmt.Printf("  the restarted B was routed to after %v\n", time.Since(restartConnect).Round(time.Millisecond))
	restored, err := b.device.Restore(ctx)
	if err != nil {
		fail("the restarted B Restore: %v", err)
	}
	check(len(restored) == 1, "B was in one group and %d came back from the disk", len(restored))
	bGroup = restored[0]
	check(string(bGroup.Id()) == string(groupId), "B came back into group %x and was in %x", bGroup.Id(), groupId)
	check(bGroup.Epoch() == bEpoch, "B was at epoch %d and came back at %d", bEpoch, bGroup.Epoch())
	check(bGroup.IsOpen(), "the restored group does not know it is open on the server, so it will refuse to send")
	// the cursor is not persisted, so this re-reads the whole history and re-derives every key
	afterRestart := receive(bGroup, ctx, "the restarted B")
	found := false
	for _, one := range afterRestart {
		if one.Text == beforeTheRestart {
			found = true
		}
	}
	check(found, "the restarted B read %d messages and none is the one A sealed before the restart", len(afterRestart))
	// B'S OWN HALF. The Mine bit is held separately from the text, because a device that came
	// back at a different leaf would open its own records as somebody else's and a check on the
	// text alone would pass over it.
	held := bGroup.Messages()
	for _, text := range bsOwn {
		mine := false
		for _, one := range held {
			if one.Text == text {
				mine = one.Mine
			}
		}
		check(mine, "the restarted B's log does not hold %q as its own; the user has lost their own half of the conversation. It holds %s",
			text, texts(held))
	}
	fmt.Printf("  and B's own %d pre-restart line(s) came back as B's own, out of %d in its log\n",
		len(bsOwn), len(held))
	// THE PRE-CHANGE HISTORY COMES BACK. B was a member at epoch 1, so item 241 says every epoch-1
	// line is B's to read after the membership change: A's lines open under a REBUILT epoch-1
	// schedule (loaded once from the epoch-1 state blob the 32-epoch window keeps), and B's own come
	// from its local copies. Before 241 landed this block asserted the OPPOSITE -- exactly 602
	// out_of_window gaps -- and printed it as "out of this build's reach". Now the count that must be
	// exact is the other way round: ZERO gaps for a member who was there, and every A line from
	// epoch 1 counted under Stats.OpenedPastEpoch. A gap here is a line the change lost; an
	// OpenedPastEpoch below A's epoch-1 count is a line that came back some other way than the one
	// this build claims.
	check(bGroup.Epoch() == 2, "the restarted B's re-walk over the epoch commit left it at epoch %d, want 2", bGroup.Epoch())
	bGaps, bOpenedAfterRestart, bOtherGaps := gapCount(afterRestart)
	check(bOtherGaps == 0, "the restarted B's re-walk produced %d gap(s) of a reason other than out_of_window", bOtherGaps)
	check(bGaps == 0,
		"the restarted B re-walked %d epoch-one line(s) as out_of_window gaps; B was a member at epoch 1 and item 241 says it keeps every one of them",
		bGaps)
	check(bGroup.Stats().GapOutOfWindow == 0, "the restarted B's Stats.GapOutOfWindow is %d, want 0", bGroup.Stats().GapOutOfWindow)
	asEpochOne := uint64(epochOneLines - 1) // B sealed exactly one line at epoch 1 (step 3's answer); the rest are A's
	check(bGroup.Stats().OpenedPastEpoch == asEpochOne,
		"the restarted B opened %d record(s) under the rebuilt epoch-1 schedule and A sealed %d at epoch 1",
		bGroup.Stats().OpenedPastEpoch, asEpochOne)
	fmt.Printf("  the restarted B re-walked its whole history at epoch 2 with 0 out_of_window gaps: %d of A's epoch-1\n"+
		"  line(s) opened under the REBUILT epoch-1 schedule (item 241, live), B's own came from copies, and\n"+
		"  %d line(s) in all opened with 0 failures\n", bGroup.Stats().OpenedPastEpoch, bOpenedAfterRestart)
	const afterTheRestart = "typed by the SAME device after it was restarted"
	if _, err := bGroup.Send(ctx, afterTheRestart); err != nil {
		fail("the restarted B Send: %v", err)
	}
	fromRestarted := receive(aGroup, ctx, "A")
	check(len(fromRestarted) == 1 && fromRestarted[0].Text == afterTheRestart,
		"A read %s for the one line the restarted B sent", texts(fromRestarted))
	check(string(fromRestarted[0].SenderHandle) == string(bHandle),
		"the restarted B seals under sender_handle %x and sealed under %x before, so it is a different leaf",
		fromRestarted[0].SenderHandle, bHandle)
	fmt.Printf("  B came back at epoch %d under the same leaf, read %d messages including the one\n"+
		"  sealed before the restart, and A opened the one B sealed after it\n", bGroup.Epoch(), len(afterRestart))

	// ── 8 ────────────────────────────────────────────────────────────────────────────────
	step("two senders at once, which is where the stream indices and the reserver earn their keep")
	fmt.Printf("  WHAT THIS IS FOR: each sender allocates from its OWN durable stream row, so two\n" +
		"  senders must never collide -- and a sender that raced with itself would reuse an index,\n" +
		"  which 5.6 calls a total break of both AEADs for that record. Every line below is\n" +
		"  distinct, so a lost one and a duplicated one are both visible in the counts.\n")
	const concurrent = 20
	var wait sync.WaitGroup
	sendErrors := make([]error, 2)
	fromA := map[string]bool{}
	fromB := map[string]bool{}
	for at := 0; at < concurrent; at += 1 {
		fromA[fmt.Sprintf("A concurrent %d", at)] = true
		fromB[fmt.Sprintf("B concurrent %d", at)] = true
	}
	wait.Add(2)
	go func() {
		defer wait.Done()
		for at := 0; at < concurrent; at += 1 {
			if _, err := aGroup.Send(ctx, fmt.Sprintf("A concurrent %d", at)); err != nil {
				sendErrors[0] = err
				return
			}
		}
	}()
	go func() {
		defer wait.Done()
		for at := 0; at < concurrent; at += 1 {
			if _, err := bGroup.Send(ctx, fmt.Sprintf("B concurrent %d", at)); err != nil {
				sendErrors[1] = err
				return
			}
		}
	}()
	wait.Wait()
	check(sendErrors[0] == nil, "A's concurrent sends failed: %v", sendErrors[0])
	check(sendErrors[1] == nil, "B's concurrent sends failed: %v", sendErrors[1])
	atA := receive(aGroup, ctx, "A")
	atB := receive(bGroup, ctx, "B")
	countOnce(atA, fromB, "A", "B")
	countOnce(atB, fromA, "B", "A")
	fmt.Printf("  %d lines each way, concurrently: A opened %d of B's, B opened %d of A's, none twice\n",
		concurrent, len(atA), len(atB))

	// ── 9 ────────────────────────────────────────────────────────────────────────────────
	step("a reply, two reactions, one taken back, and a delete -- the content envelope over the mesh")
	fmt.Printf("  WHAT THIS IS FOR: every line above this step was a TEXT. A reply, a reaction and a\n" +
		"  tombstone ride the SAME sealed body under a one-octet kind, so a build that got the\n" +
		"  envelope wrong does not refuse -- it renders them as garbage text attributed to a real\n" +
		"  sender. Every kind here is asserted on the FAR side, because the near side proves only\n" +
		"  that this build agrees with itself.\n")

	anchor, err := aGroup.Send(ctx, "the line every kind below points at")
	if err != nil {
		fail("A Send the anchor line: %v", err)
	}
	anchorAtB := findById(receive(bGroup, ctx, "B"), anchor.MessageId)
	check(anchorAtB != nil, "B never received the anchor line A sent")
	check(anchorAtB.Kind == urmessage.KindText,
		"the anchor came back as kind %s and A sealed it as a text", anchorAtB.Kind)

	// A REPLY carries a raw 32 octet reference in front of its text. The reference is the half a
	// text-only build cannot have got right by accident.
	const replyText = "a reply that names the line above"
	replySent, err := bGroup.SendReply(ctx, anchor.MessageId, replyText)
	if err != nil {
		fail("B SendReply: %v", err)
	}
	replyAtA := findById(receive(aGroup, ctx, "A"), replySent.MessageId)
	check(replyAtA != nil, "A never received B's reply")
	check(replyAtA.Kind == urmessage.KindReply, "B's reply came back as kind %s", replyAtA.Kind)
	check(bytes.Equal(replyAtA.ReplyToId, anchor.MessageId),
		"the reply names message %x and the anchor is %x", replyAtA.ReplyToId, anchor.MessageId)
	check(replyAtA.Text == replyText, "the reply's text came back as %q", replyAtA.Text)
	fmt.Printf("  a REPLY crossed: it names the anchor's message_id and its text survived\n")

	// TWO REACTIONS, THEN ONE TAKEN BACK. A reaction adds no line of its own -- it changes a line
	// that is already there -- so the assertion is on the ANCHOR, not on what Receive answered.
	for _, emoji := range []string{"👍", "🎉"} {
		if _, err := bGroup.React(ctx, anchor.MessageId, emoji); err != nil {
			fail("B React %q: %v", emoji, err)
		}
	}
	receive(aGroup, ctx, "A")
	anchorAtA := findById(aGroup.Messages(), anchor.MessageId)
	check(anchorAtA != nil, "A lost its own anchor line out of its log")
	check(len(anchorAtA.Reactions) == 2,
		"A sees %d reaction(s) on its line and B sent two", len(anchorAtA.Reactions))

	if _, err := bGroup.Unreact(ctx, anchor.MessageId, "👍"); err != nil {
		fail("B Unreact: %v", err)
	}
	receive(aGroup, ctx, "A")
	anchorAtA = findById(aGroup.Messages(), anchor.MessageId)
	check(len(anchorAtA.Reactions) == 1,
		"after B took one back A sees %d reaction(s), want 1", len(anchorAtA.Reactions))
	check(anchorAtA.Reactions[0].Emoji == "🎉",
		"the reaction still standing is %q and the one taken back was the other",
		anchorAtA.Reactions[0].Emoji)
	fmt.Printf("  two REACTIONS crossed and one was taken back: A sees exactly the one that stands\n")

	// THE SAME-SENDER RULE, ON THE SEND SIDE. R1 proves who wrote a TOMBSTONE and NOTHING proves
	// they wrote its target, so an honest build refuses to seal one naming somebody else's line.
	// This asserts the refusal, which is the arm a receiver-side check alone would leave untested.
	if _, err := bGroup.Delete(ctx, anchor.MessageId); err == nil {
		fail("B SEALED A TOMBSTONE FOR A'S MESSAGE. The same-sender rule is not enforced on the send\n" +
			"  side, so this build emits a record every honest receiver is supposed to ignore.")
	}
	fmt.Printf("  and B REFUSED to delete A's line, which is the same-sender rule on the send side\n")

	if _, err := aGroup.Delete(ctx, anchor.MessageId); err != nil {
		fail("A Delete its own line: %v", err)
	}
	receive(bGroup, ctx, "B")
	anchorAtB = findById(bGroup.Messages(), anchor.MessageId)
	check(anchorAtB != nil, "B lost the anchor line entirely once it was deleted; it should be MARKED")
	check(anchorAtB.Deleted, "A deleted its line and B's copy of it is not marked deleted")
	fmt.Printf("  a TOMBSTONE crossed: B's copy of A's line is marked deleted and still present\n")

	// ── 10 ───────────────────────────────────────────────────────────────────────────────
	step("roles: a promotion, a member's refused add, a transfer of ownership and a demotion, with every party's roster agreeing at every stage")
	fmt.Printf("  WHAT THIS IS FOR: MASTER 11's role model (ledger item 242) is live on both arms --\n" +
		"  a commit the committer's role does not permit is refused before it is built and rejected\n" +
		"  by every receiver -- and this is the first time the two arms run over the deployed\n" +
		"  server with three real devices. Every stage prints each party's roster off its OWN\n" +
		"  Members() and asserts that the three agree, because a role only exists if every member\n" +
		"  reads the same one; and the refused add asserts that NO party's epoch moved, which is\n" +
		"  the send-side arm doing its job rather than the receivers cleaning up after it.\n")
	parties := []*namedGroup{{"A", aGroup}, {"B", bGroup}, {"C", cGroup}}
	// EVERY PARTY IS DRAINED FIRST. Steps 6 to 9 are conversations between A and B alone, so C
	// holds a backlog of every line since step 5, and the assertion below that a Receive after a
	// role commit hands back NO line is about the commit only if nothing else is waiting. The
	// first run of this step failed exactly here: C's Receive of the promotion answered 47 lines
	// it had simply not fetched yet.
	for _, one := range parties {
		backlog := receive(one.group, ctx, one.name)
		fmt.Printf("  %s drained %d entr%s of backlog before the first role change\n", one.name, len(backlog),
			map[bool]string{true: "y", false: "ies"}[len(backlog) == 1])
	}
	identities := map[string]string{}
	for _, one := range parties {
		identities[string(identityOf(one.group, one.name))] = one.name
	}
	check(len(identities) == 3, "the three parties hold %d distinct identities", len(identities))
	bId, cId := identityOf(bGroup, "B"), identityOf(cGroup, "C")
	epochAtStart := aGroup.Epoch()
	rolesAgree("before any role change", parties, identities, epochAtStart,
		map[string]string{"A": "owner", "B": "member", "C": "member"})

	// STAGE 1: the owner promotes B. A commits and moves; B and C follow on their next Receive,
	// which hands back no line because a commit is not one.
	if err := aGroup.SetRole(ctx, bId, "admin"); err != nil {
		fail("A SetRole(B, admin): %v", err)
	}
	check(aGroup.Epoch() == epochAtStart+1, "A's promotion of B left A at epoch %d, want %d", aGroup.Epoch(), epochAtStart+1)
	for _, follower := range []*namedGroup{{"B", bGroup}, {"C", cGroup}} {
		got := receive(follower.group, ctx, follower.name)
		check(len(got) == 0, "%s's Receive of the promotion handed back %d entries and a commit is not a line: %s",
			follower.name, len(got), texts(got))
	}
	rolesAgree("A promoted B to admin", parties, identities, epochAtStart+1,
		map[string]string{"A": "owner", "B": "admin", "C": "member"})
	if role, err := bGroup.MyRole(); err != nil || role != "admin" {
		fail("B's MyRole after the promotion is %q, %v; want admin", role, err)
	}

	// STAGE 2: C, a MEMBER, tries to add a stranger. The send side refuses it with the
	// receivers' own sentence, nothing is built, and no party's epoch moves -- asserted on
	// every party after a Receive that finds nothing to ingest.
	stranger := mesh.stranger(c)
	defer stranger.close()
	strangerKeyPackage, err := stranger.device.KeyPackage()
	if err != nil {
		fail("the stranger's KeyPackage: %v", err)
	}
	refusedBefore := cGroup.Stats().CommitRefusedOwn
	_, err = cGroup.AddMemberAndPublish(ctx, strangerKeyPackage)
	check(err != nil, "C, a MEMBER, ADDED A STRANGER TO THE GROUP: the send-side arm of the role model is not running")
	check(errors.Is(err, urmessage.ErrCommitUnauthorized), "C's add was refused with %v, which does not wrap ErrCommitUnauthorized", err)
	check(errors.Is(err, urmessage.ErrCommitAddByNonAdmin), "C's add was refused with %v, which does not wrap R1's ErrCommitAddByNonAdmin", err)
	check(cGroup.Stats().CommitRefusedOwn == refusedBefore+1, "C's Stats.CommitRefusedOwn went %d -> %d over one refused add, want one more",
		refusedBefore, cGroup.Stats().CommitRefusedOwn)
	fmt.Printf("  C's AddMemberAndPublish as a member was refused on the SEND side: %v\n", err)
	for _, one := range []*namedGroup{{"A", aGroup}, {"B", bGroup}} {
		got := receive(one.group, ctx, one.name)
		check(len(got) == 0, "%s fetched %d entries after C's refused add; something was published: %s", one.name, len(got), texts(got))
	}
	rolesAgree("C's add of a stranger was refused, nothing moved", parties, identities, epochAtStart+1,
		map[string]string{"A": "owner", "B": "admin", "C": "member"})

	// STAGE 3: A hands the group to B. B is the owner and A is an admin from then (ruling 4).
	if err := aGroup.TransferOwnership(ctx, bId); err != nil {
		fail("A TransferOwnership(B): %v", err)
	}
	check(aGroup.Epoch() == epochAtStart+2, "the transfer left A at epoch %d, want %d", aGroup.Epoch(), epochAtStart+2)
	for _, follower := range []*namedGroup{{"B", bGroup}, {"C", cGroup}} {
		got := receive(follower.group, ctx, follower.name)
		check(len(got) == 0, "%s's Receive of the transfer handed back %d entries: %s", follower.name, len(got), texts(got))
	}
	rolesAgree("A transferred ownership to B", parties, identities, epochAtStart+2,
		map[string]string{"A": "admin", "B": "owner", "C": "member"})
	if role, _ := bGroup.MyRole(); role != "owner" {
		fail("B's MyRole after the transfer is %q, want owner", role)
	}
	if role, _ := aGroup.MyRole(); role != "admin" {
		fail("A's MyRole after the transfer is %q, want admin", role)
	}

	// STAGE 4: the new owner demotes C to observer, and A -- now an admin -- follows a commit
	// it did not make.
	if err := bGroup.SetRole(ctx, cId, "observer"); err != nil {
		fail("B SetRole(C, observer) as the new owner: %v", err)
	}
	check(bGroup.Epoch() == epochAtStart+3, "B's demotion of C left B at epoch %d, want %d", bGroup.Epoch(), epochAtStart+3)
	for _, follower := range []*namedGroup{{"A", aGroup}, {"C", cGroup}} {
		got := receive(follower.group, ctx, follower.name)
		check(len(got) == 0, "%s's Receive of the demotion handed back %d entries: %s", follower.name, len(got), texts(got))
	}
	rolesAgree("B, the new owner, demoted C to observer", parties, identities, epochAtStart+3,
		map[string]string{"A": "admin", "B": "owner", "C": "observer"})
	if role, _ := cGroup.MyRole(); role != "observer" {
		fail("C's MyRole after the demotion is %q, want observer", role)
	}
	fmt.Printf("  four role commits crossed the mesh and three rosters agreed at every one of them\n")

	// ── the counters, which are the last thing a reader should see ───────────────────────
	step("the counters")
	report("A", aGroup)
	report("B", bGroup)
	report("C", cGroup)
	fmt.Printf("\n=== %d STEPS, %d ASSERTIONS, ALL HELD ===\n", steps, checks)
	fmt.Printf("WHAT THIS PROBE DOES NOT ASSERT, and it needs a database credential this binary must\n" +
		"not hold: that the plaintext is absent from the server's `message_record` rows.\n")
}

// ── the parties ──────────────────────────────────────────────────────────────────────────────

// dial stands up one whole client: a connect client on the real mesh, a 10.1 transport over it,
// the DURABLE stream store the reserver allocates out of, and the DURABLE mls state store that
// makes a restart a restore.
//
// BOTH STORES LIVE UNDER ONE DIRECTORY PER PARTY and that directory is the whole of what survives
// this process. Nothing else about a party is persisted and nothing else needs to be.
//
// THE CLIENT IS sdk.NewMessageClient'S AND IT USED TO BE THIS FUNCTION'S. The eight lines that
// stood one up -- a client strategy, an out-of-band control over https://api.<host>, a client at
// the credential's client_id, a platform transport dialling wss://connect.<host>, and the provide
// modes -- were the ONLY construction of a platform-attached client anywhere in this workspace,
// which is why the C abi could reach nothing but an in-process loopback server. They are now
// sdk/message_client.go's, and this probe calls it.
//
// THAT IS THE POINT RATHER THAN A TIDY-UP. This binary is the one thing that is ever run against a
// real operator, so putting the shared declaration on ITS path is what makes a live run evidence
// about the code the Windows app links rather than about a copy of it.
func (self *dialer) dial(name string, jwtPath string) *party {
	raw, err := os.ReadFile(jwtPath)
	if err != nil {
		fail("%s read jwt: %v", name, err)
	}
	byJwt := strings.TrimSpace(string(raw))
	client, err := sdk.NewMessageClient(self.ctx, &sdk.MessageClientConfig{
		ByClientJwt: byJwt,
		Host:        self.host,
		AppVersion:  "alphaprobe",
	})
	if err != nil {
		fail("%s client: %v", name, err)
	}

	transport, err := sdk.NewMessageTransport(&sdk.MessageTransportConfig{
		Client: client, Server: self.server, ProtocolVersion: 1, Timeout: self.timeout,
	})
	if err != nil {
		fail("%s transport: %v", name, err)
	}
	dir := self.root + "/" + name
	if err := os.MkdirAll(dir+"/stream", 0o700); err != nil {
		fail("%s stream dir: %v", name, err)
	}
	if err := os.MkdirAll(dir+"/state", 0o700); err != nil {
		fail("%s state dir: %v", name, err)
	}
	streamStore, err := sdk.OpenStreamStore(dir + "/stream")
	if err != nil {
		fail("%s OpenStreamStore: %v", name, err)
	}
	stateStore, err := urmessage.OpenDurableStateStore(dir + "/state")
	if err != nil {
		fail("%s OpenDurableStateStore: %v -- if this says the directory is held, a previous run of this probe is still alive",
			name, err)
	}
	device, err := urmessage.NewDevice(urmessage.DeviceConfig{
		Transport:  transport,
		Reserver:   sdk.NewStreamIndexReserver(streamStore),
		StateStore: stateStore,
		Connect:    self.connect,
	})
	if err != nil {
		fail("%s NewDevice: %v", name, err)
	}
	fmt.Printf("%s  client_id %s, dialling %s, durable state in %s\n",
		name, client.ClientId(), client.PlatformUrl(), dir)
	return &party{
		name: name, dir: dir, client: client, transport: transport,
		streamStore: streamStore, stateStore: stateStore, device: device,
	}
}

// restart kills a party and opens a new one over the same directory, the way the operating system
// would if the user closed the app.
//
// It re-reads the credential from the SAME flag the first dial used rather than carrying anything
// forward: a restart handed the parsed credential in memory would be carrying state across the
// thing it is meant to be measuring.
func (self *dialer) restart(previous *party) *party {
	name := previous.name
	fmt.Printf("  killing %s: device, both durable stores, transport and connect client\n", name)
	previous.close()
	// the exclusions are the operating system's and are released by the closes above; if the new
	// open is refused as locked, the previous process did NOT let go and that is the finding.
	return self.dial(name, self.jwtOf(name))
}

// stranger is a device with a FRESH identity that never connects: its one job is a key package
// naming an identity the group has never seen, which is what a member's refused add (step 10) has
// to carry -- a key package from any existing member would be that member's own second device,
// which a member of any role MAY add (MASTER 11's self-service rule). It rides the transport of
// the party it is built beside because a Device needs one, and it never speaks over it; its state
// store is the in-memory one, and its stream store is a directory of its own under -dir so that
// nothing of the real party's is touched.
func (self *dialer) stranger(beside *party) *party {
	dir := self.root + "/stranger"
	if err := os.MkdirAll(dir+"/stream", 0o700); err != nil {
		fail("the stranger's stream dir: %v", err)
	}
	streamStore, err := sdk.OpenStreamStore(dir + "/stream")
	if err != nil {
		fail("the stranger's OpenStreamStore: %v", err)
	}
	device, err := urmessage.NewDevice(urmessage.DeviceConfig{
		Transport: beside.transport,
		Reserver:  sdk.NewStreamIndexReserver(streamStore),
	})
	if err != nil {
		fail("the stranger's NewDevice: %v", err)
	}
	return &party{name: "stranger", dir: dir, streamStore: streamStore, device: device}
}

// jwtOf is where a party's credential path lives across a restart. The flags are the source of
// truth and this reads them back rather than keeping a copy.
func (self *dialer) jwtOf(name string) string {
	switch name {
	case "A":
		return flag.Lookup("a").Value.String()
	case "B":
		return flag.Lookup("b").Value.String()
	case "C":
		return flag.Lookup("c").Value.String()
	}
	fail("no credential flag for party %q", name)
	return ""
}

func (self *party) close() {
	if self.device != nil {
		self.device.Close()
	}
	if self.stateStore != nil {
		self.stateStore.Close()
	}
	if self.streamStore != nil {
		self.streamStore.Close()
	}
	if self.transport != nil {
		self.transport.Close()
	}
	if self.client != nil {
		self.client.Close()
	}
}

// ── the harness ──────────────────────────────────────────────────────────────────────────────

// printConnectAttempt is what makes "reconnecting" a thing an operator SEES rather than a thing
// the error says afterwards. A blocking Connect that prints nothing for ninety seconds is
// indistinguishable from a hang, which is most of why the old hard failure was tolerable.
func printConnectAttempt(attempt urmessage.ConnectAttempt) {
	fmt.Printf("  reconnecting: Hello attempt %d was not answered after %v; waiting %v (%v)\n",
		attempt.Attempt, attempt.Elapsed.Round(time.Millisecond),
		attempt.Backoff.Round(time.Millisecond), attempt.Err)
}

func step(s string) {
	steps += 1
	current = s
	fmt.Printf("\n=== %d. %s ===\n", steps, s)
}

// check is the whole of the probe's discipline: every assertion carries the sentence that says
// what was expected and what came back, so a failure at 2am is readable without this source.
func check(held bool, format string, args ...any) {
	checks += 1
	if !held {
		fail(format, args...)
	}
}

// receive is [urmessage.Group.Receive] with its error treated as fatal AND its truncation signal
// treated as fatal, which is the point of the signal existing.
func receive(group *urmessage.Group, ctx context.Context, who string) []*urmessage.Message {
	got, err := group.Receive(ctx)
	if err != nil {
		if errors.Is(err, urmessage.ErrFetchIncomplete) {
			fail("%s Receive stopped at its page bound with %d messages read; the server still has more: %v",
				who, len(got), err)
		}
		if errors.Is(err, urmessage.ErrIdentityInUse) {
			fail("%s: ANOTHER DEVICE IS SEALING UNDER THIS DEVICE'S IDENTITY IN THIS GROUP. That is a COPY\n"+
				"  of the app-data directory -- two devices at one leaf, one sender_handle and one stream\n"+
				"  counter -- and two records under one (epoch, sender_handle, stream_index) are one\n"+
				"  record_key and one nonce, which 5.6 calls a total break of both AEADs for that record.\n"+
				"  One of the two copies has to stop -- this is not a probe artefact and not something\n"+
				"  re-running fixes. NOTE it is NOT what running this probe twice over one -dir does:\n"+
				"  a second run founds a fresh group id, so the old group's indices still match its own\n"+
				"  reserver. This means a COPY of the directory exists somewhere: %v", who, err)
		}
		if errors.Is(err, urmessage.ErrFetchOmitted) {
			fail("%s: THE SERVER ANSWERED A COMPLETE PAGE AND NAMED A HIGH WATER ABOVE EVERYTHING IT HANDED\n"+
				"  OVER. It is holding records back, which is the one failure the AEAD cannot see.\n"+
				"  THE ONE INNOCENT EXPLANATION IS NOT BUILT YET: 7.2's retention sweep would take rows\n"+
				"  out from under a high water that is next_record_id-1 and does not come down, and\n"+
				"  nothing in the server deletes a message_record row today. If you are running against a\n"+
				"  server new enough to sweep, check its retention settings before reading this as an\n"+
				"  omission; otherwise read it as one: %v", who, err)
		}
		if errors.Is(err, urmessage.ErrRecordAbandoned) {
			fail("%s: a record did not open after every retry and is no longer being fetched, so this\n"+
				"  conversation has a hole in it. Records given up on: %v -- %v",
				who, group.UnopenedRecords(), err)
		}
		fail("%s Receive: %v", who, err)
	}
	return got
}

// opens is one direction of a group chat: [receive] on the far side, then the assertion that the
// exact text came back OPENED -- a line and not a gap -- and that it came back ALONE, because
// every group here has drained before the send, so a second entry is a record nobody sent.
func opens(group *urmessage.Group, ctx context.Context, reader string, writer string, want string) {
	got := receive(group, ctx, reader)
	check(len(got) == 1, "%s read %d entries for the one line %s sent: %s", reader, len(got), writer, texts(got))
	check(got[0].Gap == "", "%s received %s's line as a %q gap rather than opening it", reader, writer, got[0].Gap)
	check(got[0].Text == want, "%s opened %q and %s typed %q", reader, got[0].Text, writer, want)
	check(!got[0].Mine, "%s opened %s's line and its own log marks it as %s's own", reader, writer, reader)
	fmt.Printf("  %s->%s opened on %s: %q\n", writer, reader, reader, got[0].Text)
}

// gapCount sorts one Receive's entries three ways: out_of_window gaps, opened lines, and gaps of
// any OTHER reason -- which the epoch change never produces, so the third is asserted zero.
func gapCount(got []*urmessage.Message) (outOfWindow int, opened int, other int) {
	for _, one := range got {
		switch one.Gap {
		case "":
			opened += 1
		case urmessage.GapOutOfWindow:
			outOfWindow += 1
		default:
			other += 1
		}
	}
	return outOfWindow, opened, other
}

// countOnce holds that every expected line arrived EXACTLY once, which is what a concurrent send
// can break in both directions: a lost line and a duplicated one.
func countOnce(got []*urmessage.Message, expected map[string]bool, reader string, writer string) {
	seen := map[string]int{}
	for _, one := range got {
		seen[one.Text] += 1
	}
	for line := range expected {
		check(seen[line] == 1, "%s read %s's line %q %d times, want exactly 1", reader, writer, line, seen[line])
	}
	check(len(got) == len(expected), "%s read %d messages and %s sent %d", reader, len(got), writer, len(expected))
}

// namedGroup is one party's group under the name the tables print.
type namedGroup struct {
	name  string
	group *urmessage.Group
}

// identityOf is a party's own identity public key, read off its own roster's Mine row -- the
// value SetRole and TransferOwnership take, and the key every roster is joined on.
func identityOf(group *urmessage.Group, who string) []byte {
	members, err := group.Members()
	if err != nil {
		fail("%s Members: %v", who, err)
	}
	for _, member := range members {
		if member.Mine {
			return append([]byte(nil), member.IdentityPub...)
		}
	}
	fail("%s's roster marks no row as its own", who)
	return nil
}

// rolesAgree prints one roles table per party -- every row of its OWN Members(), with the epoch
// -- and asserts three things at once: every party is at the wanted epoch, every party's roster
// names exactly the three identities with exactly the wanted roles, and so the three rosters
// agree. A disagreement is a FAIL line naming the party, the identity and both roles.
func rolesAgree(stage string, parties []*namedGroup, identities map[string]string, epoch uint64, want map[string]string) {
	fmt.Printf("  roles after %q:\n", stage)
	for _, one := range parties {
		members, err := one.group.Members()
		if err != nil {
			fail("%s Members after %s: %v", one.name, stage, err)
		}
		row := []string{}
		seen := map[string]string{}
		for _, member := range members {
			name, known := identities[string(member.IdentityPub)]
			if !known {
				name = "?" + fmt.Sprintf("%x", member.IdentityPub[:4])
			}
			mine := ""
			if member.Mine {
				mine = "*"
			}
			row = append(row, fmt.Sprintf("leaf%d %s%s=%s", member.LeafIndex, name, mine, member.Role))
			seen[name] = member.Role
		}
		fmt.Printf("    %s @epoch %d: %s\n", one.name, one.group.Epoch(), strings.Join(row, "  "))
		check(one.group.Epoch() == epoch, "%s is at epoch %d after %s, want %d", one.name, one.group.Epoch(), stage, epoch)
		check(len(members) == len(want), "%s's roster holds %d rows after %s, want %d", one.name, len(members), stage, len(want))
		for name, role := range want {
			check(seen[name] == role, "%s reads %s as %q after %s, want %q", one.name, name, seen[name], stage, role)
		}
		for name := range seen {
			if _, wanted := want[name]; !wanted {
				fail("%s's roster names %s, which no party is, after %s", one.name, name, stage)
			}
		}
	}
}

func report(who string, group *urmessage.Group) {
	stats := group.Stats()
	fmt.Printf("  %s: fetched=%d opened=%d ceremony=%d own=%d otherClasses=%d FAILED=%d submitted=%d rebound=%d pages=%d unattested=%d\n",
		who, stats.Fetched, stats.Opened, stats.SkippedCeremony, stats.SkippedOwn,
		stats.SkippedClass, stats.FailedOpen, stats.Submitted, stats.Rebound, stats.Pages, stats.Unattested)
	check(stats.FailedOpen == 0, "%s: %d records from a member of this group did not open", who, stats.FailedOpen)
}

func texts(messages []*urmessage.Message) string {
	out := []string{}
	for _, one := range messages {
		if one.Gap != "" {
			// a gap has no text, and rendering it as "" would make it a blank line somebody sent
			out = append(out, fmt.Sprintf("<gap:%s@%d>", one.Gap, one.RecordId))
			continue
		}
		if 80 < len(one.Text) {
			out = append(out, fmt.Sprintf("%q...(%d octets)", one.Text[:80], len(one.Text)))
			continue
		}
		out = append(out, fmt.Sprintf("%q", one.Text))
	}
	return "[" + strings.Join(out, " ") + "]"
}

// firstDifference is where two strings stop agreeing, so a fragment reassembled out of order says
// WHERE rather than only that it is wrong.
// findById is the probe's one lookup: a message by the id its own sender was told it has.
//
// IT EXISTS BECAUSE NAMING IS THE WHOLE OF WHAT THE ENVELOPE ADDED. A reply that points at
// nothing, and a reaction that lands on nothing, both look like success from the sending side.
func findById(messages []*urmessage.Message, id []byte) *urmessage.Message {
	for _, message := range messages {
		if bytes.Equal(message.MessageId, id) {
			return message
		}
	}
	return nil
}

func firstDifference(want string, got string) int {
	for at := 0; at < len(want) && at < len(got); at += 1 {
		if want[at] != got[at] {
			return at
		}
	}
	if len(want) != len(got) {
		return min(len(want), len(got))
	}
	return -1
}

func fail(format string, args ...any) {
	if current != "" {
		fmt.Fprintf(os.Stderr, "\nFAIL at step %d (%s)\n", steps, current)
	}
	fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", args...)
	os.Exit(1)
}
