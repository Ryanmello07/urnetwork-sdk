// Two real URnetwork accounts, two real platform connections, one DEPLOYED message server, and
// the whole of what the alpha can do, scenario by scenario.
//
// Everything before this ran two connect.Clients over in-process Routes in one binary. This
// crosses the operator's mesh to a server it did not start.
//
// EVERY STEP PRINTS WHAT IT ASSERTED. A probe that prints "OK" without naming what it checked is
// useless at 2am, so each check() below carries the sentence a reader needs in order to know what
// went wrong, and fail() names the step, the expectation and what actually came back.
package main

import (
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

	client      *connect.Client
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
}

var (
	steps   int
	checks  int
	current string
)

func main() {
	aJwt := flag.String("a", "", "file holding party A's by_client_jwt")
	bJwt := flag.String("b", "", "file holding party B's by_client_jwt")
	cJwt := flag.String("c", "", "file holding party C's by_client_jwt; optional, and see step 5")
	serverId := flag.String("server", "", "the message server's client_id")
	host := flag.String("host", "beta-test.net", "operator host")
	dir := flag.String("dir", "/var/lib/urmessage/probe", "where each party's durable state lives")
	text := flag.String("text", "the first message over the real mesh", "what A sends first")
	lines := flag.Int("lines", 600, "how many messages step 4 sends; must exceed the server's max_records_per_fetch to reach the truncation path")
	bigBytes := flag.Int("big", 40000, "how many octets step 6's message carries; anything over 2048 crosses the fragmentation cut")
	timeout := flag.Duration("timeout", 60*time.Second, "per-request transport timeout")
	flag.Parse()

	server, err := connect.ParseId(*serverId)
	if err != nil {
		fail("parse server id: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lineCount := *lines
	mesh := &dialer{ctx: ctx, server: server, host: *host, root: *dir, timeout: *timeout}

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
	step("a third member -- AND WHY THIS BUILD REFUSES ONE")
	fmt.Printf("  The alpha adds EXACTLY ONE member, in the commit that opens epoch 1, before Open.\n" +
		"  A second add is a second epoch: every member's session has to advance, the server has to\n" +
		"  be handed the new epoch's keys in a new commit, and 6.1's wrap fan-out has to run again.\n" +
		"  None of that is built. So this step does not add a third member -- it holds that the\n" +
		"  refusal is BY NAME rather than a REASON_REJECTED a caller has to decode, which is the\n" +
		"  only thing about a third member that is true today.\n")
	if *cJwt != "" {
		c := mesh.dial("C", *cJwt)
		defer c.close()
		if err := c.device.Connect(ctx); err != nil {
			fail("C Connect: %v", err)
		}
		thirdKeyPackage, err := c.device.KeyPackage()
		if err != nil {
			fail("C KeyPackage: %v", err)
		}
		_, err = aGroup.AddMember(thirdKeyPackage)
		check(err != nil, "a SECOND AddMember was accepted; the alpha has no second epoch and this build just made one")
		check(errors.Is(err, urmessage.ErrAlphaOneAdd) || errors.Is(err, urmessage.ErrGroupOpen),
			"the second AddMember answered %v, want ErrAlphaOneAdd or ErrGroupOpen", err)
		fmt.Printf("  a real third device was refused by name: %v\n", err)
	} else {
		_, err := aGroup.AddMember(keyPackage)
		check(err != nil, "a SECOND AddMember was accepted; the alpha has no second epoch and this build just made one")
		fmt.Printf("  refused by name (no -c credential, so B's own key package stood in): %v\n", err)
	}

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
	bHandle := append([]byte(nil), back[0].SenderHandle...)
	bEpoch := bGroup.Epoch()
	b = mesh.restart(b)
	defer b.close()
	if err := b.device.Connect(ctx); err != nil {
		fail("the restarted B Connect: %v", err)
	}
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

	// ── the counters, which are the last thing a reader should see ───────────────────────
	step("the counters")
	report("A", aGroup)
	report("B", bGroup)
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
func (self *dialer) dial(name string, jwtPath string) *party {
	raw, err := os.ReadFile(jwtPath)
	if err != nil {
		fail("%s read jwt: %v", name, err)
	}
	byJwt := strings.TrimSpace(string(raw))
	parsed, err := connect.ParseByJwtUnverified(byJwt)
	if err != nil {
		fail("%s parse jwt: %v", name, err)
	}
	strategy := connect.NewClientStrategyWithDefaults(self.ctx)
	oob := connect.NewApiOutOfBandControl(self.ctx, strategy, byJwt, "https://api."+self.host)
	client := connect.NewClient(self.ctx, parsed.ClientId, oob, connect.DefaultClientSettings())
	connect.NewPlatformTransport(
		client.Ctx(), strategy, client.RouteManager(), "wss://connect."+self.host,
		&connect.ClientAuth{ByJwt: byJwt, InstanceId: connect.NewId(), AppVersion: "alphaprobe"},
		connect.DefaultPlatformTransportSettings(),
	)
	// The server's replies are IT sending to a client it has no contract with: return traffic.
	client.ContractManager().SetProvideModesWithReturnTraffic(map[protocol.ProvideMode]bool{})

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
	})
	if err != nil {
		fail("%s NewDevice: %v", name, err)
	}
	fmt.Printf("%s  client_id %s, durable state in %s\n", name, parsed.ClientId, dir)
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
		self.client.Cancel()
	}
}

// ── the harness ──────────────────────────────────────────────────────────────────────────────

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
		fail("%s Receive: %v", who, err)
	}
	return got
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
