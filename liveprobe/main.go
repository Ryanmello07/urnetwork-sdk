// Two real URnetwork accounts, two real platform connections, one DEPLOYED message server:
// a text typed by one comes back to the other.
//
// Everything before this ran two connect.Clients over in-process Routes in one binary. This
// crosses the operator's mesh to a server it did not start.
package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/sdk"
	"github.com/urnetwork/sdk/urmessage"
)

type party struct {
	name      string
	client    *connect.Client
	transport *sdk.MessageTransport
	device    *urmessage.Device
}

func main() {
	aJwt := flag.String("a", "", "file holding party A's by_client_jwt")
	bJwt := flag.String("b", "", "file holding party B's by_client_jwt")
	serverId := flag.String("server", "", "the message server's client_id")
	host := flag.String("host", "beta-test.net", "operator host")
	dir := flag.String("dir", "/var/lib/urmessage/probe", "where each party's stream store lives")
	text := flag.String("text", "the first message over the real mesh", "what A sends")
	flag.Parse()

	server, err := connect.ParseId(*serverId)
	if err != nil {
		fail("parse server id: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a := dial(ctx, "A", *aJwt, server, *host, *dir)
	b := dial(ctx, "B", *bJwt, server, *host, *dir)
	defer a.close()
	defer b.close()

	step("Hello, both parties")
	for _, p := range []*party{a, b} {
		hctx, hcancel := context.WithTimeout(ctx, 30*time.Second)
		reason, hello, err := p.transport.Hello(hctx, 1)
		hcancel()
		if err != nil {
			fail("%s hello: %v", p.name, err)
		}
		fmt.Printf("  %s  %v, nonce %d octets\n", p.name, reason, len(hello.GetServerNonce()))
	}

	step("A founds a group")
	groupId := make([]byte, 32)
	if _, err := rand.Read(groupId); err != nil {
		fail("group id: %v", err)
	}
	gctx, gcancel := context.WithTimeout(ctx, 60*time.Second)
	defer gcancel()
	aGroup, err := a.device.CreateGroup(gctx, groupId)
	if err != nil {
		fail("A CreateGroup: %v", err)
	}
	fmt.Printf("  group %x epoch %d\n", aGroup.Id()[:8], aGroup.Epoch())

	step("B publishes a key package, A adds it")
	keyPackage, err := b.device.KeyPackage()
	if err != nil {
		fail("B KeyPackage: %v", err)
	}
	invite, err := aGroup.AddMember(keyPackage)
	if err != nil {
		fail("A AddMember: %v", err)
	}
	encoded, err := invite.Encode()
	if err != nil {
		fail("encode invite: %v", err)
	}
	fmt.Printf("  invite %d octets (carried out of band, as the design says)\n", len(encoded))

	step("A opens the group on the server")
	if err := aGroup.Open(gctx); err != nil {
		fail("A Open: %v", err)
	}

	step("A sends")
	sent, err := aGroup.Send(gctx, *text)
	if err != nil {
		fail("A Send: %v", err)
	}
	fmt.Printf("  record_id %d, %d octets of text\n", sent.RecordId, len(sent.Text))

	step("B joins and receives")
	carried, err := urmessage.ParseInvite(encoded)
	if err != nil {
		fail("parse invite: %v", err)
	}
	bGroup, err := b.device.Join(gctx, carried)
	if err != nil {
		fail("B Join: %v", err)
	}
	got, err := bGroup.Receive(gctx)
	if err != nil {
		fail("B Receive: %v", err)
	}
	if len(got) == 0 {
		fail("B received nothing")
	}
	fmt.Printf("  B got %d message(s); first: %q\n", len(got), got[0].Text)
	if got[0].Text != *text {
		fail("B read %q, A typed %q", got[0].Text, *text)
	}

	step("B answers, A receives")
	reply := "and the answer came back"
	if _, err := bGroup.Send(gctx, reply); err != nil {
		fail("B Send: %v", err)
	}
	back, err := aGroup.Receive(gctx)
	if err != nil {
		fail("A Receive: %v", err)
	}
	if len(back) == 0 || back[0].Text != reply {
		fail("A did not read B's answer: %+v", back)
	}
	fmt.Printf("  A got %q\n", back[0].Text)

	fmt.Printf("\n=== TWO PEOPLE EXCHANGED MESSAGES THROUGH A DEPLOYED SERVER ON THE REAL MESH ===\n")
	fmt.Printf("A stats: %+v\nB stats: %+v\n", aGroup.Stats(), bGroup.Stats())
}

func dial(ctx context.Context, name, jwtPath string, server connect.Id, host, dir string) *party {
	raw, err := os.ReadFile(jwtPath)
	if err != nil {
		fail("%s read jwt: %v", name, err)
	}
	byJwt := strings.TrimSpace(string(raw))
	parsed, err := connect.ParseByJwtUnverified(byJwt)
	if err != nil {
		fail("%s parse jwt: %v", name, err)
	}
	strategy := connect.NewClientStrategyWithDefaults(ctx)
	oob := connect.NewApiOutOfBandControl(ctx, strategy, byJwt, "https://api."+host)
	client := connect.NewClient(ctx, parsed.ClientId, oob, connect.DefaultClientSettings())
	connect.NewPlatformTransport(
		client.Ctx(), strategy, client.RouteManager(), "wss://connect."+host,
		&connect.ClientAuth{ByJwt: byJwt, InstanceId: connect.NewId(), AppVersion: "alphaprobe"},
		connect.DefaultPlatformTransportSettings(),
	)
	// The server's replies are IT sending to a client it has no contract with: return traffic.
	client.ContractManager().SetProvideModesWithReturnTraffic(map[protocol.ProvideMode]bool{})

	transport, err := sdk.NewMessageTransport(&sdk.MessageTransportConfig{
		Client: client, Server: server, ProtocolVersion: 1, Timeout: 30 * time.Second,
	})
	if err != nil {
		fail("%s transport: %v", name, err)
	}
	storeDir := dir + "/" + name
	if err := os.MkdirAll(storeDir, 0o700); err != nil {
		fail("%s store dir: %v", name, err)
	}
	streamStore, err := sdk.OpenStreamStore(storeDir)
	if err != nil {
		fail("%s OpenStreamStore: %v", name, err)
	}
	device, err := urmessage.NewDevice(urmessage.DeviceConfig{
		Transport: transport, Reserver: sdk.NewStreamIndexReserver(streamStore),
	})
	if err != nil {
		fail("%s NewDevice: %v", name, err)
	}
	fmt.Printf("%s  client_id %s\n", name, parsed.ClientId)
	return &party{name: name, client: client, transport: transport, device: device}
}

func (self *party) close() {
	if self.device != nil {
		self.device.Close()
	}
	if self.transport != nil {
		self.transport.Close()
	}
	if self.client != nil {
		self.client.Cancel()
	}
}

func step(s string) { fmt.Printf("\n=== %s ===\n", s) }

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", args...)
	os.Exit(1)
}
