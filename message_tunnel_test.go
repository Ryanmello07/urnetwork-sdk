//go:build !sdk_mobile_bind

package sdk

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"
)

// THE TUNNEL'S PER-PEER MODE, PINNED BY WHAT THE TUNNEL DOES WITH THE TWO KINDS OF EXIT.
//
// The owner's ruling of 2026-10-04, "Opportunistic + provider fix", is two behaviours, and each case
// below is one of them. Both run the tunnel itself to an exit in this process and dial UDP through
// it to an address the exit echoes back. "The tunnel itself" is startMessageTunnel: the gvisor tun,
// the multi client with messageTunnelMultiClientSettings, and connect's own window-client
// construction, which is where a profile with PostQuantumEncryption overrode the mode to REQUIRED
// (ledger 278). The generator hands that construction messageTunnelClientSettings.
//
//   - An exit that never answers the per-peer handshake, because its provider leaves connect's
//     default mode, Off, as the beta's provider CLI did on 2026-10-04. The tunnel must reach it
//     anyway, unsealed, as the pre-merge alpha does. Under REQUIRED no echo ever comes back.
//   - An exit that answers, as the sdk's provider path does (device_local_provider.go). The tunnel
//     must seal with it, under the X25519MLKEM768 hybrid. Under Off it never seals.
//
// What differs from the deployment: no contracts exist in this process. So a window client learns
// the exit's identity key from the key api its settings wire (/key/<id>, served here), where on
// the beta the contract names the key and /key only cross-checks it; and handshake replies cannot
// ride companion contracts, so EncryptionControlUseCompanion is off, as in
// cp3b/platformview_test.go. Nothing else of the tunnel's settings is changed.

func TestMessageTunnelReachesAnExitThatNeverAnswersTheHandshake(t *testing.T) {
	world := newTunnelWorld(t, connect.EncryptionModeOff)

	elapsed, echoErr := world.echo("an exit that drops every ClientHello", 20*time.Second)
	world.requireOpportunisticWindows(t)
	if echoErr != nil {
		t.Fatalf("the tunnel did not reach an exit that never answers the handshake: %v", echoErr)
	}
	t.Logf("echoed through the tunnel in %v", elapsed.Round(time.Millisecond))

	for _, window := range world.generator.windowClients() {
		if _, sealed := tunnelSealedWith(window.client, world.exit.ClientId()); sealed {
			t.Errorf("window client %s reports a sealed session with an exit that runs none", window.client.ClientId())
		}
	}

	// The establish hold (the owner's second ruling of 2026-10-04): a window waits up to its hold
	// for the exit's session, then falls through. So nothing readable leaves a window before its
	// hold has run from the window's first establishment attempt, which is after the window was
	// made; and the echo above came back, so the fall-through happened.
	hold := world.generator.NewClientSettings().EncryptionSettings.OpportunisticEstablishHold
	if hold <= 0 {
		t.Fatal("the tunnel's window clients have no establish hold, so the timing below would hold vacuously")
	}
	if elapsed < hold {
		t.Errorf("the echo came back after %v, inside the %v establish hold", elapsed, hold)
	}
	readable := 0
	for _, window := range world.generator.windowClients() {
		wire := world.wire.window(window.client.ClientId())
		readable += wire.application
		if wire.application != 0 && wire.firstApplication.Before(window.made.Add(hold)) {
			t.Errorf("window client %s wrote its first readable application frame %v after it was made, inside the %v hold",
				window.client.ClientId(), wire.firstApplication.Sub(window.made).Round(time.Millisecond), hold)
		}
	}
	if readable == 0 {
		t.Error("no readable application frame crossed the wire to an exit that runs no session, so the tap read nothing")
	}
}

func TestMessageTunnelSealsWithAnExitThatAnswers(t *testing.T) {
	world := newTunnelWorld(t, connect.EncryptionModeOpportunistic)

	_, echoErr := world.echo("before the session", 20*time.Second)
	world.requireOpportunisticWindows(t)
	if echoErr != nil {
		t.Fatalf("the tunnel did not reach an exit that answers the handshake: %v", echoErr)
	}

	curve, window, err := world.waitSealed(20 * time.Second)
	if err != nil {
		t.Fatalf("no window client sealed with an exit that answers: %v", err)
	}
	if curve != tls.X25519MLKEM768 {
		t.Errorf("the session sealed under %v, not X25519MLKEM768", curve)
	}
	if served := world.keyApi.servedFor(world.exit.ClientId()); served == 0 {
		t.Errorf("the session sealed, but the exit's key was never fetched from the key api the tunnel's settings wire")
	}
	t.Logf("window client %s sealed with the exit under %v", window.ClientId(), curve)

	elapsed, echoErr := world.echo("after the session sealed", 20*time.Second)
	if echoErr != nil {
		t.Fatalf("the tunnel stopped reaching the exit once sealed: %v", echoErr)
	}
	t.Logf("echoed through the sealed tunnel in %v", elapsed.Round(time.Millisecond))

	// The establish hold (the owner's second ruling of 2026-10-04): an exit that answers is sealed
	// from the first byte. The first echo above was dialled before any session existed, and still
	// not one application frame crossed the wire readable. The readable handshake frames are the
	// tap's control: it reads plaintext when there is any.
	sealedCount, application, handshake, notToExit := 0, 0, 0, 0
	for _, window := range world.generator.windowClients() {
		wire := world.wire.window(window.client.ClientId())
		sealedCount += wire.sealed
		application += wire.application
		handshake += wire.handshake
		notToExit += wire.notToExit
	}
	if application != 0 {
		t.Errorf("%d application frame(s) crossed the wire readable to an exit that answers the handshake", application)
	}
	if handshake == 0 {
		t.Error("the tap read no handshake frame in the clear, so it cannot tell a readable application frame either")
	}
	if sealedCount == 0 {
		t.Error("no sealed message crossed the wire")
	}
	t.Logf("on the wire to the exit: %d sealed, %d readable handshake frame(s), %d readable application frame(s); %d message(s) to the platform",
		sealedCount, handshake, application, notToExit)
}

// The other setting the tunnel names rather than inherits: no peer-to-peer link to the exit, so the
// exit never learns this device's address. The cases above cannot see it: no P2P exists in-process.
func TestMessageTunnelNeverDialsTheExitDirectly(t *testing.T) {
	profile := messageTunnelMultiClientSettings().DefaultPerformanceProfile
	if profile == nil {
		t.Fatal("the tunnel sets no performance profile, so AllowDirect is whatever connect defaults to")
	}
	if profile.AllowDirect {
		t.Error("AllowDirect is on: the exit would learn this device's address")
	}
}

// ── the world: the tunnel, a generator that mints its window clients, and one exit ──────────────

type tunnelWorld struct {
	ctx       context.Context
	tunnel    *messageTunnel
	exit      *connect.Client
	keyApi    *tunnelKeyApi
	generator *tunnelGenerator
	wire      *tunnelWire
}

// ── the wire: everything a window client writes toward the exit, as a relay would see it ────────
//
// The window client has one route here, so the tap also sees what it addresses to the platform
// (its key publications, which no per-peer session covers on any route). Those are counted apart:
// the property is about what is addressed to the exit.

type tunnelWire struct {
	exit    connect.Id
	mutex   sync.Mutex
	windows map[connect.Id]*tunnelWindowWire
}

type tunnelWindowWire struct {
	sealed int
	// frames to the exit readable on the wire: the per-peer handshake, and everything else
	handshake        int
	application      int
	firstApplication time.Time
	// messages addressed to anyone but the exit (the platform)
	notToExit int
}

func (self *tunnelWire) record(clientId connect.Id, at time.Time, wireBytes []byte) {
	var transferFrame protocol.TransferFrame
	if err := connect.ProtoUnmarshal(wireBytes, &transferFrame); err != nil {
		return
	}
	self.mutex.Lock()
	defer self.mutex.Unlock()
	window := self.windows[clientId]
	if window == nil {
		window = &tunnelWindowWire{}
		self.windows[clientId] = window
	}
	if !bytes.Equal(transferFrame.GetTransferPath().GetDestinationId(), self.exit.Bytes()) {
		window.notToExit += 1
		return
	}
	if 0 < len(transferFrame.GetEncryptedTransferFrame()) {
		window.sealed += 1
		return
	}
	pack := transferFrame.GetPack()
	if pack == nil && transferFrame.GetFrame().GetMessageType() == protocol.MessageType_TransferPack {
		var framePack protocol.Pack
		if err := connect.ProtoUnmarshal(transferFrame.GetFrame().GetMessageBytes(), &framePack); err == nil {
			pack = &framePack
		}
	}
	for _, frame := range pack.GetFrames() {
		if frame.GetMessageType() == protocol.MessageType_TransferEncryptedControl {
			window.handshake += 1
		} else {
			window.application += 1
			if window.firstApplication.IsZero() {
				window.firstApplication = at
			}
		}
	}
}

func (self *tunnelWire) window(clientId connect.Id) tunnelWindowWire {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if window := self.windows[clientId]; window != nil {
		return *window
	}
	return tunnelWindowWire{}
}

func newTunnelWorld(t *testing.T, exitMode connect.EncryptionMode) *tunnelWorld {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	keyApi := newTunnelKeyApi(t)
	exit := startTunnelEchoExit(t, ctx, exitMode, keyApi)
	wire := &tunnelWire{exit: exit.ClientId(), windows: map[connect.Id]*tunnelWindowWire{}}
	generator := &tunnelGenerator{
		exit:           exit,
		keyApi:         keyApi,
		clientStrategy: connect.NewClientStrategyWithDefaults(ctx),
		unsubs:         map[*connect.Client]func(){},
		wire:           wire,
	}
	tunnelCtx, tunnelCancel := context.WithCancel(ctx)
	tunnel, err := startMessageTunnel(tunnelCtx, tunnelCancel, generator, connect.NewId())
	if err != nil {
		t.Fatalf("startMessageTunnel: %v", err)
	}
	t.Cleanup(tunnel.Close)
	return &tunnelWorld{ctx: ctx, tunnel: tunnel, exit: exit, keyApi: keyApi, generator: generator, wire: wire}
}

// echo sends a datagram through the tunnel to an address the exit answers for, and waits for it to
// come back. The datagram is sent again every half second, so a window still forming costs time,
// not the case; a window that never carries it runs out the budget.
func (self *tunnelWorld) echo(label string, within time.Duration) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(self.ctx, within)
	defer cancel()
	started := time.Now()
	conn, err := self.tunnel.DialContext(ctx, "udp", "203.0.113.7:123")
	if err != nil {
		return 0, fmt.Errorf("%s: dial through the tunnel: %w", label, err)
	}
	defer conn.Close()
	payload := []byte("urmessage tunnel echo: " + label)
	buffer := make([]byte, 2048)
	var lastErr error
	for ctx.Err() == nil {
		if _, err := conn.Write(payload); err != nil {
			return 0, fmt.Errorf("%s: write: %w", label, err)
		}
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := conn.Read(buffer)
		if err == nil {
			if !bytes.Equal(buffer[:n], payload) {
				return 0, fmt.Errorf("%s: the exit echoed %q for %q", label, buffer[:n], payload)
			}
			return time.Since(started), nil
		}
		lastErr = err
	}
	return 0, fmt.Errorf("%s: nothing came back within %v (last read: %v)", label, within, lastErr)
}

// requireOpportunisticWindows checks the mode connect handed each window client, AFTER the window's
// performance profile had its say: that is where PostQuantumEncryption turns REQUIRED on.
func (self *tunnelWorld) requireOpportunisticWindows(t *testing.T) {
	t.Helper()
	windows := self.generator.windowClients()
	if len(windows) == 0 {
		t.Fatal("the tunnel minted no window client")
	}
	for _, window := range windows {
		if window.mode != connect.EncryptionModeOpportunistic {
			t.Errorf("window client %s runs per-peer encryption %s, not OPPORTUNISTIC (the owner's ruling of 2026-10-04)",
				window.client.ClientId(), tunnelModeName(window.mode))
		}
	}
}

// waitSealed keeps traffic on the window while it waits, so its sequences, and the session they
// hold, stay alive.
func (self *tunnelWorld) waitSealed(within time.Duration) (tls.CurveID, *connect.Client, error) {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		for _, window := range self.generator.windowClients() {
			if curve, sealed := tunnelSealedWith(window.client, self.exit.ClientId()); sealed {
				return curve, window.client, nil
			}
		}
		self.echo("while the session forms", time.Second)
		time.Sleep(50 * time.Millisecond)
	}
	return 0, nil, errors.New("not sealed within " + within.String())
}

func tunnelSealedWith(client *connect.Client, peerId connect.Id) (tls.CurveID, bool) {
	for _, state := range client.EncryptionSessionManager().PeerEncryptionStates() {
		if state.PeerId == peerId && state.Sealed {
			return state.KeyExchange, true
		}
	}
	return 0, false
}

func tunnelModeName(mode connect.EncryptionMode) string {
	switch mode {
	case connect.EncryptionModeOff:
		return "OFF"
	case connect.EncryptionModeOpportunistic:
		return "OPPORTUNISTIC"
	case connect.EncryptionModeRequired:
		return "REQUIRED"
	}
	return fmt.Sprintf("mode(%d)", int(mode))
}

// ── the exit: a provider client that echoes every IP packet back to where it came from ──────────

func startTunnelEchoExit(t *testing.T, ctx context.Context, mode connect.EncryptionMode, keyApi *tunnelKeyApi) *connect.Client {
	t.Helper()
	settings := connect.DefaultClientSettings()
	settings.EncryptionSettings.Mode = mode
	if mode != connect.EncryptionModeOff {
		settings.EncryptionSettings.EncryptionControlUseCompanion = false
		settings.EncryptionSettings.NewPeerClientPublicKeyFetcher = keyApi.fetcher
	}
	exit := connect.NewClient(ctx, connect.NewId(), connect.NewNoContractClientOob(), settings)
	t.Cleanup(exit.Close)
	keyApi.publish(exit)
	exit.AddReceiveCallback(func(source connect.TransferPath, frames []*protocol.Frame, peer connect.Peer) {
		for _, frame := range frames {
			message, err := connect.FromFrame(frame)
			if err != nil {
				continue
			}
			toProvider, ok := message.(*protocol.IpPacketToProvider)
			if !ok {
				continue
			}
			ipPath, payload, err := connect.ParseIpPathWithPayload(toProvider.IpPacket.PacketBytes)
			if err != nil {
				continue
			}
			echoed := craftIpv4Packet(ipPath.Protocol, ipPath.DestinationIp, ipPath.DestinationPort,
				ipPath.SourceIp, ipPath.SourcePort, false, payload)
			if echoed == nil {
				continue
			}
			echoFrame, err := connect.ToFrame(&protocol.IpPacketFromProvider{
				IpPacket: &protocol.IpPacket{PacketBytes: echoed},
			}, connect.DefaultProtocolVersion)
			if err != nil {
				continue
			}
			exit.SendWithTimeout(echoFrame, source.SourceId, func(err error) {}, -1)
		}
	})
	return exit
}

// ── the key api: what /key/<client_id> answers on the operator, for this process's clients ──────

type tunnelKeyApi struct {
	server *httptest.Server
	keys   sync.Map // connect.Id -> []byte

	mutex  sync.Mutex
	served map[connect.Id]int
}

func newTunnelKeyApi(t *testing.T) *tunnelKeyApi {
	t.Helper()
	self := &tunnelKeyApi{served: map[connect.Id]int{}}
	self.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rest, ok := strings.CutPrefix(r.URL.Path, "/key/")
		if !ok {
			http.NotFound(w, r)
			return
		}
		if _, history := strings.CutSuffix(rest, "/history"); history {
			// no client here holds a signed registration (tier P, connect/DESIGNNOTES3)
			json.NewEncoder(w).Encode(&connect.GetClientKeyHistoryResult{History: [][]byte{}})
			return
		}
		id, err := connect.ParseId(rest)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		key, ok := self.keys.Load(id)
		if !ok {
			http.NotFound(w, r)
			return
		}
		self.mutex.Lock()
		self.served[id] += 1
		self.mutex.Unlock()
		json.NewEncoder(w).Encode(&connect.GetClientKeyResult{PublicKey: key.([]byte)})
	}))
	t.Cleanup(self.server.Close)
	return self
}

func (self *tunnelKeyApi) publish(client *connect.Client) {
	self.keys.Store(client.ClientId(), []byte(client.ClientKeyManager().PublicKey()))
}

func (self *tunnelKeyApi) servedFor(id connect.Id) int {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return self.served[id]
}

// fetcher is the exit's own way to the same keys; only the window clients go through http
func (self *tunnelKeyApi) fetcher(peerId connect.Id) func(context.Context) ([]byte, error) {
	return func(context.Context) ([]byte, error) {
		if key, ok := self.keys.Load(peerId); ok {
			return key.([]byte), nil
		}
		return nil, fmt.Errorf("no identity key published for %s", peerId)
	}
}

// ── the generator: the tunnel's window clients, each wired to the exit in memory ────────────────
//
// It mirrors muxSecurityGenerator (device_local_mux_security_test.go), with the tunnel's own
// window-client settings and a record of the settings connect handed each client.

type tunnelGenerator struct {
	exit           *connect.Client
	keyApi         *tunnelKeyApi
	clientStrategy *connect.ClientStrategy
	wire           *tunnelWire

	mutex   sync.Mutex
	windows []tunnelWindowClient
	unsubs  map[*connect.Client]func()
}

type tunnelWindowClient struct {
	client *connect.Client
	// the mode in the settings connect passed to NewClient, after the window's performance profile
	mode connect.EncryptionMode
	// when the window client was made, before any of its sessions could start
	made time.Time
}

func (self *tunnelGenerator) windowClients() []tunnelWindowClient {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return append([]tunnelWindowClient(nil), self.windows...)
}

func (self *tunnelGenerator) NextDestinations(count int, excludeDestinations []connect.MultiHopId, rankMode string) (map[connect.MultiHopId]connect.DestinationStats, error) {
	next := map[connect.MultiHopId]connect.DestinationStats{}
	for _, excluded := range excludeDestinations {
		if 0 < excluded.Len() && excluded.Tail() == self.exit.ClientId() {
			return next, nil
		}
	}
	next[connect.RequireMultiHopId(self.exit.ClientId())] = connect.DestinationStats{}
	return next, nil
}

func (self *tunnelGenerator) NewClientArgs() (*connect.MultiClientGeneratorClientArgs, error) {
	return &connect.MultiClientGeneratorClientArgs{ClientId: connect.NewId()}, nil
}

func (self *tunnelGenerator) RemoveClientArgs(args *connect.MultiClientGeneratorClientArgs) {}

func (self *tunnelGenerator) RemoveClientWithArgs(client *connect.Client, args *connect.MultiClientGeneratorClientArgs) {
	self.mutex.Lock()
	unsub, ok := self.unsubs[client]
	delete(self.unsubs, client)
	self.mutex.Unlock()
	if ok {
		unsub()
	}
}

// NewClientSettings is the tunnel's window-client settings, pointed at this process's key api,
// with the one harness change the file comment names.
func (self *tunnelGenerator) NewClientSettings() *connect.ClientSettings {
	settings := messageTunnelClientSettings(self.keyApi.server.URL, self.clientStrategy)
	settings.EncryptionSettings.EncryptionControlUseCompanion = false
	return settings
}

func (self *tunnelGenerator) NewClient(ctx context.Context, args *connect.MultiClientGeneratorClientArgs, clientSettings *connect.ClientSettings) (*connect.Client, error) {
	mode := connect.EncryptionModeOff
	if clientSettings.EncryptionSettings != nil {
		mode = clientSettings.EncryptionSettings.Mode
	}
	made := time.Now()
	client := connect.NewClient(ctx, args.ClientId, connect.NewNoContractClientOob(), clientSettings)
	self.keyApi.publish(client)

	// everything the window client writes toward the exit passes the tap first
	written := make(chan []byte)
	toExit := make(chan []byte)
	fromExit := make(chan []byte)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case wireBytes := <-written:
				self.wire.record(args.ClientId, time.Now(), wireBytes)
				select {
				case toExit <- wireBytes:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	sendTransport := connect.NewSendGatewayTransport()
	receiveTransport := connect.NewReceiveGatewayTransport()
	client.RouteManager().UpdateTransport(sendTransport, []connect.Route{written})
	client.RouteManager().UpdateTransport(receiveTransport, []connect.Route{fromExit})
	client.ContractManager().AddNoContractPeer(self.exit.ClientId())

	exitSendTransport := connect.NewSendClientTransport(connect.DestinationId(args.ClientId))
	exitReceiveTransport := connect.NewReceiveGatewayTransport()
	self.exit.RouteManager().UpdateTransport(exitReceiveTransport, []connect.Route{toExit})
	self.exit.RouteManager().UpdateTransport(exitSendTransport, []connect.Route{fromExit})
	self.exit.ContractManager().AddNoContractPeer(client.ClientId())

	unsub := func() {
		client.RouteManager().RemoveTransport(sendTransport)
		client.RouteManager().RemoveTransport(receiveTransport)
		self.exit.RouteManager().RemoveTransport(exitReceiveTransport)
		self.exit.RouteManager().RemoveTransport(exitSendTransport)
		client.Cancel()
	}
	self.mutex.Lock()
	self.windows = append(self.windows, tunnelWindowClient{client: client, mode: mode, made: made})
	self.unsubs[client] = unsub
	self.mutex.Unlock()
	return client, nil
}

func (self *tunnelGenerator) FixedDestinationSize() (int, bool) { return 1, true }
