package cp3b

import (
	"bytes"
	"context"
	"crypto/rand"
	"path/filepath"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/message-server/api"
	"github.com/urnetwork/message-server/peer"
	"github.com/urnetwork/message-server/store"
	"github.com/urnetwork/sdk"
	"github.com/urnetwork/sdk/urmessage"
)

// THE WORLD: ONE RUNNING MESSAGE SERVER AND AS MANY REAL CLIENTS AS A CASE ASKS FOR.
//
// The server half is the real one and not a double: `peer.Peer` dispatching §4.2 frames,
// `api.Handler` running §5.1's pipeline with `peer.Checks` as its front, and `store.MemoryStore`
// behind it. It is wired the way `msgrepo/cmd/message-server/stack_test.go` wires it, because
// `connect` has no inbound listener for client frames -- an in-process `connect.Route` and a
// `connect.PlatformTransport` dialling `wss://connect.<host>` are the only two ways a
// `connect.Client` ever receives one, and the second needs an operator-minted `ByJwt` per spec B
// §9.1. See urmessage's package document for the whole of the S2-7 decision.
//
// The CLIENT half is NOT this file's. Every client speaks through `sdk.MessageTransport` and
// `urmessage`, which is the code under test; nothing here builds a frame, computes an
// authenticator or seals a record.
type world struct {
	ctx    context.Context
	cancel context.CancelFunc

	serverClient *connect.Client
	store        *store.MemoryStore
	peer         *peer.Peer
	handler      *api.Handler

	// the decorator in front of the store, when this world has one. A case reaches it to say
	// WHICH record is bent and for how long, which is not something worldOptions can carry: the
	// record ids do not exist until the group has been founded through this very server.
	shaped *shapedStore
}

const worldProtocolVersion = 1

// worldOptions are the two things a case may need the server configured differently for. Both
// default to the server's own default, so a case that says nothing gets the deployed shape.
type worldOptions struct {
	// §4.3.1's `max_records_per_fetch`. A small number here is an ORDINARY OPERATOR SETTING
	// and not a test seam: the server advertises whatever it is configured with, and a page
	// truncated by it is what §4.3.4 calls NORMAL. It is how a case reaches the truncation
	// path without writing 512 messages.
	maxRecordsPerFetch int

	// What the server ADVERTISES about §4.3.4. This build signs nothing whatever it says here
	// (msgrepo/api/fetch.go:112), so setting it true is a server that claims to sign and does
	// not -- which is the downgrade a client must refuse.
	attestationSupported bool

	// How the fetch RESULT is bent on its way out of the store, and nothing else about the
	// server. See [shapedStore]: the group is still founded, opened and written through the
	// real §6.1 transaction.
	fetchShape fetchShape
}

func newWorld(t *testing.T) *world {
	t.Helper()
	return newWorldWith(t, worldOptions{})
}

func newWorldWith(t *testing.T, options worldOptions) *world {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	settings := connect.DefaultClientSettings()
	serverClient := connect.NewClient(ctx, connect.NewId(), connect.NewNoContractClientOob(), settings)

	connections, err := peer.NewConnections(rand.Reader, time.Now, time.Hour)
	if err != nil {
		cancel()
		t.Fatalf("peer.NewConnections: %v", err)
	}
	checks, err := peer.NewChecks(connections, peer.DefaultMaxRequestBytes)
	if err != nil {
		cancel()
		t.Fatalf("peer.NewChecks: %v", err)
	}
	memory := store.NewMemoryStore(store.DefaultLimits())
	var backing store.Store = memory
	var shaped *shapedStore
	if options.fetchShape != fetchNormal {
		shaped = &shapedStore{Store: memory, shape: options.fetchShape}
		backing = shaped
	}
	handler, err := api.New(api.Config{
		Store:              backing,
		KnownGroups:        api.NewMemoryKnownGroups(),
		Front:              checks,
		MaxRecordsPerFetch: options.maxRecordsPerFetch,
	})
	if err != nil {
		cancel()
		t.Fatalf("api.New: %v", err)
	}
	served, err := peer.New(peer.Config{
		Client:      serverClient,
		Handler:     handler,
		Connections: connections,
		Checks:      checks,
		Capabilities: &protocol.Capabilities{
			MaxRequestBytes:      peer.DefaultMaxRequestBytes,
			MaxRecordsPerFetch:   uint32(options.maxRecordsPerFetch),
			AttestationSupported: options.attestationSupported,
		},
		ProtocolVersion: worldProtocolVersion,
		ServerId:        bytes.Repeat([]byte{0x5A}, 16),
	})
	if err != nil {
		cancel()
		t.Fatalf("peer.New: %v", err)
	}

	current := &world{
		ctx:          ctx,
		cancel:       cancel,
		serverClient: serverClient,
		store:        memory,
		peer:         served,
		handler:      handler,
		shaped:       shaped,
	}
	t.Cleanup(func() {
		served.Close()
		serverClient.Close()
		cancel()
	})
	return current
}

// connectClient stands up one more real `connect.Client` and routes it to the server, both ways.
//
// No network space, no operator and no ByJwt: `NewNoContractClientOob` plus `AddNoContractPeer` is
// what removes the contract requirement, which is why connect's own data-path tests run offline
// and why these do. The two routes are plain channels, one per direction, and they are this
// client's own -- so two clients of one world do not share a wire.
func (self *world) connectClient(t *testing.T) *connect.Client {
	t.Helper()
	client := connect.NewClient(self.ctx, connect.NewId(), connect.NewNoContractClientOob(),
		connect.DefaultClientSettings())
	toServer := make(connect.Route)
	toClient := make(connect.Route)
	client.RouteManager().UpdateTransport(connect.NewSendGatewayTransport(), []connect.Route{toServer})
	client.RouteManager().UpdateTransport(connect.NewReceiveGatewayTransport(), []connect.Route{toClient})
	client.ContractManager().AddNoContractPeer(self.serverClient.ClientId())
	self.serverClient.RouteManager().UpdateTransport(
		connect.NewSendClientTransport(connect.DestinationId(client.ClientId())), []connect.Route{toClient})
	self.serverClient.RouteManager().UpdateTransport(
		connect.NewReceiveGatewayTransport(), []connect.Route{toServer})
	self.serverClient.ContractManager().AddNoContractPeer(client.ClientId())
	t.Cleanup(client.Close)
	return client
}

// transport is one §10.1 binding over a connect client, built through the exported door package
// sdk publishes.
func (self *world) transport(t *testing.T, client *connect.Client) *sdk.MessageTransport {
	t.Helper()
	transport, err := sdk.NewMessageTransport(&sdk.MessageTransportConfig{
		Client:          client,
		Server:          self.serverClient.ClientId(),
		ProtocolVersion: worldProtocolVersion,
		Timeout:         30 * time.Second,
	})
	if err != nil {
		t.Fatalf("sdk.NewMessageTransport: %v", err)
	}
	t.Cleanup(transport.Close)
	return transport
}

// device is one whole client: its own connect client, its own transport, its own DURABLE stream
// store on disk, and the urmessage device over them.
//
// THE STREAM STORE IS THE REAL ONE AND IT IS PER DEVICE. `sdk.OpenStreamStore` fsyncs a row before
// it returns an index and holds a single-writer exclusion over its directory, which is why each
// device gets a directory of its own rather than a shared one: two devices are two processes in
// every deployment that matters, and a fixture that shared a store would be testing a shape
// nothing ships.
func (self *world) device(t *testing.T, name string) (*urmessage.Device, *connect.Client, *sdk.MessageTransport) {
	t.Helper()
	client := self.connectClient(t)
	transport := self.transport(t, client)
	streamStore, err := sdk.OpenStreamStore(t.TempDir())
	if err != nil {
		t.Fatalf("%s: sdk.OpenStreamStore: %v", name, err)
	}
	t.Cleanup(func() { streamStore.Close() })
	reserver := sdk.NewStreamIndexReserver(streamStore)
	if reserver == nil {
		t.Fatalf("%s: sdk.NewStreamIndexReserver answered no reserver over a live store", name)
	}
	device, err := urmessage.NewDevice(urmessage.DeviceConfig{
		Transport: transport,
		Reserver:  reserver,
	})
	if err != nil {
		t.Fatalf("%s: urmessage.NewDevice: %v", name, err)
	}
	t.Cleanup(func() { device.Close() })
	return device, client, transport
}

// newGroupId is 32 octets of CSPRNG, which is what the server keys its rows by.
func newGroupId(t *testing.T) []byte {
	t.Helper()
	groupId := make([]byte, urmessage.GroupIdBytes)
	if _, err := rand.Read(groupId); err != nil {
		t.Fatalf("drawing a group id: %v", err)
	}
	return groupId
}

// ── a device that can be killed and started again ────────────────────────────────────────────

// persona is one device together with the TWO DIRECTORIES that are the only thing that survives
// its death: the durable stream store the reserver allocates out of, and the durable MLS state
// store S2-14 added.
//
// It exists so that a restart can be written as what it is -- everything in memory dropped, the
// same two directories reopened -- rather than as a device that keeps a pointer to something the
// previous run held. Nothing crosses [world.restart] except the two path strings and the name.
type persona struct {
	name      string
	stateDir  string
	streamDir string

	client      *connect.Client
	transport   *sdk.MessageTransport
	streamStore *sdk.StreamStore
	stateStore  *urmessage.DurableStateStore
	device      *urmessage.Device

	dead bool
}

// durablePersona stands one up over two directories of the caller's choosing.
func (self *world) durablePersona(t *testing.T, name string, stateDir string, streamDir string) *persona {
	t.Helper()
	client := self.connectClient(t)
	transport := self.transport(t, client)
	streamStore, err := sdk.OpenStreamStore(streamDir)
	if err != nil {
		t.Fatalf("%s: sdk.OpenStreamStore(%s): %v", name, streamDir, err)
	}
	stateStore, err := urmessage.OpenDurableStateStore(stateDir)
	if err != nil {
		streamStore.Close()
		t.Fatalf("%s: urmessage.OpenDurableStateStore(%s): %v", name, stateDir, err)
	}
	device, err := urmessage.NewDevice(urmessage.DeviceConfig{
		Transport:  transport,
		Reserver:   sdk.NewStreamIndexReserver(streamStore),
		StateStore: stateStore,
	})
	if err != nil {
		stateStore.Close()
		streamStore.Close()
		t.Fatalf("%s: urmessage.NewDevice: %v", name, err)
	}
	current := &persona{
		name: name, stateDir: stateDir, streamDir: streamDir,
		client: client, transport: transport,
		streamStore: streamStore, stateStore: stateStore, device: device,
	}
	t.Cleanup(current.kill)
	return current
}

// newPersona is durablePersona over two fresh directories.
func (self *world) newPersona(t *testing.T, name string) *persona {
	t.Helper()
	root := t.TempDir()
	return self.durablePersona(t, name,
		filepath.Join(root, name, "state"), filepath.Join(root, name, "stream"))
}

// kill drops everything this device holds in memory and releases both single-writer exclusions.
//
// IT IS THE WHOLE OF WHAT "THE USER CLOSED THE APP" MEANS HERE. Both stores are closed, so the
// next opener has to acquire the exclusions again -- which is also what says the previous run
// really let go of them rather than the test merely forgetting about it.
func (self *persona) kill() {
	if self.dead {
		return
	}
	self.dead = true
	self.device.Close()
	self.stateStore.Close()
	self.streamStore.Close()
	self.transport.Close()
	self.client.Close()
}

// restart kills this device and opens a NEW one over the same two directories.
//
// THE ONLY THING THAT CROSSES IS THE DISK. The returned persona has a new connect client, a new
// transport, a new crypto provider, a new engine and a new device; it shares no pointer with the
// one that was killed. A restore that worked because something stayed in memory could not pass
// through this function.
func (self *world) restart(t *testing.T, previous *persona) *persona {
	t.Helper()
	name, stateDir, streamDir := previous.name, previous.stateDir, previous.streamDir
	previous.kill()
	return self.durablePersona(t, name, stateDir, streamDir)
}
