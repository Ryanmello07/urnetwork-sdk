package cp3b

import (
	"bytes"
	"context"
	"crypto/rand"
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
}

const worldProtocolVersion = 1

func newWorld(t *testing.T) *world {
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
	handler, err := api.New(api.Config{
		Store:       memory,
		KnownGroups: api.NewMemoryKnownGroups(),
		Front:       checks,
	})
	if err != nil {
		cancel()
		t.Fatalf("api.New: %v", err)
	}
	served, err := peer.New(peer.Config{
		Client:          serverClient,
		Handler:         handler,
		Connections:     connections,
		Checks:          checks,
		Capabilities:    &protocol.Capabilities{MaxRequestBytes: peer.DefaultMaxRequestBytes},
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
