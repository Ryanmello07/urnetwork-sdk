package sdk

import (
	"context"
	"testing"

	"github.com/urnetwork/connect"
)

// newTestingConnectViewController builds the bare view controller the grid
// tests use (see connect_grid_reconcile_test.go).
func newTestingConnectViewController(ctx context.Context) *ConnectViewController {
	return &ConnectViewController{
		ctx:                       ctx,
		device:                    nil,
		selectedLocationListeners: connect.NewCallbackList[SelectedLocationListener](),
		connectionStatusListeners: connect.NewCallbackList[ConnectionStatusListener](),
		gridListeners:             connect.NewCallbackList[GridListener](),
	}
}

// TestConnectGridGenerationGate is the D2 phantom-green defense: once the user
// has issued a disconnect (or a new connect), window-monitor events from the
// outgoing session generation must not recompute the grid status. The field
// capture shows the owner's grid flashing CONNECTED +424ms and +1.37s AFTER
// his disconnect click — the outgoing window's monitor events ride an async
// worker and land exactly when teardown un-sticks the control plane.
func TestConnectGridGenerationGate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	vc := newTestingConnectViewController(ctx)
	grid := newConnectGridWithDefaults(ctx, vc)
	defer grid.close()
	grid.generation = vc.generation

	monitor := newTestingGridWindowMonitor()
	grid.listenToWindow(monitor)

	// the window satisfies its minimum: the grid computes Connected
	a := connect.NewId()
	func() {
		monitor.mu.Lock()
		defer monitor.mu.Unlock()
		monitor.windowExpandEvent = connect.WindowExpandEvent{TargetSize: 2, MinSatisfied: true}
	}()
	monitor.emit(map[connect.Id]*connect.ProviderEvent{
		a: {ClientId: a, State: connect.ProviderStateAdded},
	})
	connect.AssertEqual(t, vc.GetConnectionStatus(), Connected)

	// the user disconnects: the generation moves on, and the same late event
	// from the outgoing session must change NOTHING — not the status, not the
	// dots
	vc.setConnectionStatus(Disconnected)
	vc.bumpGeneration()
	pointsBefore := grid.GetProviderGridPointList().Len()

	b := connect.NewId()
	monitor.emit(map[connect.Id]*connect.ProviderEvent{
		b: {ClientId: b, State: connect.ProviderStateAdded},
	})
	connect.AssertEqual(t, vc.GetConnectionStatus(), Disconnected)
	connect.AssertEqual(t, grid.GetProviderGridPointList().Len(), pointsBefore)

	// a grid created under the NEW generation is live again
	grid2 := newConnectGridWithDefaults(ctx, vc)
	defer grid2.close()
	grid2.generation = vc.generation
	grid2.listenToWindow(monitor)
	connect.AssertEqual(t, vc.GetConnectionStatus(), Connected)
}

// TestConnectGridFailedStatus maps the window honesty layer's terminal
// outcome onto the connection status: Failed (zero Added past both outcome
// deadlines) renders CONNECT_FAILED, and a satisfied window always wins.
func TestConnectGridFailedStatus(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	vc := newTestingConnectViewController(ctx)
	grid := newConnectGridWithDefaults(ctx, vc)
	defer grid.close()

	monitor := newTestingGridWindowMonitor()
	grid.listenToWindow(monitor)

	func() {
		monitor.mu.Lock()
		defer monitor.mu.Unlock()
		monitor.windowExpandEvent = connect.WindowExpandEvent{
			TargetSize:   2,
			MinSatisfied: false,
			Reason:       connect.WindowStallProvidersUnresponsive,
			Failed:       true,
		}
	}()
	monitor.emit(map[connect.Id]*connect.ProviderEvent{})
	connect.AssertEqual(t, vc.GetConnectionStatus(), ConnectFailed)

	// a provider landing (min satisfied) overrides the failed latch
	func() {
		monitor.mu.Lock()
		defer monitor.mu.Unlock()
		monitor.windowExpandEvent = connect.WindowExpandEvent{
			TargetSize:   2,
			MinSatisfied: true,
			// the connect side clears Failed on an Added, but even a stale
			// combination must render Connected
			Failed: true,
		}
	}()
	a := connect.NewId()
	monitor.emit(map[connect.Id]*connect.ProviderEvent{
		a: {ClientId: a, State: connect.ProviderStateAdded},
	})
	connect.AssertEqual(t, vc.GetConnectionStatus(), Connected)
}

// TestToWindowStatusCarriesStallDiagnosis pins the WindowStatus rpc surface:
// the stall reason and the failed latch cross from the connect monitor into
// the struct DeviceRemote reads (GetWindowStatus and the change listener both
// carry it, so the app sees the same diagnosis as DeviceLocal).
func TestToWindowStatusCarriesStallDiagnosis(t *testing.T) {
	monitor := connect.NewRemoteUserNatMultiClientMonitorWithDefaults()

	windowStatus := toWindowStatus(monitor)
	connect.AssertEqual(t, windowStatus.StallReason, connect.WindowStallEvaluating)
	connect.AssertEqual(t, windowStatus.Failed, false)

	monitor.SetStallStatus(connect.WindowStallPlatformUnreachable, true)
	windowStatus = toWindowStatus(monitor)
	connect.AssertEqual(t, windowStatus.StallReason, connect.WindowStallPlatformUnreachable)
	connect.AssertEqual(t, windowStatus.Failed, true)
}

// TestDeviceLocalRpcWindowMonitorGenerationTag is the D10 stale-monitor
// hardening: a monitor callback subscribed under an older window generation
// must not forward its events to remote listeners — the local monitor was
// replaced (destination change) and the event belongs to the outgoing window.
func TestDeviceLocalRpcWindowMonitorGenerationTag(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rpc := &DeviceLocalRpc{
		ctx:                           ctx,
		sendPending:                   map[string]func(){},
		sendSignal:                    make(chan struct{}, 1),
		windowMonitorEventListenerIds: map[connect.Id]map[connect.Id]bool{},
		localWindowIds:                map[connect.Id]connect.Id{},
	}

	current := connect.NewId()
	stale := connect.NewId()
	rpc.localWindowId = current

	expand := &connect.WindowExpandEvent{TargetSize: 3}

	// an event through a subscription from the outgoing generation: dropped
	rpc.windowMonitorCallbackFor(stale)(expand, nil, false)
	rpc.sendMu.Lock()
	pendingAfterStale := len(rpc.sendPending)
	rpc.sendMu.Unlock()
	connect.AssertEqual(t, pendingAfterStale, 0)

	// the same event through the current generation: forwarded
	rpc.windowMonitorCallbackFor(current)(expand, nil, false)
	rpc.sendMu.Lock()
	pendingAfterCurrent := len(rpc.sendPending)
	rpc.sendMu.Unlock()
	connect.AssertEqual(t, pendingAfterCurrent, 1)
}
