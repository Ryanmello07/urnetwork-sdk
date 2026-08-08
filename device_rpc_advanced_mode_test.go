package sdk

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/urnetwork/connect"
)

// The advanced-mode bridge: the controls a desktop client needs to tune the
// sdk from a DeviceRemote, whose device lives in another process.
//
// Three things are pinned here that the reliability bridge does not cover:
//
//   - the fault injection actions (drop, stall/unstall) reach the local AND
//     report whether they found the exit, where the older action bridges
//     returned nothing at all;
//   - the probe suite round trips as a suite -- start, poll, results, stop --
//     including a results list read before any run, which is the empty-list
//     shape the c++ wrapper unwraps into a std::vector; and
//   - MigrateExit and ProbeAllExits carry their counts, which the bridge used
//     to drop on the floor.
//
// These are ordinary build-tag-free tests in the default compile set, and run
// on Windows as well as in the Linux sdk CI.

// gob wire fidelity for the new payloads

// TestRpcGobStallExitComplete covers the only reliability control that takes
// more than one argument. The false case is called out because gob omits
// zero-valued fields: if `Stalled` did not survive as false, "unstall" would
// arrive as "stall" and the control would be one-way.
func TestRpcGobStallExitComplete(t *testing.T) {
	clientId := connect.NewId()

	wiredStalled := gobRoundTrip(t, &DeviceRemoteStallExitRpc{
		ClientId: clientId,
		Stalled:  true,
	})
	connect.AssertEqual(t, wiredStalled.ClientId, clientId)
	connect.AssertEqual(t, wiredStalled.Stalled, true)

	wiredUnstalled := gobRoundTrip(t, &DeviceRemoteStallExitRpc{
		ClientId: clientId,
		Stalled:  false,
	})
	connect.AssertEqual(t, wiredUnstalled.ClientId, clientId)
	connect.AssertEqual(t, wiredUnstalled.Stalled, false)
}

func TestRpcGobProbeSuiteConfigComplete(t *testing.T) {
	seed := 0
	config := &ProbeSuiteConfig{}
	fillNonZero(t, reflect.ValueOf(config), &seed)

	wired := gobRoundTrip(t, &DeviceRemoteProbeSuiteConfigRpc{
		Config: config,
	})
	connect.AssertEqual(t, wired.Config, config)
}

// TestRpcGobProbeSuiteConfigNilCrossesWire pins the reason the config is
// wrapped at all: a nil config means "use the sdk default", and it has to
// arrive as nil so the handler can substitute the default. gob omits nil
// pointer fields, so decoding it back as a ZERO config would start a run with
// concurrency 0 and no probes enabled instead of the default suite.
func TestRpcGobProbeSuiteConfigNilCrossesWire(t *testing.T) {
	wired := gobRoundTrip(t, &DeviceRemoteProbeSuiteConfigRpc{Config: nil})
	connect.AssertEqual(t, wired.Config, nil)
}

func TestRpcMirrorProbeResultListPopulated(t *testing.T) {
	seed := 0
	results := NewProbeResultList()
	sourceResults := []*ProbeResult{}
	for range 3 {
		result := &ProbeResult{}
		fillNonZero(t, reflect.ValueOf(result), &seed)
		results.Add(result)
		sourceResults = append(sourceResults, result)
	}
	// a nil row must be skipped, not crash the encoder
	results.Add(nil)

	wired := gobRoundTrip(t, &DeviceRemoteProbeResultListRpc{
		Results: newProbeResultListRpc(results),
	})
	resultList := toProbeResultList(wired.Results)
	connect.AssertEqual(t, resultList.Len(), 3)
	for i, result := range sourceResults {
		connect.AssertEqual(t, resultList.Get(i), result)
	}
}

// TestRpcMirrorProbeResultListEmpty is the "no probes have run" shape, which
// is what a probe ui reads before its first run and therefore the single most
// likely thing to cross this bridge. A nil slice must arrive as an empty
// list, never as a nil one.
func TestRpcMirrorProbeResultListEmpty(t *testing.T) {
	// the nil list itself (what a device with no probe state would hand over)
	connect.AssertNotEqual(t, newProbeResultListRpc(nil), nil)
	connect.AssertEqual(t, len(newProbeResultListRpc(nil)), 0)

	wired := gobRoundTrip(t, &DeviceRemoteProbeResultListRpc{
		Results: newProbeResultListRpc(NewProbeResultList()),
	})
	resultList := toProbeResultList(wired.Results)
	connect.AssertNotEqual(t, resultList, nil)
	connect.AssertEqual(t, resultList.Len(), 0)
}

// TestExportedListEmptyMarshalsAsArray pins the fix for the fourth c-abi bug
// this client has found.
//
// Go marshals a nil slice as the document `null`, and every one of these
// lists starts with a nil backing slice. The generated c++ wrapper unwraps a
// list getter straight into a std::vector, and nlohmann throws
// type_error.302 converting `null` to an array -- so on a live session SEVEN
// of eleven list getters threw within milliseconds of the session coming up,
// because at that moment every list is empty.
//
// `[]` is the honest rendering of an empty list and the one every consumer
// can unwrap. The wrapper also tolerates `null` now, but this is the assertion
// that keeps the wire correct rather than merely survivable.
func TestExportedListEmptyMarshalsAsArray(t *testing.T) {
	// one list of each shape that crosses as json: the new probe list, a
	// struct list read at session start, and a scalar list
	emptyLists := map[string]any{
		"ProbeResultList":     NewProbeResultList(),
		"ExitList":            NewExitList(),
		"DestinationExitList": NewDestinationExitList(),
		"StringList":          NewStringList(),
	}
	for name, emptyList := range emptyLists {
		encoded, err := json.Marshal(emptyList)
		connect.AssertEqual(t, err, nil)
		if string(encoded) != "[]" {
			t.Fatalf("%s marshalled empty as %q, want \"[]\" (a `null` document throws type_error.302 in the c++ wrapper)", name, string(encoded))
		}
	}

	// a populated list is unaffected, and both forms decode back
	results := NewProbeResultList()
	results.Add(&ProbeResult{Name: "example.com", Kind: "dns", Ok: true})
	encoded, err := json.Marshal(results)
	connect.AssertEqual(t, err, nil)
	connect.AssertNotEqual(t, string(encoded), "[]")

	decoded := NewProbeResultList()
	connect.AssertEqual(t, json.Unmarshal([]byte("[]"), decoded), nil)
	connect.AssertEqual(t, decoded.Len(), 0)
	// the wire still accepts a `null` document from an older producer
	connect.AssertEqual(t, json.Unmarshal([]byte("null"), decoded), nil)
	connect.AssertEqual(t, decoded.Len(), 0)
}

// degraded shapes: the local with no multi client, and the remote with no
// service. Neither may return nil for a list, and each action reports the
// documented "nothing happened" value rather than pretending it worked.

func TestAdvancedModeDegradedWithoutMultiClient(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	networkSpace, byJwt, err := testing_newNetworkSpace(ctx)
	connect.AssertEqual(t, err, nil)

	settings := DefaultDeviceLocalSettings()
	settings.DisableLogging = true
	settings.AllowProvider = false
	deviceLocal, err := newDeviceLocalWithOverrides(
		networkSpace,
		byJwt,
		"",
		"",
		"",
		NewId(),
		settings,
		connect.NewId(),
	)
	connect.AssertEqual(t, err, nil)
	defer deviceLocal.Close()

	// the local path: no multi client to act on
	exitClientId := NewId()
	connect.AssertEqual(t, deviceLocal.DropExit(exitClientId), false)
	connect.AssertEqual(t, deviceLocal.StallExit(exitClientId, true), false)
	connect.AssertEqual(t, deviceLocal.StallExit(exitClientId, false), false)
	connect.AssertEqual(t, deviceLocal.MigrateExit(exitClientId), int32(-1))
	connect.AssertEqual(t, deviceLocal.ProbeAllExits(), int32(0))
	// a safe no-op rather than a panic
	deviceLocal.ShuffleExits()

	// the probe suite does not need a multi client to report its state
	connect.AssertEqual(t, deviceLocal.ProbeSuiteRunning(), false)
	localResults := deviceLocal.GetProbeResults()
	connect.AssertNotEqual(t, localResults, nil)
	connect.AssertEqual(t, localResults.Len(), 0)

	// the remote path with no service at all (the cold launch: the remote
	// exists from login, the service process is not up)
	deviceRemote := &DeviceRemote{}
	connect.AssertEqual(t, deviceRemote.DropExit(exitClientId.IdStr), false)
	connect.AssertEqual(t, deviceRemote.StallExit(exitClientId.IdStr, true), false)
	connect.AssertEqual(t, deviceRemote.StallExit(exitClientId.IdStr, false), false)
	connect.AssertEqual(t, deviceRemote.MigrateExit(exitClientId.IdStr), int32(-1))
	connect.AssertEqual(t, deviceRemote.ProbeAllExits(), int32(0))
	connect.AssertEqual(t, deviceRemote.StartProbeSuite(GetDefaultProbeSuiteConfig()), false)
	connect.AssertEqual(t, deviceRemote.ProbeSuiteRunning(), false)
	deviceRemote.StopProbeSuite()

	// a malformed id is rejected client side, with the same values
	connect.AssertEqual(t, deviceRemote.DropExit("not-an-id"), false)
	connect.AssertEqual(t, deviceRemote.StallExit("not-an-id", true), false)
	connect.AssertEqual(t, deviceRemote.MigrateExit("not-an-id"), int32(-1))

	// the readout degrades to empty, never nil -- this is the value that
	// reaches parseJson<ProbeResultList> on the c++ side
	remoteResults := deviceRemote.GetProbeResults()
	connect.AssertNotEqual(t, remoteResults, nil)
	connect.AssertEqual(t, remoteResults.Len(), 0)

	encoded, err := json.Marshal(remoteResults)
	connect.AssertEqual(t, err, nil)
	connect.AssertEqual(t, string(encoded), "[]")
}

// TestDeviceRemoteAdvancedModeActionsReachTheLocal asserts each new action
// bridge actually reached the DeviceLocal side rather than merely returning
// without error. No-oping any of the new DeviceLocalRpc handlers must fail
// this.
//
// The observable is the connect-side `[rel]` action log, as for the older
// actions. For the fault injection controls the log also carries the exit id
// (and, for stall, the flag), which is what pins the ARGUMENTS crossing the
// wire: string -> connect.Id -> *Id -> connect, and the bool alongside it.
func TestDeviceRemoteAdvancedModeActionsReachTheLocal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	networkSpace, byJwt, err := testing_newNetworkSpace(ctx)
	connect.AssertEqual(t, err, nil)

	clientId := connect.NewId()
	instanceId := NewId()

	actionLogger := &testingReliabilityActionLogger{}
	settings := testDeviceLocalSettingsRpc()
	// the capturing logger only reaches connect when logging is enabled
	settings.DisableLogging = false
	settings.ClientSettings.Log = actionLogger
	settings.AllowProvider = false
	settings.GeneratorFunc = func(specs []*connect.ProviderSpec) connect.MultiClientGenerator {
		return &rpcLeakTestGenerator{}
	}
	deviceLocal, err := newDeviceLocalWithOverrides(
		networkSpace,
		byJwt,
		"",
		"",
		"",
		instanceId,
		settings,
		clientId,
	)
	connect.AssertEqual(t, err, nil)
	defer deviceLocal.Close()

	upgradeMuxSettings := connect.DefaultUpgradeMuxSettings()
	upgradeMuxSettings.Dns = nil
	deviceLocal.SetUpgradeMuxSettings(upgradeMuxSettings)

	deviceRemote, err := newDeviceRemoteWithOverrides(
		networkSpace,
		byJwt,
		instanceId,
		defaultDeviceRpcSettings(),
		clientId,
		testing_deviceRpcDialerDefault(),
	)
	connect.AssertEqual(t, err, nil)
	defer deviceRemote.Close()

	// the actions need a multi client to act on
	deviceLocal.SetConnectLocation(testingReliabilityConnectLocation("advanced mode actions"))
	testingReliabilityWaitFor(t, "the remote reaches the local", func() bool {
		return deviceRemote.GetReliabilitySettings() != nil
	})

	// distinct exit ids per action: a shared id would let one action's log
	// line satisfy another's assertion, and the whole point of these
	// assertions is that each handler reached the local INDEPENDENTLY
	dropClientId := NewId()
	stallClientId := NewId()
	idTail := func(id *Id) string {
		return id.IdStr[len(id.IdStr)-8:]
	}

	// DropExit: the action ran AND the exit id arrived intact. The stub window
	// admits no clients, so the exit is not found and the bridge reports false
	// -- which is itself the return value crossing back.
	connect.AssertEqual(t, deviceRemote.DropExit(dropClientId.IdStr), false)
	testingReliabilityWaitFor(t, "drop_exit reached the local with its exit id", func() bool {
		return actionLogger.contains("drop_exit", "exit="+idTail(dropClientId))
	})

	// StallExit in both directions: stall and unstall must each reach the
	// local, since an unstall that arrives as a stall would leave the exit
	// swallowing packets with no way back. The `[rel]` grammar renders bools
	// as 1/0 (see connect's relValue: `stalled=1` greps cleanly where
	// `stalled=true` is a prefix of nothing useful), so the flag is what
	// distinguishes the two lines.
	connect.AssertEqual(t, deviceRemote.StallExit(stallClientId.IdStr, true), false)
	testingReliabilityWaitFor(t, "stall_exit(stalled) reached the local", func() bool {
		return actionLogger.contains("stall_exit", "exit="+idTail(stallClientId), "stalled=1")
	})

	connect.AssertEqual(t, deviceRemote.StallExit(stallClientId.IdStr, false), false)
	testingReliabilityWaitFor(t, "stall_exit(unstalled) reached the local", func() bool {
		return actionLogger.contains("stall_exit", "exit="+idTail(stallClientId), "stalled=0")
	})

	// the counts the bridge used to drop. Against a stub window these are the
	// documented "nothing to do" values, but they are now VALUES rather than
	// void -- see TestDeviceRemoteProbeSuiteBridge for a non-sentinel result
	// crossing the same machinery.
	connect.AssertEqual(t, deviceRemote.MigrateExit(dropClientId.IdStr), int32(-1))
	connect.AssertEqual(t, deviceRemote.ProbeAllExits(), int32(0))
	testingReliabilityWaitFor(t, "probe_all reached the local", func() bool {
		return actionLogger.contains("probe_all")
	})

	// Shuffle is the whole-window action; there is deliberately no separate
	// ShuffleExits bridge, since DeviceLocal.ShuffleExits and
	// DeviceLocal.Shuffle both end at RemoteUserNatMultiClient.Shuffle
	deviceRemote.Shuffle()
	testingReliabilityWaitFor(t, "shuffle reached the local", func() bool {
		return actionLogger.contains("shuffle")
	})

	// malformed ids are rejected client-side and never reach the local
	dropCount := actionLogger.count("drop_exit")
	stallCount := actionLogger.count("stall_exit")
	connect.AssertEqual(t, deviceRemote.DropExit("not-an-id"), false)
	connect.AssertEqual(t, deviceRemote.StallExit("not-an-id", true), false)
	select {
	case <-time.After(500 * time.Millisecond):
	}
	connect.AssertEqual(t, actionLogger.count("drop_exit"), dropCount)
	connect.AssertEqual(t, actionLogger.count("stall_exit"), stallCount)
}

// TestDeviceRemoteProbeSuiteBridge runs the probe suite as a suite across the
// bridge: start, poll, read results, stop.
//
// This is the test that proves a return value genuinely crosses the wire
// rather than being confused with a fallback. Every other control here
// reports its "nothing happened" value against a stub window, and those are
// the same values a dead rpc returns. `StartProbeSuite` returns TRUE on a
// fresh device, which no failure path can produce: a down rpc, an
// unresolvable handle and an already-running suite all return false.
//
// The suite is configured with every probe kind off, so it builds zero jobs
// and touches no network -- the run exists to move the running flag, not to
// measure anything.
func TestDeviceRemoteProbeSuiteBridge(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	networkSpace, byJwt, err := testing_newNetworkSpace(ctx)
	connect.AssertEqual(t, err, nil)

	clientId := connect.NewId()
	instanceId := NewId()

	deviceLocal := testingNewReliabilityDeviceLocal(t, networkSpace, byJwt, instanceId, clientId)
	defer deviceLocal.Close()

	deviceRemote, err := newDeviceRemoteWithOverrides(
		networkSpace,
		byJwt,
		instanceId,
		defaultDeviceRpcSettings(),
		clientId,
		testing_deviceRpcDialerDefault(),
	)
	connect.AssertEqual(t, err, nil)
	defer deviceRemote.Close()

	testingReliabilityWaitFor(t, "the remote reaches the local", func() bool {
		return deviceRemote.GetRemoteConnected()
	})

	// before any run: both ends agree nothing is running, and the results
	// list is empty and NOT nil. This is the exact value a probe ui reads on
	// first paint, and the one that used to reach the c++ wrapper as `null`.
	connect.AssertEqual(t, deviceLocal.ProbeSuiteRunning(), false)
	testingReliabilityWaitFor(t, "the remote reports the suite is not running", func() bool {
		return !deviceRemote.ProbeSuiteRunning()
	})
	initialResults := deviceRemote.GetProbeResults()
	connect.AssertNotEqual(t, initialResults, nil)
	connect.AssertEqual(t, initialResults.Len(), 0)
	encoded, err := json.Marshal(initialResults)
	connect.AssertEqual(t, err, nil)
	connect.AssertEqual(t, string(encoded), "[]")

	// no jobs, no network: the run exists to move the flag
	config := &ProbeSuiteConfig{
		Concurrency:     1,
		TimeoutMillis:   1000,
		RepeatCount:     1,
		IncludeDns:      false,
		IncludeHttp:     false,
		IncludeDownload: false,
	}

	// TRUE across the bridge -- the assertion no fallback can satisfy
	connect.AssertEqual(t, deviceRemote.StartProbeSuite(config), true)

	// the start reached the DeviceLocal side: only the local owns the suite
	// state, so the local observing a run is proof the handler ran there
	testingReliabilityWaitFor(t, "the suite started on the local", func() bool {
		return deviceLocal.ProbeSuiteRunning() || 0 < deviceLocal.GetProbeResults().Len()
	})

	// stop, and both ends settle on not-running
	deviceRemote.StopProbeSuite()
	testingReliabilityWaitFor(t, "the suite stops on the local", func() bool {
		return !deviceLocal.ProbeSuiteRunning()
	})
	testingReliabilityWaitFor(t, "the remote reports the suite stopped", func() bool {
		return !deviceRemote.ProbeSuiteRunning()
	})

	// results after a run cross the bridge as the same list the local holds,
	// whatever the harness made of a zero-job run
	localResults := deviceLocal.GetProbeResults()
	remoteResults := deviceRemote.GetProbeResults()
	connect.AssertNotEqual(t, remoteResults, nil)
	connect.AssertEqual(t, remoteResults.Len(), localResults.Len())
	for i := range localResults.Len() {
		connect.AssertEqual(t, remoteResults.Get(i), localResults.Get(i))
	}

	// The nil config ("use the sdk default") is deliberately NOT exercised
	// live here: the default suite probes real dns and http targets, and a
	// test that reaches the network to prove an argument default is a worse
	// trade than the two tests that already pin it --
	// TestRpcGobProbeSuiteConfigNilCrossesWire (nil survives the wire as nil,
	// rather than decoding as a zero config that would run nothing) and
	// TestDeviceLocalRpcStartProbeSuiteDefaultsNilConfig (the handler
	// substitutes the default rather than passing nil to a DeviceLocal that
	// would dereference it).
}

// TestDeviceLocalRpcStartProbeSuiteDefaultsNilConfig pins the handler-side
// half of the nil-config contract without starting a run.
//
// `DeviceLocal.StartProbeSuite` dereferences its config in `buildProbeJobs`,
// so a nil arriving from the wire would panic inside the service process --
// the caller would see a dead rpc, not a bad argument. The handler
// substitutes the sdk default instead.
func TestDeviceLocalRpcStartProbeSuiteDefaultsNilConfig(t *testing.T) {
	// the substitution the handler actually performs
	config := (&DeviceRemoteProbeSuiteConfigRpc{Config: nil}).configOrDefault()
	connect.AssertNotEqual(t, config, nil)
	connect.AssertEqual(t, config, GetDefaultProbeSuiteConfig())

	// a supplied config is passed through untouched
	supplied := &ProbeSuiteConfig{Concurrency: 7, TimeoutMillis: 1234, RepeatCount: 2}
	connect.AssertEqual(t, (&DeviceRemoteProbeSuiteConfigRpc{Config: supplied}).configOrDefault(), supplied)

	// and the decoded-from-wire nil path, end to end
	wired := gobRoundTrip(t, &DeviceRemoteProbeSuiteConfigRpc{Config: nil})
	connect.AssertEqual(t, wired.configOrDefault(), GetDefaultProbeSuiteConfig())

	// and the default is a config that would actually probe something -- a
	// zero config (what a lost nil would decode to) builds no jobs at all
	connect.AssertEqual(t, 0 < len(buildProbeJobs(config)), true)
	connect.AssertEqual(t, len(buildProbeJobs(&ProbeSuiteConfig{})), 0)
}
