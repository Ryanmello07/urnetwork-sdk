//go:build !js && !ios_extension

package walletconnect

// The transport is tested against the relay of relaytest in a synctest
// bubble, so the waits below take no real time and are exact. Config.Now is
// the bubble's clock plus an offset that a test can jump: a jump with no tick
// in between is what a suspension looks like to the loop (design B.3 R2).
//
// A bubble cannot end while a goroutine is left in it, so every test also
// shows that the transport leaves none behind.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/urnetwork/sdk/walletconnect/relaytest"
	"github.com/urnetwork/sdk/walletconnect/wire"
)

const (
	comHost     = "relay.walletconnect.com"
	orgHost     = "relay.walletconnect.org"
	originBody  = `{"error":"Unauthorized: origin not allowed"}`
	projectBody = `{"error":"Project not found"}`
	// the relay answers a subscribe after this long
	latency = 20 * time.Millisecond
	quiet   = 500 * time.Millisecond
)

var (
	topicA = strings.Repeat("a", 64)
	topicB = strings.Repeat("b", 64)
	topicC = strings.Repeat("c", 64)
	topicD = strings.Repeat("d", 64)
)

// sameBytes is a random source that gives zeros: two ids of one millisecond
// are equal unless the transport keeps them apart.
type sameBytes struct{}

func (sameBytes) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// harness is a transport on a relay, and the handler that writes down what
// the transport tells it.
type harness struct {
	t      *testing.T
	relay  *relaytest.Relay
	tr     *transport
	done   chan struct{} // closed when run returned
	start  time.Time
	offset atomic.Int64 // milliseconds Config.Now is ahead of the bubble's clock

	mu    sync.Mutex
	log   []string
	dials []time.Duration // when each dial began, since start
	ticks int

	frames int // frames of the relay's record already looked at
	// hooks that run on the loop; a test sets them before what calls them
	open    func()
	message func(topic string)
}

// bubble runs f with a relay and a transport on it.
func bubble(t *testing.T, options relaytest.RelayOptions, edit func(h *harness, config *Config), f func(t *testing.T, h *harness)) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		relay := relaytest.NewRelay(options)
		defer relay.Close()
		h := &harness{t: t, relay: relay, done: make(chan struct{}), start: time.Now()}
		config := &Config{
			ProjectId: "test-project",
			Now:       func() int64 { return time.Now().UnixMilli() + h.offset.Load() },
			DialTLS: func(ctx context.Context, network string, address string) (net.Conn, error) {
				h.mu.Lock()
				h.dials = append(h.dials, time.Since(h.start))
				h.mu.Unlock()
				return relay.DialTLS(ctx, network, address)
			},
		}
		if edit != nil {
			edit(h, config)
		}
		ctx, cancel := context.WithCancel(context.Background())
		h.tr = newTransport(ctx, config.withDefaults(), h)
		go func() {
			defer close(h.done)
			h.tr.run()
		}()
		defer func() {
			cancel()
			<-h.done
		}()
		f(t, h)
	})
}

func (h *harness) note(format string, args ...any) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.log = append(h.log, fmt.Sprintf(format, args...))
}

func (h *harness) onRead(seq int64)           { h.note("read %d", seq) }
func (h *harness) onConnected(connected bool) { h.note("connected %t", connected) }
func (h *harness) onFirstWrite(e *publishEntry) {
	h.note("written %v on %s tag %d", e.data, e.topic[:4], e.tag)
}
func (h *harness) onAcked(e *publishEntry)  { h.note("acked %v", e.data) }
func (h *harness) onGiveUp(e *publishEntry) { h.note("gave up %v", e.data) }
func (h *harness) onFatal(err *Error)       { h.note("fatal %s %d", err.Kind, err.Code) }

func (h *harness) onOpen() {
	h.note("open")
	if h.open != nil {
		h.open()
	}
}

func (h *harness) onMessage(topic string, message string, tag int) {
	h.note("message %s %s %d", topic[:4], message, tag)
	if h.message != nil {
		h.message(topic)
	}
}

func (h *harness) onTick(runningSeconds int64, resumed bool) {
	h.mu.Lock()
	h.ticks++
	h.mu.Unlock()
	if resumed {
		h.note("resumed")
	}
}

// do runs f on the loop and waits until the bubble is at rest.
func (h *harness) do(f func(tr *transport)) {
	h.tr.do(func() { f(h.tr) })
	synctest.Wait()
}

// wait lets d pass.
func (h *harness) wait(d time.Duration) {
	time.Sleep(d)
	synctest.Wait()
}

// told is what the handler was told since the last call.
func (h *harness) told() []string {
	synctest.Wait()
	h.mu.Lock()
	defer h.mu.Unlock()
	log := h.log
	h.log = nil
	return log
}

func (h *harness) dialed() []time.Duration {
	synctest.Wait()
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.dials)
}

func (h *harness) ticked() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.ticks
}

func (h *harness) stopped() bool {
	synctest.Wait()
	select {
	case <-h.done:
		return true
	default:
		return false
	}
}

// seen is what the relay took from and gave to the transport's sockets since
// the last call, one line for each frame: the ordinal of the socket, ">" for
// a frame of the transport, and what it is.
func (h *harness) seen() []string {
	synctest.Wait()
	frames := h.relay.Frames("")
	lines := []string{}
	for _, frame := range frames[h.frames:] {
		lines = append(lines, line(frame))
	}
	h.frames = len(frames)
	return lines
}

func line(frame relaytest.RecordedFrame) string {
	direction, text := "<", frame.Text
	if frame.ToRelay {
		direction = ">"
	}
	if parsed, err := wire.ParseFrame([]byte(frame.Text)); err == nil {
		var params struct {
			Topic   string
			Message string
			Data    wire.SubscriptionData
		}
		json.Unmarshal(parsed.Params, &params)
		switch {
		case parsed.Method == wire.MethodSubscription:
			text = "push " + params.Data.Topic[:4] + " " + params.Data.Message
		case parsed.Method == wire.MethodPublish:
			text = parsed.Method + " " + params.Topic[:4] + " " + params.Message
		case parsed.IsRequest():
			text = parsed.Method + " " + params.Topic[:4]
		case parsed.Error != nil:
			text = fmt.Sprintf("error %d", parsed.Error.Code)
		case frame.ToRelay:
			text = "ack"
		default:
			text = "result"
		}
	}
	return fmt.Sprintf("%d%s %s", frame.Socket, direction, text)
}

func (h *harness) expect(what string, got []string, want ...string) {
	h.t.Helper()
	if !slices.Equal(got, want) {
		h.t.Fatalf("%s:\n got  %q\n want %q", what, got, want)
	}
}

// connect holds the topics, wants a socket and waits for the first sync.
func (h *harness) connect(topics ...string) {
	h.t.Helper()
	h.do(func(tr *transport) {
		for _, topic := range topics {
			tr.addTopic(topic)
		}
		tr.setWanted(true)
	})
	h.wait(latency)
	h.expect("the first sync", h.told(), "open", "connected true", "read 1")
	h.seen()
}

// within reports whether got is want give or take the jitter of a back-off.
func within(got time.Duration, want time.Duration) bool {
	return got >= want*8/10 && got <= want*12/10
}

// TT1 (R15): what a dial presents to the relay.
func TestTransportHandshake(t *testing.T) {
	for _, row := range []struct{ name, value, bundleId, packageName string }{
		{"bundleId", "network.ur", "network.ur", ""},
		{"packageName", "com.bringyour.network", "", "com.bringyour.network"},
		{"bundleId", "", "", ""},
	} {
		t.Run(row.name+"="+row.value, func(t *testing.T) {
			options := relaytest.RelayOptions{BundleIds: []string{"network.ur"}, PackageNames: []string{"com.bringyour.network"}}
			bubble(t, options, func(h *harness, config *Config) {
				config.IdentifierName, config.IdentifierValue = row.name, row.value
				h.offset.Store(90_000)
			}, func(t *testing.T, h *harness) {
				h.do(func(tr *transport) { tr.setWanted(true) })
				handshakes := h.relay.Handshakes()
				if len(handshakes) != 1 || handshakes[0].Status != 101 {
					t.Fatalf("handshakes: %+v", handshakes)
				}
				seen := handshakes[0]
				token, bearer := strings.CutPrefix(seen.Header.Get("Authorization"), "Bearer ")
				claims, err := wire.VerifyToken(token)
				if !bearer || err != nil {
					t.Fatalf("no bearer token that verifies: %v", err)
				}
				now := time.Now().Unix() + 90
				query := map[string][]string{"projectId": {"test-project"}}
				if row.value != "" {
					query[row.name] = []string{row.value}
				}
				switch {
				case seen.Header["Origin"] != nil:
					t.Fatal("an Origin header was sent")
				case seen.Host != comHost || claims.Aud != "wss://"+comHost:
					t.Fatalf("host %q, aud %q", seen.Host, claims.Aud)
				case claims.Iat != now-43200 || claims.Exp != now+43200 || claims.Act != "client_auth" || len(claims.Sub) != 64:
					t.Fatalf("claims %+v at %d", claims, now)
				case fmt.Sprint(map[string][]string(seen.Query)) != fmt.Sprint(query):
					t.Fatalf("query %v, want %v", seen.Query, query)
				}
			})
		})
	}
}

// TT2 (R16): a refused upgrade.
func TestTransportRefusals(t *testing.T) {
	t.Run("the identifier is dropped", func(t *testing.T) {
		bubble(t, relaytest.RelayOptions{BundleIds: []string{"network.ur"}}, func(h *harness, config *Config) {
			config.IdentifierName, config.IdentifierValue = "bundleId", "network.ur"
		}, func(t *testing.T, h *harness) {
			h.relay.RefuseHandshakes(1, 403, originBody)
			h.do(func(tr *transport) { tr.setWanted(true) })
			handshakes := h.relay.Handshakes()
			if len(handshakes) != 2 || handshakes[0].Status != 403 || !handshakes[0].Query.Has("bundleId") ||
				handshakes[1].Status != 101 || handshakes[1].Query.Has("bundleId") {
				t.Fatalf("handshakes: %+v", handshakes)
			}
			h.expect("dialled again at once", h.told(), "open", "connected true", "read 1")
			if dials := h.dialed(); len(dials) != 2 || dials[1] != 0 {
				t.Fatalf("dials at %v", dials)
			}
		})
	})
	for _, row := range []struct {
		status int
		body   string
	}{
		{400, `{"error":"Project ID is missing"}`},
		{401, `{"error":"JWT is missing"}`},
		{403, projectBody},
		{403, originBody}, // nothing was presented
	} {
		t.Run(fmt.Sprintf("first connect %d %s", row.status, row.body), func(t *testing.T) {
			bubble(t, relaytest.RelayOptions{}, nil, func(t *testing.T, h *harness) {
				h.relay.RefuseHandshakes(1, row.status, row.body)
				h.do(func(tr *transport) { tr.setWanted(true) })
				h.wait(30 * time.Second)
				h.expect("fatal", h.told(), fmt.Sprintf("fatal unavailable %d", row.status))
				if dials := h.dialed(); len(dials) != 1 {
					t.Fatalf("dials at %v", dials)
				}
			})
		})
		t.Run(fmt.Sprintf("after a sync %d %s", row.status, row.body), func(t *testing.T) {
			bubble(t, relaytest.RelayOptions{}, nil, func(t *testing.T, h *harness) {
				h.connect(topicA)
				h.relay.RefuseHandshakes(1, row.status, row.body)
				h.relay.Drop("")
				h.wait(time.Second)
				h.expect("retried", h.told(), "connected false", "open")
				if statuses := h.relay.Handshakes(); len(statuses) != 3 || statuses[1].Status != row.status || statuses[2].Status != 101 {
					t.Fatalf("handshakes: %+v", statuses)
				}
			})
		})
	}
}

// TT3 and TT4 (R4): the socket is dropped and the relay cannot be
// reached for a while. Nothing is given up but what has a give-up of its own.
func TestTransportDropAndOffline(t *testing.T) {
	for _, offline := range []time.Duration{8 * time.Second, 45 * time.Second} {
		t.Run(offline.String(), func(t *testing.T) {
			bubble(t, relaytest.RelayOptions{}, nil, func(t *testing.T, h *harness) {
				wallet := h.relay.Peer("wallet")
				h.connect(topicA)
				h.relay.SetOffline(true)
				h.relay.Drop("")
				h.expect("lost", h.told(), "connected false")
				if err := wallet.Publish(topicA, "stored", 1101, 300); err != nil {
					t.Fatal(err)
				}
				var read int64
				h.do(func(tr *transport) {
					tr.publish(topicA, "kept", 1100, 300, 0, "kept")
					tr.publish(topicA, "short", 1100, 300, 20, "short")
					read = tr.startRead()
				})
				h.wait(offline)
				before := len(h.dialed())
				h.relay.SetOffline(false)
				// one back-off step at most, then the sync
				h.wait(7 * time.Second)
				want := []string{"open", "written kept on aaaa tag 1100", "written short on aaaa tag 1100",
					"message aaaa stored 1101", "acked kept", "acked short", "connected true", fmt.Sprintf("read %d", read)}
				if offline > 20*time.Second {
					want = []string{"gave up short", "open", "written kept on aaaa tag 1100",
						"message aaaa stored 1101", "acked kept", "connected true", fmt.Sprintf("read %d", read)}
				}
				h.expect("back", h.told(), want...)
				// what was queued goes out when the socket is subscribed, not before
				frames := []string{"2> irn_subscribe aaaa", "2< result", "2< push aaaa stored", "2> irn_publish aaaa kept", "2< result",
					"2> irn_publish aaaa short", "2< result", "2> ack"}
				if offline > 20*time.Second {
					frames = slices.Delete(frames, 5, 7)
				}
				h.expect("on the new socket", h.seen(), frames...)
				if after := len(h.dialed()); read != 2 || before < 5 || after != before+1 {
					t.Fatalf("read %d, %d dials while offline, %d in all", read, before, after)
				}
			})
		})
	}
}

// TT5 (R11): a socket that went silent is replaced, and what it
// swallowed arrives on the next one. What finds it depends on what is
// outstanding: the probe of a pending wait, a subscribe of the sync, or
// nothing but the silence.
func TestTransportZombie(t *testing.T) {
	for _, row := range []struct {
		name     string
		synced   bool // before it goes silent
		wanted   bool
		replaced time.Duration
	}{
		{"R11a the probe gets no result in 5 s", true, true, 20 * time.Second},
		{"R11b a subscribe gets no result in 15 s", false, true, 15 * time.Second},
		{"R11c nothing arrives for 45 s", true, false, 45 * time.Second},
	} {
		t.Run(row.name, func(t *testing.T) {
			bubble(t, relaytest.RelayOptions{}, nil, func(t *testing.T, h *harness) {
				wallet := h.relay.Peer("wallet")
				if row.synced {
					h.connect(topicA)
				} else {
					h.do(func(tr *transport) {
						tr.addTopic(topicA)
						tr.setWanted(true)
					})
				}
				h.relay.SetZombie("", true)
				go wallet.Publish(topicA, "swallowed", 1101, 300)
				if !row.wanted {
					// no wait is pending: a publish keeps the socket needed
					h.do(func(tr *transport) {
						tr.setWanted(false)
						tr.publish(topicA, "kept", 1108, 300, 0, "kept")
					})
				}
				h.wait(row.replaced - time.Second)
				if dials := h.dialed(); len(dials) != 1 {
					t.Fatalf("replaced early: dials at %v", dials)
				}
				h.wait(2 * time.Second)
				dials, told := h.dialed(), h.told()
				// a socket that never synced is followed by a back-off step
				if len(dials) != 2 || row.synced && dials[1] != row.replaced || !row.synced && !within(dials[1]-row.replaced, 250*time.Millisecond) {
					t.Fatalf("dials at %v", dials)
				}
				if !slices.Contains(told, "message aaaa swallowed 1101") {
					t.Fatalf("told %q", told)
				}
			})
		})
	}
}

// TT6 (R3): coming back to the foreground.
func TestTransportForeground(t *testing.T) {
	t.Run("after the background a new socket at once", func(t *testing.T) {
		bubble(t, relaytest.RelayOptions{}, func(h *harness, config *Config) { config.BackgroundSocketSeconds = 45 }, func(t *testing.T, h *harness) {
			wallet := h.relay.Peer("wallet")
			h.connect(topicA)
			h.relay.SetZombie("", true)
			go wallet.Publish(topicA, "swallowed", 1101, 300)
			h.wait(2 * time.Second)
			h.do(func(tr *transport) {
				tr.setForeground(false)
				tr.setForeground(true)
			})
			if dials := h.dialed(); len(dials) != 2 || dials[1] != 2*time.Second+latency || h.tr.ResumeEpoch() != 1 {
				t.Fatalf("dials at %v, epoch %d", dials, h.tr.ResumeEpoch())
			}
			h.wait(latency + quiet)
			h.expect("collected", h.told(), "connected false", "open", "message aaaa swallowed 1101", "connected true", "read 2")
		})
	})
	t.Run("with no background before it one probe round", func(t *testing.T) {
		bubble(t, relaytest.RelayOptions{}, nil, func(t *testing.T, h *harness) {
			h.connect(topicA)
			h.do(func(tr *transport) { tr.setForeground(true) })
			h.wait(latency + quiet)
			h.expect("probe", h.seen(), "1> irn_subscribe aaaa", "1< result")
			h.expect("the socket is kept", h.told(), "read 2")
			// a read on a synced socket starts now, and one asked for meanwhile follows it
			var first, second int64
			h.do(func(tr *transport) { first, second = tr.startRead(), tr.startRead() })
			h.wait(2 * (latency + quiet))
			h.expect("two reads", h.seen(), "1> irn_subscribe aaaa", "1< result", "1> irn_subscribe aaaa", "1< result")
			h.expect("two reads", h.told(), "read 3", "read 4")
			if dials := h.dialed(); first != 3 || second != 4 || len(dials) != 1 {
				t.Fatalf("reads %d and %d, dials at %v", first, second, dials)
			}
		})
	})
}

// TT7 (R5): a dial that hangs is abandoned, and the next one goes to
// the other host.
func TestTransportHungDial(t *testing.T) {
	bubble(t, relaytest.RelayOptions{}, nil, func(t *testing.T, h *harness) {
		h.relay.HangDials(1)
		h.do(func(tr *transport) { tr.setWanted(true) })
		h.wait(7999 * time.Millisecond)
		if dials := h.dialed(); len(dials) != 1 {
			t.Fatalf("dials at %v", dials)
		}
		h.wait(time.Second)
		dials, handshakes := h.dialed(), h.relay.Handshakes()
		if len(dials) != 2 || !within(dials[1]-8*time.Second, 250*time.Millisecond) || len(handshakes) != 1 {
			t.Fatalf("dials at %v, %d handshakes", dials, len(handshakes))
		}
		token, _ := strings.CutPrefix(handshakes[0].Header.Get("Authorization"), "Bearer ")
		if claims, err := wire.VerifyToken(token); err != nil || claims.Aud != "wss://"+orgHost || handshakes[0].Host != orgHost {
			t.Fatalf("host %q, claims %+v, %v", handshakes[0].Host, claims, err)
		}
	})
}

// TT8 (R14): a close of the relay on a socket that was healthy is followed by
// a dial at once, and the held topics are subscribed again.
func TestTransportRoutineClose(t *testing.T) {
	bubble(t, relaytest.RelayOptions{}, nil, func(t *testing.T, h *harness) {
		h.connect(topicA, topicB, topicC)
		h.wait(10 * time.Second)
		h.do(func(tr *transport) { tr.removeTopic(topicC) })
		h.expect("unsubscribed", h.seen(), "1> irn_unsubscribe cccc", "1< result")
		// with the subscription id the relay gave for the topic
		var call, given, sent string
		for _, recorded := range h.relay.Frames("") {
			var frame struct {
				Id     json.RawMessage
				Method string
				Result json.RawMessage
				Params wire.UnsubscribeParams
			}
			json.Unmarshal([]byte(recorded.Text), &frame)
			switch {
			case frame.Method == wire.MethodSubscribe && frame.Params.Topic == topicC:
				call = string(frame.Id)
			case frame.Method == wire.MethodUnsubscribe:
				sent = `"` + frame.Params.Id + `"`
			case string(frame.Id) == call:
				given = string(frame.Result)
			}
		}
		if len(given) != 66 || sent != given {
			t.Fatalf("unsubscribed with the id %s, the relay gave %s", sent, given)
		}
		h.relay.CloseSockets("", 4010, "Disconnecting for load balancing reasons")
		h.wait(latency)
		h.expect("again", h.seen(), "1< close 4010 Disconnecting for load balancing reasons",
			"2> irn_subscribe aaaa", "2> irn_subscribe bbbb", "2< result", "2< result")
		if dials := h.dialed(); len(dials) != 2 || dials[1] != 10*time.Second+latency {
			t.Fatalf("dials at %v", dials)
		}
		// that socket is lost in its quiet window: the end of the window is
		// not the end of its round
		h.relay.Drop("")
		h.wait(time.Second)
		h.expect("the round of a lost socket", h.told(), "connected false", "open", "open", "connected true", "read 3")
		// With nothing pending the socket is kept while the relay's pings come
		// and are answered, and is not dialled again when it is lost.
		h.do(func(tr *transport) { tr.setWanted(false) })
		h.wait(100 * time.Second)
		if dials := h.dialed(); len(dials) != 3 || h.relay.OpenSockets("") != 1 {
			t.Fatalf("dials at %v, %d sockets", dials, h.relay.OpenSockets(""))
		}
		h.relay.Drop("")
		h.wait(30 * time.Second)
		if dials := h.dialed(); len(dials) != 3 {
			t.Fatalf("dials at %v", dials)
		}
	})
}

// TT9 (R4): sockets that open and die are dialled with a back-off, which
// starts again only after a socket synced and lived 10 seconds.
func TestTransportBackoff(t *testing.T) {
	bubble(t, relaytest.RelayOptions{}, nil, func(t *testing.T, h *harness) {
		h.relay.CloseAfterUpgrade(6, 4010)
		h.do(func(tr *transport) {
			tr.addTopic(topicA)
			tr.setWanted(true)
		})
		h.wait(18 * time.Second)
		dials := h.dialed()
		if len(dials) != 7 {
			t.Fatalf("dials at %v", dials)
		}
		for i, step := range []time.Duration{250, 500, 1000, 2000, 4000, 5000} {
			if gap := dials[i+1] - dials[i]; !within(gap, step*time.Millisecond) {
				t.Fatalf("dial %d came %v after the one before, want %v: %v", i+2, gap, step*time.Millisecond, dials)
			}
		}
		// the seventh socket synced and has lived under 10 seconds
		h.relay.Drop("")
		h.wait(18 * time.Second)
		if dials = h.dialed(); len(dials) != 8 || !within(dials[7]-18*time.Second, 5*time.Second) {
			t.Fatalf("dials at %v", dials)
		}
		// the eighth has lived over 10 seconds
		h.relay.Drop("")
		if dials = h.dialed(); len(dials) != 9 || dials[8] != 36*time.Second {
			t.Fatalf("dials at %v", dials)
		}
	})
}

// TT10 (R7): a stored message that the relay pushes before the result of its
// topic's subscribe is not dropped.
func TestTransportPushBeforeResult(t *testing.T) {
	bubble(t, relaytest.RelayOptions{}, func(h *harness, config *Config) { config.Rand = sameBytes{} }, func(t *testing.T, h *harness) {
		wallet := h.relay.Peer("wallet")
		wallet.Publish(topicA, "one", 1101, 300)
		wallet.Publish(topicB, "two", 1102, 300)
		// what the handler adds in onOpen is part of the sync
		h.open = func() {
			h.tr.addTopic(topicA)
			h.tr.addTopic(topicB)
		}
		h.do(func(tr *transport) { tr.setWanted(true) })
		h.wait(latency)
		h.expect("the push comes first", h.seen(), "1> irn_subscribe aaaa", "1> irn_subscribe bbbb",
			"1< push aaaa one", "1< result", "1< result", "1< push bbbb two", "1> ack", "1> ack")
		h.expect("both delivered", h.told(), "open", "message aaaa one 1101", "connected true", "read 1", "message bbbb two 1102")
		// a topic that is added later is subscribed on the open socket, which
		// is synced again when its mailbox was read: no round, so no onRead
		wallet.Publish(topicC, "three", 1102, 300)
		h.do(func(tr *transport) { tr.addTopic(topicC) })
		h.wait(latency + quiet - time.Millisecond)
		h.expect("subscribed", h.seen(), "1> irn_subscribe cccc", "1< result", "1< push cccc three", "1> ack")
		h.expect("not synced yet", h.told(), "connected false", "message cccc three 1102")
		h.wait(time.Millisecond)
		h.expect("synced", h.told(), "connected true")
		// one that is added while a round waits for its end is part of the round
		h.do(func(tr *transport) { tr.startRead() })
		h.wait(latency + quiet - 10*time.Millisecond)
		h.do(func(tr *transport) { tr.addTopic(topicD) })
		h.wait(10 * time.Millisecond)
		h.expect("the round is not over", h.told(), "connected false")
		h.wait(latency + quiet - 10*time.Millisecond)
		h.expect("the round is over", h.told(), "connected true", "read 2")
	})
}

// TT11 (R10): a push is acknowledged before it is handed on, with its id
// digit for digit. One for a topic that is no longer held is acknowledged and
// dropped, and so is a second delivery of a message.
func TestTransportAcknowledgesFirst(t *testing.T) {
	for _, first := range []int64{0, 1791419882856123457} {
		t.Run(fmt.Sprint(first), func(t *testing.T) {
			bubble(t, relaytest.RelayOptions{FirstPushId: first}, nil, func(t *testing.T, h *harness) {
				wallet := h.relay.Peer("wallet")
				h.connect(topicA, topicB)
				release := make(chan struct{})
				h.message = func(string) {
					<-release
					h.tr.removeTopic(topicB)
				}
				go wallet.Publish(topicA, "m", 1109, 300)
				synctest.Wait()
				// the loop is inside onMessage now
				frames := h.relay.Frames("")
				var push struct {
					Id json.RawMessage
				}
				json.Unmarshal([]byte(frames[len(frames)-2].Text), &push)
				id := string(push.Id)
				if digits := len(id); first == 0 && digits != 15 || first != 0 && id != fmt.Sprint(first) {
					t.Fatalf("the push has the id %s", id)
				}
				if ack := frames[len(frames)-1]; !ack.ToRelay || ack.Text != `{"id":`+id+`,"jsonrpc":"2.0","result":true}` {
					t.Fatalf("the relay has no acknowledgement while the message is handed on: %q", ack.Text)
				}
				h.seen()
				go wallet.Publish(topicB, "late", 1109, 300)
				synctest.Wait()
				close(release)
				h.expect("acknowledged and dropped", h.seen(), "1< push bbbb late", "1> irn_unsubscribe bbbb", "1< result", "1> ack")
				h.relay.DuplicateNextPush(topicA)
				wallet.Publish(topicA, "twice", 1109, 300)
				h.expect("acknowledged twice", h.seen(), "1< push aaaa twice", "1< push aaaa twice", "1> ack", "1> ack")
				h.expect("handed on once", h.told(), "message aaaa m 1109", "message aaaa twice 1109")
			})
		})
	}
}

// TT12 (R6, R9): a publish whose acknowledgement did not come is written
// again on the next socket, the same bytes, and only when that socket is
// synced: the quiet window after the last push has passed. One whose answer
// came meanwhile is not written again.
func TestTransportPublishSurvivesAReconnect(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancelled %t", cancelled), func(t *testing.T) {
			bubble(t, relaytest.RelayOptions{}, nil, func(t *testing.T, h *harness) {
				wallet := h.relay.Peer("wallet")
				h.connect(topicA)
				h.relay.LoseNextPublishAck("")
				var entry *publishEntry
				h.do(func(tr *transport) { entry = tr.publish(topicA, "request", 1108, 300, 0, "request") })
				h.expect("written", h.told(), "written request on aaaa tag 1108")
				first := h.relay.Frames("")
				h.seen()
				// a socket that lived 10 seconds is followed by a dial at once
				h.wait(10 * time.Second)
				h.relay.Drop("")
				h.wait(latency + 300*time.Millisecond)
				wallet.Publish(topicA, "meanwhile", 1109, 300)
				if cancelled {
					h.do(func(tr *transport) { tr.cancelPublish(entry) })
				}
				h.wait(quiet)
				frames := h.relay.Frames("")
				if cancelled {
					h.expect("not written again", h.seen(), "2> irn_subscribe aaaa", "2< result", "2< push aaaa meanwhile", "2> ack")
					h.expect("synced", h.told(), "connected false", "open", "message aaaa meanwhile 1109", "connected true", "read 2")
					return
				}
				h.expect("written again", h.seen(), "2> irn_subscribe aaaa", "2< result", "2< push aaaa meanwhile", "2> ack",
					"2> irn_publish aaaa request", "2< result")
				h.expect("after the sync", h.told(), "connected false", "open", "message aaaa meanwhile 1109", "connected true", "read 2", "acked request")
				again, push := frames[len(frames)-2], frames[len(frames)-4]
				if again.Text != first[len(first)-1].Text || again.At.Sub(push.At) != quiet {
					t.Fatalf("written again %v after the last push: %q", again.At.Sub(push.At), again.Text)
				}
			})
		})
	}
}

// A write that fails, as one does that ran into its deadline, is no write
// (R13): the socket is let go, and the entry is written for the first time
// on the next one, as soon as that is subscribed.
func TestTransportWriteFails(t *testing.T) {
	var fail atomic.Bool
	bubble(t, relaytest.RelayOptions{}, func(h *harness, config *Config) {
		dial := config.DialTLS
		config.DialTLS = func(ctx context.Context, network string, address string) (net.Conn, error) {
			conn, err := dial(ctx, network, address)
			return failing{conn, &fail}, err
		}
	}, func(t *testing.T, h *harness) {
		h.connect(topicA)
		fail.Store(true)
		h.do(func(tr *transport) { tr.publish(topicA, "request", 1108, 300, 0, "request") })
		h.expect("let go", h.told(), "connected false")
		fail.Store(false)
		h.wait(time.Second)
		h.expect("written once", h.seen(), "2> irn_subscribe aaaa", "2< result", "2> irn_publish aaaa request", "2< result")
		h.expect("written once", h.told(), "open", "written request on aaaa tag 1108", "acked request", "connected true", "read 2")
	})
}

// failing is a connection whose writes fail on demand.
type failing struct {
	net.Conn
	fail *atomic.Bool
}

func (c failing) Write(p []byte) (int, error) {
	if c.fail.Load() {
		return 0, errors.New("the write failed")
	}
	return c.Conn.Write(p)
}

// TT13 (R9, R11): a publish that the relay answers late, behind a recipient
// that is silent, is left alone on a socket that answers its probes.
func TestTransportSlowPublishAck(t *testing.T) {
	bubble(t, relaytest.RelayOptions{}, nil, func(t *testing.T, h *harness) {
		wallet := h.relay.Peer("wallet")
		wallet.Subscribe(topicA)
		h.relay.SetZombie("wallet", true)
		h.connect(topicA)
		for i, hold := range []time.Duration{6100 * time.Millisecond, 12 * time.Second} {
			h.relay.SetAckHold(hold)
			// three seconds before the next probe round
			h.wait(time.Duration(12+15*i)*time.Second - time.Since(h.start))
			h.told()
			h.do(func(tr *transport) { tr.publish(topicA, fmt.Sprint("request ", i), 1108+i, 300, 0, i) })
			h.wait(hold - time.Millisecond)
			h.expect("held", h.told(), fmt.Sprintf("written %d on aaaa tag %d", i, 1108+i), fmt.Sprintf("read %d", i+2))
			h.wait(time.Millisecond)
			h.expect("acknowledged", h.told(), fmt.Sprintf("acked %d", i))
		}
		h.expect("one write each, and the probes", h.seen(),
			"1> irn_publish aaaa request 0", "1> irn_subscribe aaaa", "1< result", "1< result",
			"1> irn_publish aaaa request 1", "1> irn_subscribe aaaa", "1< result", "1< result")
		if dials := h.dialed(); len(dials) != 1 {
			t.Fatalf("dials at %v", dials)
		}
	})
}

// TT14 (R2, R3): in the background the socket is closed on purpose.
func TestTransportBackground(t *testing.T) {
	t.Run("at once", func(t *testing.T) {
		bubble(t, relaytest.RelayOptions{}, nil, func(t *testing.T, h *harness) {
			h.connect(topicA)
			h.do(func(tr *transport) { tr.setForeground(false) })
			h.expect("closed", h.seen(), "1> close 1000", "1< close 1000")
			h.expect("closed", h.told(), "connected false")
			ticks, running := h.ticked(), h.tr.RunningSeconds()
			h.wait(30 * time.Second)
			if dials := h.dialed(); len(dials) != 1 || h.ticked() != ticks || h.tr.RunningSeconds() != running {
				t.Fatalf("closed on purpose: dials at %v, %d ticks more", dials, h.ticked()-ticks)
			}
			h.do(func(tr *transport) { tr.setForeground(true) })
			h.wait(time.Second)
			h.expect("back", h.told(), "open", "connected true", "read 2", "resumed")
			if dials := h.dialed(); len(dials) != 2 || dials[1] != 30*time.Second+latency {
				t.Fatalf("dials at %v", dials)
			}
		})
	})
	t.Run("after 45 ticks", func(t *testing.T) {
		bubble(t, relaytest.RelayOptions{}, func(h *harness, config *Config) { config.BackgroundSocketSeconds = 45 }, func(t *testing.T, h *harness) {
			h.connect(topicA)
			h.do(func(tr *transport) { tr.setForeground(false) })
			h.wait(45*time.Second - 2*latency)
			if frames := h.seen(); slices.Contains(frames, "1> close 1000") {
				t.Fatalf("closed early: %q", frames)
			}
			h.wait(latency)
			h.expect("closed", h.seen(), "1> close 1000", "1< close 1000")
		})
	})
	t.Run("a suspension in the background", func(t *testing.T) {
		bubble(t, relaytest.RelayOptions{}, func(h *harness, config *Config) { config.BackgroundSocketSeconds = 45 }, func(t *testing.T, h *harness) {
			h.connect(topicA)
			h.do(func(tr *transport) { tr.setForeground(false) })
			h.wait(10 * time.Second)
			h.seen()
			h.offset.Add(60_000)
			h.wait(30 * time.Second)
			h.expect("dropped", h.seen())
			if dials := h.dialed(); len(dials) != 1 || h.relay.OpenSockets("") != 0 || h.tr.ResumeEpoch() != 1 {
				t.Fatalf("dials at %v, %d sockets, epoch %d", dials, h.relay.OpenSockets(""), h.tr.ResumeEpoch())
			}
		})
	})
}

// TT15 (R2): a suspension is seen with no call from the app.
func TestTransportSuspension(t *testing.T) {
	// the clock of a phone can also have been set back meanwhile
	for _, jump := range []int64{60_000, -60_000} {
		t.Run(fmt.Sprintf("the socket is replaced after a jump of %d ms", jump), func(t *testing.T) {
			bubble(t, relaytest.RelayOptions{}, nil, func(t *testing.T, h *harness) {
				h.connect(topicA)
				h.wait(5 * time.Second)
				h.offset.Add(jump)
				h.wait(5 * time.Second)
				h.expect("resumed", h.told(), "connected false", "resumed", "open", "connected true", "read 2")
				if dials := h.dialed(); len(dials) != 2 || dials[1] != 6*time.Second || h.tr.ResumeEpoch() != 1 {
					t.Fatalf("dials at %v, epoch %d", dials, h.tr.ResumeEpoch())
				}
			})
		})
	}
	t.Run("the back-off and the give-ups start again", func(t *testing.T) {
		bubble(t, relaytest.RelayOptions{}, nil, func(t *testing.T, h *harness) {
			h.connect(topicA)
			h.relay.SetOffline(true)
			h.relay.Drop("")
			h.do(func(tr *transport) { tr.publish(topicA, "m", 1108, 300, 20, "timed") })
			h.wait(10*time.Second - latency)
			h.offset.Add(60_000)
			// The next iteration of the loop sees the gap, the tick at 11 s at
			// the latest: a dial at once, and 20 seconds more for the entry.
			h.wait(20*time.Second - time.Millisecond)
			dials, told := h.dialed(), h.told()
			i := slices.IndexFunc(dials, func(dial time.Duration) bool { return dial > 10*time.Second })
			if i < 0 || dials[i] > 11*time.Second || !within(dials[i+1]-dials[i], 250*time.Millisecond) {
				t.Fatalf("no dial at once and a first back-off step after it: %v", dials)
			}
			if slices.Contains(told, "gave up timed") {
				t.Fatalf("gave up early: %q", told)
			}
			h.wait(time.Millisecond)
			h.expect("gave up", h.told(), "gave up timed")
		})
	})
}

// TT16 (R4, R16): three frames above the read limit end the transport, and
// so do three errors of the relay in a row.
func TestTransportFatal(t *testing.T) {
	t.Run("three frames above the read limit", func(t *testing.T) {
		bubble(t, relaytest.RelayOptions{}, nil, func(t *testing.T, h *harness) {
			h.connect(topicA)
			for range 3 {
				h.relay.SendOversized("", 1<<20+1)
				h.wait(2 * time.Second)
			}
			h.wait(30 * time.Second)
			h.expect("fatal", h.told(), "connected false", "open", "connected true", "read 2",
				"connected false", "open", "connected true", "read 3", "connected false", "fatal wallet 0")
			if dials := h.dialed(); len(dials) != 3 {
				t.Fatalf("dials at %v", dials)
			}
		})
	})
	for _, failures := range []int{3, 2} {
		t.Run(fmt.Sprintf("%d errors of the relay", failures), func(t *testing.T) {
			bubble(t, relaytest.RelayOptions{}, nil, func(t *testing.T, h *harness) {
				h.relay.FailCalls(wire.MethodSubscribe, failures, -32000, "no")
				h.do(func(tr *transport) {
					tr.addTopic(topicA)
					tr.setWanted(true)
				})
				h.wait(10 * time.Second)
				want := []string{"open", "open", "open", "fatal unavailable -32000"}
				if failures == 2 {
					want = []string{"open", "open", "open", "connected true", "read 3"}
				}
				h.expect("three sockets", h.told(), want...)
				if dials := h.dialed(); len(dials) != 3 {
					t.Fatalf("dials at %v", dials)
				}
				if failures == 2 {
					// in a row: two more after a success end nothing either
					h.relay.FailCalls(wire.MethodSubscribe, 2, -32000, "no")
					h.relay.Drop("")
					h.wait(10 * time.Second)
					h.expect("counted from zero", h.told(), "connected false", "open", "open", "open", "connected true", "read 6")
				}
			})
		})
	}
	// The errors to a publish are a row of their own: each is followed by a
	// sync, whose subscribes succeed and must not start the count again.
	t.Run("3 errors of the relay to a publish", func(t *testing.T) {
		bubble(t, relaytest.RelayOptions{}, nil, func(t *testing.T, h *harness) {
			h.connect(topicA)
			h.relay.FailCalls(wire.MethodPublish, 3, -32000, "no")
			h.do(func(tr *transport) { tr.publish(topicA, "m", 1108, 300, 0, "m") })
			h.wait(10 * time.Second)
			h.expect("each on a new socket", h.told(), "written m on aaaa tag 1108", "connected false", "open", "connected true", "read 2",
				"connected false", "open", "connected true", "read 3", "connected false", "fatal unavailable -32000")
		})
	})
}

// TT17 (R19): a shutdown writes what is queued, on one dial if it has to, and
// ends the loop.
func TestTransportShutdown(t *testing.T) {
	queue := func(tr *transport) {
		tr.addTopic(topicA) // not subscribed for a shutdown
		tr.publish(topicA, "settle answer", 1103, 300, 0, "one")
		tr.publish(topicA, "delete", 1112, 86400, 0, "two")
		tr.shutdown(3)
	}
	t.Run("flushed", func(t *testing.T) {
		bubble(t, relaytest.RelayOptions{}, nil, func(t *testing.T, h *harness) {
			h.do(queue)
			if dials := h.dialed(); !h.stopped() || len(dials) != 1 {
				t.Fatalf("stopped %t, dials at %v", h.stopped(), dials)
			}
			h.expect("written, then closed", h.seen(), "1> irn_publish aaaa settle answer", "1< result",
				"1> irn_publish aaaa delete", "1< result", "1> close 1000", "1< close 1000")
		})
	})
	t.Run("the relay cannot be reached", func(t *testing.T) {
		bubble(t, relaytest.RelayOptions{}, nil, func(t *testing.T, h *harness) {
			h.relay.SetOffline(true)
			h.do(queue)
			h.wait(2999 * time.Millisecond)
			if h.stopped() {
				t.Fatal("stopped before the flush time was over")
			}
			h.wait(time.Millisecond)
			if dials := h.dialed(); !h.stopped() || len(dials) != 1 {
				t.Fatalf("stopped %t, dials at %v", h.stopped(), dials)
			}
		})
	})
}

// TT18 (R1): a panic on the loop ends the transport and not the process.
func TestTransportPanic(t *testing.T) {
	for _, where := range []string{"do", "onMessage"} {
		t.Run(where, func(t *testing.T) {
			bubble(t, relaytest.RelayOptions{}, nil, func(t *testing.T, h *harness) {
				wallet := h.relay.Peer("wallet")
				h.connect(topicA)
				if where == "do" {
					h.tr.do(func() { panic("boom") })
				} else {
					h.message = func(string) { panic("boom") }
					go wallet.Publish(topicA, "m", 1109, 300)
				}
				if !h.stopped() || !h.tr.crashed() || h.relay.OpenSockets("") != 0 {
					t.Fatalf("stopped %t, crashed %t, %d sockets", h.stopped(), h.tr.crashed(), h.relay.OpenSockets(""))
				}
				h.told()
				h.tr.do(func() { h.note("ran after the end") })
				h.wait(5 * time.Second)
				h.expect("nothing afterwards", h.told())
				h.tr.mu.Lock()
				kept := len(h.tr.commands)
				h.tr.mu.Unlock()
				if kept != 0 {
					t.Fatal("a function passed to do after the end is kept")
				}
			})
		})
	}
}
