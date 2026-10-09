//go:build !js && !ios_extension

package walletconnect

// The client is tested end to end in a synctest bubble: on the relay of
// relaytest, against its wallet on an in-process peer. Config.Now is the
// bubble's clock plus an offset that a test can jump, which is what a
// suspension looks like to the loop (design G). The client's ticks fall on
// whole seconds after the start of a test.
//
// A bubble cannot end while a goroutine is left in it, so every test also
// shows that a client that ended leaves none behind.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
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
	testChain   = "polkadot:2f0555cc76fc2840a25a6ea3b9637146"
	testMethod  = "polkadot_signMessage"
	testAddress = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
	testAccount = testChain + ":" + testAddress
	testMessage = "Sign in to URnetwork\nChallenge: q1w2e3r4t5y6u7i8o9p0\nTimestamp: 1757340000"
)

var (
	testSignature = "0x" + strings.Repeat("ab", 64)
	// the private key of the wallet's key agreement: with it and the
	// proposal a test has the session key
	walletSeed = wire.Key{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
)

func skipSettle(settle *relaytest.SettleEdit) { settle.SkipSettle = true }

// Every line a client may trace (delta 5.3), as a whole: numbers, fixed words
// and 8 hex characters of a topic. So no text that a wallet or the relay wrote
// and no part of a key, a uri or a token fits one. play holds every line of
// every test against it. bwcTraceLine of the root package's tests repeats the
// forms, for the trace of a connection.
var traceLine = func() *regexp.Regexp {
	const topic, id = `topic=[0-9a-f]{8}`, `id=(?:\d{1,20}|\?)`
	const label = `tag=\d+ ` + topic + ` ` + id
	const said = `(?:request (?:wc_(?:pairingDelete|pairingPing|sessionSettle|sessionRequest|sessionDelete|sessionPing|sessionEvent|sessionUpdate|sessionExtend)|` +
		`wc_sessionPropose T=[01] E=[01] R=[01]|other)|error -?\d+|result(?: responderPublicKey=1)?(?: signature=1)?)`
	return regexp.MustCompile(`^(?:` + strings.Join([]string{
		`sock dial \d+ relay\.walletconnect\.(?:com|org)`,
		`sock (?:open|synced) \d+`,
		`sock dial-failed \d+ status=\d+`,
		`sock lost \d+ age=\d+s code=\d+`,
		`sock close \d+ code=1000 (?:parked|shutdown)`,
		`fg [01]`,
		`parked after \d+s`,
		`resume \d+`,
		`stopped (?:unavailable|wallet) code=-?\d+`,
		`pairing ` + topic + ` expires \+\d+s`,
		`wait (?:proposal|settle|request)`,
		`OUT ` + label + ` ` + said,
		`(?:write|rewrite) ` + label + ` sock=\d+`,
		`(?:ack|give-up) ` + label,
		`push tag=\d+ (?:` + topic + `(?: dropped duplicate)?|dropped not-held)`,
		`IN tag=\d+ ` + topic + ` (?:` + id + ` ` + said + `|dropped (?:cannot-open|not-jsonrpc|unexpected-id))`,
		`settle (?:ok accounts=\d+|refused code=-?\d+)`,
		`deadline passed: reading`,
		`read [12]/2`,
		`expired`,
		`unreachable`,
		`end(?: (?:unavailable|expired|rejected|unsupported|no_account|deleted|wallet) code=-?\d+)?`,
	}, "|") + `)$`)
}()

// scene is a client on a relay, the wallet it talks to, and what the client
// told.
type scene struct {
	t      *testing.T
	relay  *relaytest.Relay
	peer   *relaytest.Peer // the wallet's connection, also for what a wallet would not send
	wallet *relaytest.Wallet
	client *Client
	cancel context.CancelFunc
	start  time.Time
	offset atomic.Int64 // milliseconds Config.Now is ahead of the bubble's clock
	lossy  atomic.Bool  // what the client writes does not arrive

	mu     sync.Mutex
	events []Event
	logs   []string
	trace  []string // what Config.Trace was given
	uri    string

	told     int // events already looked at
	frames   int // frames of the relay's record already looked at
	proposal *relaytest.Proposal
}

// play runs f with a client, a relay and a wallet.
func play(t *testing.T, edit func(s *scene, config *Config, wallet *relaytest.WalletOptions), f func(t *testing.T, s *scene)) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		s := &scene{t: t, relay: relaytest.NewRelay(relaytest.RelayOptions{}), start: time.Now()}
		defer s.relay.Close()
		config := &Config{
			ProjectId:    "test-project",
			Metadata:     wire.Metadata{Name: "URnetwork", Description: "URnetwork", Url: "https://ur.io", Icons: []string{"https://ur.io/favicon.ico"}},
			NamespaceKey: "polkadot",
			Chain:        testChain,
			Method:       testMethod,
			Now:          func() int64 { return time.Now().UnixMilli() + s.offset.Load() },
			DialTLS: func(ctx context.Context, network string, address string) (net.Conn, error) {
				conn, err := s.relay.DialTLS(ctx, network, address)
				return lossy{conn, &s.lossy}, err
			},
			OnEvent: func(ev Event) {
				s.mu.Lock()
				defer s.mu.Unlock()
				s.events = append(s.events, ev)
				if ev.Kind == EventPairingReady {
					s.uri = ev.PairingUri
				}
			},
			Trace: func(format string, args ...any) {
				s.mu.Lock()
				defer s.mu.Unlock()
				s.trace = append(s.trace, fmt.Sprintf(format, args...))
			},
		}
		options := relaytest.WalletOptions{Seed: walletSeed, Dedup: true}
		if edit != nil {
			edit(s, config, &options)
		}
		s.peer = s.relay.Peer("wallet")
		s.wallet = relaytest.NewWallet(s.peer, options)
		defer s.wallet.Close()
		ctx, cancel := context.WithCancel(context.Background())
		client, err := NewClient(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		s.client, s.cancel = client, cancel
		// the client ends with its context, and what it traced is of the lines it may
		defer func() {
			cancel()
			<-client.Done()
			s.mu.Lock()
			defer s.mu.Unlock()
			for _, line := range s.trace {
				if !traceLine.MatchString(line) {
					t.Errorf("traced: %q", line)
				}
			}
		}()
		f(t, s)
	})
}

// lossy is a connection whose writes are lost on demand: they succeed and do
// not arrive.
type lossy struct {
	net.Conn
	lose *atomic.Bool
}

func (c lossy) Write(p []byte) (int, error) {
	if c.lose.Load() {
		return len(p), nil
	}
	return c.Conn.Write(p)
}

func (s *scene) now() int64 { return time.Now().UnixMilli() + s.offset.Load() }

// wait lets d pass.
func (s *scene) wait(d time.Duration) {
	time.Sleep(d)
	synctest.Wait()
}

// at lets the time pass until d after the start.
func (s *scene) at(d time.Duration) { s.wait(d - time.Since(s.start)) }

// receive takes the next value of a channel, which is there or about to be.
func receive[T any](s *scene, from <-chan T) T {
	s.t.Helper()
	select {
	case value := <-from:
		return value
	case <-time.After(10 * time.Second):
		s.t.Fatal("nothing came")
		panic("not reached")
	}
}

// take is what the client told since the last call.
func (s *scene) take() []Event {
	synctest.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	events := slices.Clone(s.events[s.told:])
	s.told = len(s.events)
	return events
}

// names are events as lines; the changes of Connected only when asked for.
func names(events []Event, connected bool) []string {
	lines := []string{}
	for _, ev := range events {
		switch ev.Kind {
		case EventPairingReady:
			lines = append(lines, "ready")
		case EventSessionSettled:
			lines = append(lines, "settled")
		case EventRequestSent:
			lines = append(lines, "sent")
		case EventRequestResult:
			lines = append(lines, "result "+ev.Signature)
		case EventRequestFailed:
			lines = append(lines, fmt.Sprintf("failed %s %d", ev.Err.Kind, ev.Err.Code))
		case EventConnected:
			if connected {
				lines = append(lines, fmt.Sprintf("connected %t", ev.Connected))
			}
		case EventClosed:
			if ev.Err == nil {
				lines = append(lines, "closed")
			} else {
				lines = append(lines, fmt.Sprintf("closed %s %d", ev.Err.Kind, ev.Err.Code))
			}
		}
	}
	return lines
}

func (s *scene) same(what string, got []string, want ...string) {
	s.t.Helper()
	if !slices.Equal(got, want) {
		s.t.Fatalf("%s:\n got  %q\n want %q", what, got, want)
	}
}

// expect compares what the client told since the last look, without the
// changes of Connected, with want.
func (s *scene) expect(what string, want ...string) {
	s.t.Helper()
	s.same(what, names(s.take(), false), want...)
}

// shapes are the frames of the client's sockets since the last call, as the
// relay took and gave them: ">" for a frame of the client, P for the pairing
// topic and B for any other, and the tag and the time to live of a publish.
func (s *scene) shapes() []string {
	synctest.Wait()
	s.mu.Lock()
	pairing, _ := wire.ParsePairingUri(s.uri)
	s.mu.Unlock()
	letter := func(topic string) string {
		if pairing != nil && topic == pairing.Topic {
			return "P"
		}
		return "B"
	}
	frames := s.relay.Frames("")
	lines := []string{}
	for _, recorded := range frames[s.frames:] {
		var frame struct {
			Method string
			Params struct {
				Topic    string
				Tag, Ttl int
				Data     wire.SubscriptionData
			}
		}
		text := recorded.Text // a close frame
		if json.Unmarshal([]byte(recorded.Text), &frame) == nil {
			switch {
			case frame.Method == wire.MethodPublish:
				text = fmt.Sprintf("publish %s %d %d", letter(frame.Params.Topic), frame.Params.Tag, frame.Params.Ttl)
			case frame.Method == wire.MethodSubscription:
				text = fmt.Sprintf("push %s %d", letter(frame.Params.Data.Topic), frame.Params.Data.Tag)
			case frame.Method != "":
				text = strings.TrimPrefix(frame.Method, "irn_") + " " + letter(frame.Params.Topic)
			case recorded.ToRelay:
				text = "ack"
			default:
				text = "result"
			}
		}
		if recorded.ToRelay {
			lines = append(lines, "> "+text)
		} else {
			lines = append(lines, "< "+text)
		}
	}
	s.frames = len(frames)
	return lines
}

// publishes are the publishes among shapes.
func (s *scene) publishes() []string {
	lines := []string{}
	for _, line := range s.shapes() {
		if strings.HasPrefix(line, "> publish") {
			lines = append(lines, line)
		}
	}
	return lines
}

// sessionKey is the key of the session the wallet approves.
func (s *scene) sessionKey() wire.Key {
	proposer, _ := wire.ParseKey(s.proposal.ProposerPublicKey)
	key, err := wire.DeriveSymKey(walletSeed, proposer)
	if err != nil {
		s.t.Fatal(err)
	}
	return key
}

func (s *scene) pairing() *wire.Pairing {
	pairing, err := wire.ParsePairingUri(s.uri)
	if err != nil {
		s.t.Fatal(err)
	}
	return pairing
}

// forge publishes a frame from the wallet's connection, sealed under key:
// what the wallet of relaytest does not send.
func (s *scene) forge(topic string, key wire.Key, frame []byte, tag int) {
	s.t.Helper()
	message, _ := wire.SealRandom(key, rand.Reader, frame)
	if err := s.peer.Publish(topic, message, tag, wire.TtlFiveMinutes); err != nil {
		s.t.Fatal(err)
	}
}

// pair has the client propose, and the wallet take the uri and the proposal.
func (s *scene) pair() {
	s.t.Helper()
	s.client.Pair()
	s.wait(latency)
	s.expect("paired", "ready")
	s.client.Pair() // once: a second call does nothing
	if err := s.wallet.Pair(s.uri); err != nil {
		s.t.Fatal(err)
	}
	s.proposal = receive(s, s.wallet.Proposals())
}

// settle is pair and the wallet's approval.
func (s *scene) settle() {
	s.t.Helper()
	s.pair()
	s.wallet.Approve(s.proposal)
	s.wait(latency)
	s.expect("settled", "settled")
}

// sign has the client ask for a signature, to be given within five minutes,
// and the wallet take the request.
func (s *scene) sign() (int64, *relaytest.Request) {
	s.t.Helper()
	id := s.client.SignMessage(testAddress, testMessage, s.now()+300_000)
	request := receive(s, s.wallet.Requests())
	s.expect("sent", "sent")
	return id, request
}

// TE1: one sign-in with nothing in its way, frame by frame.
func TestClientBaseline(t *testing.T) {
	play(t, func(s *scene, config *Config, wallet *relaytest.WalletOptions) {
		wallet.Accounts = []string{"polkadot:91b171bb158e2d3848fa23a9f1c25182:" + testAddress, testAccount}
	}, func(t *testing.T, s *scene) {
		s.client.Pair()
		s.wait(latency)
		ready := s.take()
		if pairing := s.pairing(); len(ready) != 2 || ready[1].PairingExpiryMillis != pairing.ExpiryUnix*1000 ||
			pairing.ExpiryUnix != time.Now().Unix()+300 || pairing.Topic != wire.Topic(pairing.SymKey) {
			t.Fatalf("told %+v", names(ready, true))
		}
		s.wallet.Pair(s.uri)
		s.proposal = receive(s, s.wallet.Proposals())
		if strings.Contains(string(s.proposal.Params), "redirect") || !strings.Contains(string(s.proposal.Params), `"optionalNamespaces":{}`) {
			t.Fatalf("the proposal: %s", s.proposal.Params)
		}
		s.wallet.Approve(s.proposal)
		s.wait(latency + quiet)
		id := s.client.SignMessage(testAddress, testMessage, s.now()+300_000)
		request := receive(s, s.wallet.Requests())
		if string(request.Id) != fmt.Sprint(id) || request.ChainId != testChain || request.Method != testMethod ||
			request.Address != testAddress || request.Message != testMessage {
			t.Fatalf("the request %d: %+v", id, request)
		}
		s.wallet.Respond(request, map[string]string{"signature": testSignature})
		synctest.Wait()
		s.client.Close()
		receive(s, s.client.Done())

		events := append(ready, s.take()...)
		s.same("told", names(events, true), "connected true", "ready", "connected false", "settled", "connected true",
			"sent", "result "+testSignature, "closed")
		if settled, sent, result := events[3], events[5], events[6]; !slices.Equal(settled.Accounts, []string{testAccount}) ||
			sent.RequestId != id || result.RequestId != id {
			t.Fatalf("settled %v, sent %d, result %d, want %d", settled.Accounts, sent.RequestId, result.RequestId, id)
		}
		s.same("frames", s.shapes(),
			"> subscribe P", "< result", "> publish P 1100 300", "< result",
			"< push P 1101", "> ack", "> subscribe B", "< result",
			"< push B 1102", "> ack", "> publish B 1103 300", "< result", "> unsubscribe P", "< result",
			"> publish B 1108 300", "< result", "< push B 1109", "> ack",
			"> publish B 1112 86400", "< result", "> close 1000", "< close 1000")
		published := s.relay.Published()
		for _, message := range published {
			envelope, err := wire.DecodeBase64(message.Message)
			if len(message.Topic) != 64 || strings.Trim(message.Topic, "0123456789abcdef") != "" || err != nil || envelope[0] != 0 {
				t.Fatalf("no type 0 envelope on a hex topic: %+v", message)
			}
		}
		if len(published) != 7 {
			t.Fatalf("%d publishes", len(published))
		}
	})
}

// The optional members of the proposal (delta 2.2). A config that asks for
// none sends ur.io's proposal. One that asks sends the topic and the expiry of
// the pairing it made, and its redirect as it is; the expiry is the one number
// the uri and the event carry, and the flow goes on with the three.
func TestClientProposalOptions(t *testing.T) {
	const redirect = `{"native":"app.example.wallet://return","universal":"https://app.example/return"}`
	for _, asked := range []bool{false, true} {
		play(t, func(s *scene, config *Config, _ *relaytest.WalletOptions) {
			// not the 300 s a pairing has until the engine gives it its own
			config.Timing = DefaultTiming()
			config.Timing.PairingTtl = 120 * time.Second
			if asked {
				config.ProposePairingTopic, config.ProposeExpiry = true, true
				config.Redirect = &wire.Redirect{Native: "app.example.wallet://return", Universal: "https://app.example/return"}
			}
		}, func(t *testing.T, s *scene) {
			s.client.Pair()
			s.wait(latency)
			ready, pairing := s.take(), s.pairing()
			s.wallet.Pair(s.uri)
			s.proposal = receive(s, s.wallet.Proposals())
			var params struct {
				PairingTopic    string
				ExpiryTimestamp int64
				Proposer        struct {
					Metadata struct{ Redirect json.RawMessage }
				}
			}
			err := json.Unmarshal(s.proposal.Params, &params)
			switch got := string(s.proposal.Params); {
			case err != nil || pairing.ExpiryUnix != time.Now().Unix()+120 || len(ready) != 2 || ready[1].PairingExpiryMillis != pairing.ExpiryUnix*1000:
				t.Fatalf("the proposal %s (%v), the pairing until %d, told %q", got, err, pairing.ExpiryUnix, names(ready, true))
			case !asked:
				for _, member := range []string{"pairingTopic", "expiryTimestamp", "redirect"} {
					if strings.Contains(got, member) {
						t.Fatalf("the proposal has %s unasked: %s", member, got)
					}
				}
			case params.PairingTopic != pairing.Topic || params.ExpiryTimestamp != pairing.ExpiryUnix || string(params.Proposer.Metadata.Redirect) != redirect:
				t.Fatalf("the proposal %s for the pairing %s until %d", got, pairing.Topic, pairing.ExpiryUnix)
			}
			s.wallet.Approve(s.proposal)
			s.wait(latency)
			s.expect("settled", "settled")
			_, request := s.sign()
			s.wallet.Respond(request, testSignature)
			s.wait(latency)
			s.expect("signed", "result "+testSignature)
		})
	}
}

// TE2, TE3, TE9 (R2, R12): the process is away while the wallet
// answers, in each of the three waits. What it finds in its mailbox when it
// runs again is used, also when the deadline of the wait has passed.
func TestClientCollectsAfterASuspension(t *testing.T) {
	for _, row := range []struct {
		name string
		jump time.Duration
		drop bool // the socket is gone too
	}{
		{"20 s", 20 * time.Second, false},
		{"90 s", 90 * time.Second, false},
		{"200 s", 200 * time.Second, false},
		{"to 60 s after the deadline", 360 * time.Second, false},
		{"20 s and the socket dropped", 20 * time.Second, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			play(t, nil, func(t *testing.T, s *scene) {
				away := func(answer func()) {
					if row.drop {
						s.relay.Drop("")
					} else {
						// what the relay pushes meets a silent socket
						s.relay.SetZombie("", true)
					}
					go answer()
					synctest.Wait()
					s.offset.Add(row.jump.Milliseconds())
					s.wait(2 * time.Second)
				}
				s.pair()
				away(func() { s.wallet.ApproveWith(s.proposal, skipSettle) })
				s.client.SignMessage(testAddress, testMessage, s.now()+300_000)
				s.expect("the approval alone is no session", "failed deleted 0")
				away(func() { s.wallet.Approve(s.proposal) })
				s.expect("the settle", "settled")
				_, request := s.sign()
				away(func() { s.wallet.Respond(request, testSignature) })
				s.expect("the result", "result "+testSignature)
				if epoch := s.client.ResumeEpoch(); epoch != 3 {
					t.Fatalf("%d resume edges", epoch)
				}
			})
		})
	}
}

// TE4 (R12): with its deadline passed and nothing in the mailbox a wait
// ends when two reads that began after the loop saw it are over, and not
// with the first.
func TestClientExpiresAfterTwoReads(t *testing.T) {
	for _, row := range []struct {
		wait, want string
		deletes    int
	}{
		{"proposal", "closed expired 0", 0},
		{"settle", "closed expired 0", 1},
		{"request", "failed expired 0", 0},
	} {
		t.Run(row.wait, func(t *testing.T) {
			play(t, nil, func(t *testing.T, s *scene) {
				s.pair()
				switch row.wait {
				case "settle":
					s.wallet.ApproveWith(s.proposal, skipSettle)
				case "request":
					s.wallet.Approve(s.proposal)
					s.wait(latency)
					s.expect("settled", "settled")
					s.sign()
				}
				// the 20 s of the first connect ended with the acknowledgement
				s.at(25 * time.Second)
				s.offset.Add(301_000)
				// the next tick sees the gap and the deadline: a new socket, whose
				// sync is the first read
				s.wait(time.Second + 2*(latency+quiet) - time.Millisecond)
				s.expect("one read is not enough")
				s.wait(time.Millisecond)
				s.expect("the second read", row.want)
				if deletes := s.wallet.Seen(wire.TagSessionDelete); deletes != row.deletes {
					t.Fatalf("the wallet saw %d deletes", deletes)
				}
			})
		})
	}
}

// TE5 (R12): with the relay out of reach a wait whose deadline passed ends
// 20 ticks after the loop saw it, and what the relay kept is used when it is
// back before that.
func TestClientDeadlineWithTheRelayOutOfReach(t *testing.T) {
	for _, back := range []bool{false, true} {
		t.Run(fmt.Sprintf("back %t", back), func(t *testing.T) {
			play(t, nil, func(t *testing.T, s *scene) {
				s.pair()
				s.at(25 * time.Second)
				s.relay.SetOffline(true)
				s.offset.Add(301_000)
				if back {
					s.wait(10 * time.Second)
					s.wallet.Approve(s.proposal)
					s.relay.SetOffline(false)
					// one step of the back-off at most
					s.wait(8 * time.Second)
					s.expect("collected", "settled")
					return
				}
				s.wait(21*time.Second - time.Millisecond)
				s.expect("not before 20 ticks have passed")
				s.wait(time.Millisecond)
				s.expect("out of reach", "closed unavailable 0")
			})
		})
	}
}

// R17: the relay has 20 s of running time to take the proposal. The plan
// rests that on the give-up of the proposal, which is queued only when a
// socket opened: with the relay out of reach nothing would ever give up.
func TestClientFirstConnect(t *testing.T) {
	for _, row := range []struct {
		name  string
		fault func(relay *relaytest.Relay)
		at    time.Duration
		want  string
	}{
		{"out of reach", func(relay *relaytest.Relay) { relay.SetOffline(true) }, 20 * time.Second, "closed unavailable 0"},
		{"no acknowledgement", func(relay *relaytest.Relay) { relay.LoseNextPublishAck("") }, 20 * time.Second, "closed unavailable 0"},
		{"refused", func(relay *relaytest.Relay) { relay.RefuseHandshakes(1, 403, projectBody) }, 0, "closed unavailable 403"},
	} {
		t.Run(row.name, func(t *testing.T) {
			play(t, nil, func(t *testing.T, s *scene) {
				row.fault(s.relay)
				s.client.Pair()
				if row.at > 0 {
					s.wait(row.at - time.Millisecond)
					s.expect("not yet")
					s.wait(time.Millisecond)
				}
				s.expect("the first connect", row.want)
			})
		})
	}
}

// TE6 (R7, R8): the socket is lost while the subscribe of the session
// topic is on its way.
func TestClientLosesTheSocketWhileSubscribingTheSession(t *testing.T) {
	for _, offline := range []time.Duration{0, 8 * time.Second} {
		t.Run(fmt.Sprint("offline ", offline), func(t *testing.T) {
			play(t, nil, func(t *testing.T, s *scene) {
				s.pair()
				s.wallet.Approve(s.proposal)
				// the relay answers a subscribe after 20 ms
				if lines := s.shapes(); lines[len(lines)-1] != "> subscribe B" {
					t.Fatalf("frames %q", lines)
				}
				s.relay.SetOffline(offline > 0)
				s.relay.Drop("")
				s.wait(offline)
				s.relay.SetOffline(false)
				s.wait(7 * time.Second)
				s.expect("the settle is collected", "settled")
			})
		})
	}
}

// TE7 (R9): the relay took the request, and its
// acknowledgement is lost with the socket.
func TestClientRequestAcknowledgementLost(t *testing.T) {
	for _, offline := range []bool{true, false} {
		t.Run(fmt.Sprintf("offline %t", offline), func(t *testing.T) {
			play(t, nil, func(t *testing.T, s *scene) {
				s.settle()
				s.relay.LoseNextPublishAck("")
				_, request := s.sign()
				s.shapes()
				s.relay.SetOffline(offline)
				s.relay.Drop("")
				if offline {
					// the answer is in the mailbox, and is read before the request
					// could go out again
					s.wallet.Respond(request, testSignature)
					s.wait(8 * time.Second)
					s.relay.SetOffline(false)
					s.wait(7 * time.Second)
					s.same("not written again", s.publishes())
				} else {
					// nothing has come when the new socket is synced: the same
					// bytes again, which the relay delivers again and a wallet
					// takes for the request it has
					s.wait(2 * time.Second)
					s.same("written again", s.publishes(), "> publish B 1108 300")
					published := s.relay.Published()
					if again, first := published[len(published)-1], published[len(published)-2]; again.Message != first.Message || s.wallet.Seen(wire.TagSessionRequest) != 2 {
						t.Fatalf("the wallet was handed %d requests", s.wallet.Seen(wire.TagSessionRequest))
					}
					s.wallet.Respond(request, testSignature)
				}
				s.expect("the result", "result "+testSignature)
				if more := len(s.wallet.Requests()); more != 0 {
					t.Fatalf("the wallet took %d requests more", more)
				}
			})
		})
	}
}

// TE8 (R6): an answer that waits in the mailbox is read before the request
// it answers could be written again, here by a wallet that would take the
// second copy for a new request.
func TestClientDoesNotRepeatAnAnsweredRequest(t *testing.T) {
	play(t, func(s *scene, config *Config, wallet *relaytest.WalletOptions) { wallet.Dedup = false }, func(t *testing.T, s *scene) {
		s.settle()
		s.relay.LoseNextPublishAck("")
		_, request := s.sign()
		s.relay.SetZombie("", true)
		go s.wallet.Respond(request, testSignature)
		synctest.Wait()
		s.offset.Add(20_000)
		s.wait(5 * time.Second)
		s.expect("the result", "result "+testSignature)
		if seen := s.wallet.Seen(wire.TagSessionRequest); seen != 1 || len(s.wallet.Requests()) != 0 {
			t.Fatalf("the wallet was handed %d requests", seen)
		}
	})
}

// TE10 (B.4): the acknowledgement of the settle, written to a socket that
// died with it, stays in front of a request that was never written.
func TestClientSettleAcknowledgementBeforeTheRequest(t *testing.T) {
	play(t, nil, func(t *testing.T, s *scene) {
		s.pair()
		s.wallet.Approve(s.proposal)
		synctest.Wait()
		s.lossy.Store(true)
		s.wait(latency)
		s.expect("settled", "settled")
		s.lossy.Store(false)
		s.relay.Drop("")
		s.client.SignMessage(testAddress, testMessage, s.now()+300_000)
		s.offset.Add(120_000)
		s.wait(2 * time.Second)
		s.expect("sent", "sent")
		s.same("in order", s.publishes(), "> publish P 1100 300", "> publish B 1103 300", "> publish B 1108 300")
	})
}

// TE11 (R13): a request counts as sent when it is written. The relay holds
// its acknowledgement back while the wallet's connection is silent.
func TestClientSentWhenWritten(t *testing.T) {
	play(t, nil, func(t *testing.T, s *scene) {
		s.settle()
		s.shapes()
		s.relay.SetAckHold(6100 * time.Millisecond)
		s.relay.SetZombie("wallet", true)
		s.client.SignMessage(testAddress, testMessage, s.now()+300_000)
		s.expect("at the write", "sent")
		s.wait(6100*time.Millisecond - time.Millisecond)
		s.same("not acknowledged", s.shapes(), "> publish B 1108 300")
		s.wait(time.Millisecond)
		s.same("acknowledged", s.shapes(), "< result")
	})
}

// TE12: what a wallet can answer a proposal with. An invalid settle is
// answered with an error on tag 1103, and the session it would have made is
// deleted.
func TestClientApprovalAndSettleFailures(t *testing.T) {
	approve := func(edit func(settle *relaytest.SettleEdit)) func(s *scene) {
		return func(s *scene) { s.wallet.ApproveWith(s.proposal, edit) }
	}
	const pairingAnswer, settleAnswer, deleted = "> publish P 1001 86400", "> publish B 1103 300", "> publish B 1112 86400"
	for _, row := range []struct {
		name      string
		act       func(s *scene)
		want      string   // the last thing the client tells
		code      int      // of the error the settle is answered with
		publishes []string // of the client, after the proposal
	}{
		// the text has none of the reject words: the code alone gives the class
		{"rejected", func(s *scene) { s.wallet.Reject(s.proposal, 5000, "no") }, "closed rejected 5000", 0, nil},
		{"unsupported", func(s *scene) { s.wallet.Reject(s.proposal, 5100, "Unsupported chains.") }, "closed unsupported 5100", 0, nil},
		{"the pairing deleted before the approval", func(s *scene) { s.wallet.DeletePairing() }, "closed rejected 0", 0, []string{pairingAnswer}},
		{"the pairing deleted after the approval", func(s *scene) {
			s.wallet.ApproveWith(s.proposal, skipSettle)
			s.wallet.DeletePairing()
			s.wallet.Approve(s.proposal)
		}, "settled", 0, []string{pairingAnswer, settleAnswer}},
		{"a responder key that is no key", func(s *scene) {
			approval := wire.ResultFrame(s.proposal.Id, map[string]string{"responderPublicKey": "zz"})
			s.forge(s.pairing().Topic, s.pairing().SymKey, approval, wire.TagSessionProposeApprove)
		}, "closed wallet -1", 0, nil},
		{"another controller key", approve(func(settle *relaytest.SettleEdit) { settle.ControllerKey = strings.Repeat("ab", 32) }),
			"closed wallet 7000", 7000, []string{settleAnswer, deleted}},
		{"an account on another chain only", approve(func(settle *relaytest.SettleEdit) {
			settle.Accounts = []string{"polkadot:91b171bb158e2d3848fa23a9f1c25182:" + testAddress}
		}), "closed unsupported 5001", 5001, []string{settleAnswer, deleted}},
		{"another method only", approve(func(settle *relaytest.SettleEdit) { settle.Methods = []string{"polkadot_signTransaction"} }),
			"closed unsupported 5002", 5002, []string{settleAnswer, deleted}},
		{"no account", approve(func(settle *relaytest.SettleEdit) { settle.Accounts = []string{} }),
			"closed no_account 5001", 5001, []string{settleAnswer, deleted}},
		{"the expiry as a string", approve(func(settle *relaytest.SettleEdit) { settle.Expiry = json.RawMessage(`"4102444800"`) }),
			"closed wallet 7000", 7000, []string{settleAnswer, deleted}},
		{"the expiry in the past", approve(func(settle *relaytest.SettleEdit) { settle.Expiry = json.RawMessage(`946684800`) }),
			"closed wallet 7000", 7000, []string{settleAnswer, deleted}},
		{"a settle of another shape", func(s *scene) {
			s.wallet.ApproveWith(s.proposal, skipSettle)
			s.wallet.Send("wc_sessionSettle", map[string]int{"controller": 7})
		}, "closed wallet -1", 7000, []string{settleAnswer, deleted}},
		// the approval is read 20 ms after the start: the tick at 301 s is the
		// first to see the settle's own five minutes over, and two reads follow
		{"no settle", func(s *scene) {
			s.wallet.ApproveWith(s.proposal, skipSettle)
			s.at(302*time.Second + 2*latency - time.Millisecond)
			s.expect("not before the second read")
		}, "closed expired 0", 0, []string{deleted}},
	} {
		t.Run(row.name, func(t *testing.T) {
			play(t, nil, func(t *testing.T, s *scene) {
				s.pair()
				s.shapes()
				row.act(s)
				s.wait(latency)
				if told := names(s.take(), false); len(told) != 1 || told[0] != row.want {
					t.Fatalf("told %q, want %q", told, row.want)
				}
				s.same("published", s.publishes(), row.publishes...)
				if row.code == 0 {
					return
				}
				for _, published := range s.relay.Published() {
					if published.Tag != wire.TagSessionSettleResponse {
						continue
					}
					plaintext, _ := wire.Open(s.sessionKey(), published.Message)
					if frame, err := wire.ParseFrame(plaintext); err != nil || frame.Error == nil || frame.Error.Code != row.code {
						t.Fatalf("the settle was answered with %s", plaintext)
					}
				}
			})
		})
	}
}

// TE13: what a wallet can answer a request with, and the wallet ending the
// session. A request that failed leaves the session as it was.
func TestClientRequestFailures(t *testing.T) {
	play(t, nil, func(t *testing.T, s *scene) {
		s.settle()
		for _, row := range []struct {
			code    int
			message string
			want    string
		}{
			{4001, "no", "failed rejected 4001"},
			{8000, "no", "failed expired 8000"},
			{5101, "no", "failed unsupported 5101"},
			{9999, "no", "failed wallet 9999"},
			{1234, "The request was DECLINED.", "failed rejected 1234"},
		} {
			_, request := s.sign()
			s.wallet.RespondError(request, row.code, row.message)
			s.expect(row.message, row.want)
		}
		// an answer that is neither a result nor an error
		_, request := s.sign()
		s.forge(wire.Topic(s.sessionKey()), s.sessionKey(), []byte(`{"id":`+string(request.Id)+`,"jsonrpc":"2.0"}`), wire.TagSessionRequestResponse)
		s.expect("no answer at all", "failed wallet -1")

		s.sign()
		second := s.client.SignMessage(testAddress, testMessage, s.now()+300_000)
		if told := s.take(); len(told) != 1 || told[0].Kind != EventRequestFailed || told[0].RequestId != second ||
			*told[0].Err != (Error{Kind: ErrWallet, Detail: "a request is pending"}) {
			t.Fatalf("a second request: told %+v", names(told, true))
		}
		s.shapes()
		s.wallet.DeleteSession()
		s.expect("the wallet ended the session", "closed deleted 0")
		s.same("answered, and no delete of its own", s.publishes(), "> publish B 1113 86400")
	})
}

// TE14 (B.4, R18): what a wallet asks of the dapp is answered, and changes
// nothing. A request of the wallet and a second settle are not answered.
func TestClientAnswersTheWallet(t *testing.T) {
	play(t, nil, func(t *testing.T, s *scene) {
		ask := func(send func(method string, params any) (*wire.Frame, error), method string, params any, want string, publishes ...string) {
			t.Helper()
			answer := "nothing"
			if frame, err := send(method, params); err == nil && frame.Error != nil {
				answer = fmt.Sprint("error ", frame.Error.Code)
			} else if err == nil {
				answer = "result " + string(frame.Result)
			}
			if answer != want {
				t.Fatalf("%s was answered with %s, want %s", method, answer, want)
			}
			s.same(method, s.publishes(), publishes...)
		}
		s.pair()
		s.shapes()
		ask(s.wallet.SendOnPairing, "wc_pairingPing", struct{}{}, "result true", "> publish P 1003 30")
		ask(s.wallet.SendOnPairing, "wc_pairingExtend", struct{}{}, "result true", "> publish P 0 86400")
		s.wallet.Approve(s.proposal)
		s.wait(latency)
		s.expect("settled", "settled")
		s.shapes()
		other := map[string]any{"polkadot": wire.Namespace{Accounts: []string{testChain + ":5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"}}}
		ask(s.wallet.Send, "wc_sessionPing", struct{}{}, "result true", "> publish B 1115 30")
		ask(s.wallet.Send, "wc_sessionEvent", map[string]string{"chainId": testChain}, "result true", "> publish B 1111 300")
		ask(s.wallet.Send, "wc_sessionUpdate", map[string]any{"namespaces": other}, "result true", "> publish B 1105 86400")
		ask(s.wallet.Send, "wc_sessionExtend", map[string]int64{"expiry": 4102444800}, "result true", "> publish B 1107 86400")
		ask(s.wallet.Send, "wc_sessionAuthenticate", struct{}{}, "error 1001", "> publish B 0 86400")
		ask(s.wallet.Send, "wc_sessionRequest", struct{}{}, "nothing")
		ask(s.wallet.Send, "wc_sessionSettle", struct{}{}, "nothing")
		s.expect("nothing changed")
	})
}

// TE15 (R10, F.2): what is not the answer to the pending request is passed
// over, and so is a second copy of the answer.
func TestClientIgnoresWhatIsNoAnswer(t *testing.T) {
	play(t, nil, func(t *testing.T, s *scene) {
		s.settle()
		pairing, key := s.pairing(), s.sessionKey()
		topic := wire.Topic(key)
		id, request := s.sign()
		forged := wire.ResultFrame(request.Id, "0xforged")
		other, _ := wire.NewKey(rand.Reader)
		// the type byte of an envelope is not part of what the key seals
		sealed, _ := wire.SealRandom(key, rand.Reader, forged)
		type1, _ := wire.DecodeBase64(sealed)
		type1[0] = 1
		s.forge(topic, key, wire.ResultFrame(wire.IdToken(id+1), "0xforged"), wire.TagSessionRequestResponse)
		s.forge(pairing.Topic, pairing.SymKey, forged, wire.TagSessionRequestResponse)
		s.forge(topic, other, forged, wire.TagSessionRequestResponse)
		s.peer.Publish(topic, wire.EncodeBase64(type1), wire.TagSessionRequestResponse, wire.TtlFiveMinutes)
		s.expect("no answer yet")
		s.relay.DuplicateNextPush(topic)
		s.wallet.Respond(request, testSignature)
		s.wallet.Respond(request, "0xagain")
		s.expect("one result", "result "+testSignature)
	})
}

// TE16 (R19): Close at every stage. The wallet is told that the session is
// over whenever the approval had been read, and never twice. A context that
// ends tells nobody.
func TestClientClose(t *testing.T) {
	for _, row := range []struct {
		stage   string
		deletes int
	}{
		{"before Pair", 0},
		{"proposing", 0},
		{"awaiting the approval", 0},
		{"approved", 1},
		{"settled", 1},
		{"requesting", 1},
		{"the context ends", 0},
	} {
		t.Run(row.stage, func(t *testing.T) {
			play(t, nil, func(t *testing.T, s *scene) {
				switch row.stage {
				case "proposing":
					s.relay.LoseNextPublishAck("")
					s.client.Pair()
					s.wait(latency)
				case "awaiting the approval":
					s.pair()
				case "approved":
					s.pair()
					s.wallet.ApproveWith(s.proposal, skipSettle)
					s.wait(latency)
				case "settled", "the context ends":
					s.settle()
				case "requesting":
					s.settle()
					s.sign()
				}
				s.take()
				if row.stage == "the context ends" {
					s.cancel()
					synctest.Wait()
				}
				s.client.Close()
				s.client.Close()
				receive(s, s.client.Done())
				s.same("closed, once", names(s.take(), true), "closed")
				s.client.Pair()
				s.client.SignMessage(testAddress, testMessage, s.now()+300_000)
				s.wait(5 * time.Second)
				s.same("nothing after the end", names(s.take(), true))
				dials := s.relay.Dials()
				if deletes := s.wallet.Seen(wire.TagSessionDelete); deletes != row.deletes || s.relay.OpenSockets("") != 0 || (dials == 0) != (row.stage == "before Pair") {
					t.Fatalf("the wallet saw %d deletes; %d sockets, %d dials", deletes, s.relay.OpenSockets(""), dials)
				}
			})
		})
	}
}

// TE17 (R21): a settled session with nothing to do is ended after 120 ticks
// in the foreground, counted from the settle, from the end of a request or
// from a resume edge.
func TestClientLinger(t *testing.T) {
	for _, row := range []struct {
		name    string
		act     func(s *scene)
		ends    time.Duration
		sockets int // just before: with nothing pending a socket that is lost is not replaced (R4)
	}{
		{"in the foreground", func(s *scene) {}, 120 * time.Second, 1},
		{"after a request that ended at 60 s", func(s *scene) {
			s.at(60500 * time.Millisecond)
			_, request := s.sign()
			s.wallet.RespondError(request, 4001, "no")
			s.expect("declined", "failed rejected 4001")
		}, 180 * time.Second, 1},
		{"not in the background", func(s *scene) {
			s.at(10500 * time.Millisecond)
			s.client.SetForeground(false)
			s.at(200500 * time.Millisecond)
			s.expect("still open")
			s.client.SetForeground(true)
		}, 321 * time.Second, 0},
		{"a resume at tick 100", func(s *scene) {
			s.at(100500 * time.Millisecond)
			s.offset.Add(60_000)
		}, 221 * time.Second, 0},
	} {
		t.Run(row.name, func(t *testing.T) {
			play(t, func(s *scene, config *Config, wallet *relaytest.WalletOptions) { config.BackgroundSocketSeconds = 200 }, func(t *testing.T, s *scene) {
				s.settle()
				row.act(s)
				s.at(row.ends - time.Millisecond)
				s.expect("not yet")
				if sockets := s.relay.OpenSockets(""); sockets != row.sockets {
					t.Fatalf("%d sockets", sockets)
				}
				s.wait(time.Millisecond)
				s.expect("ended by itself", "closed")
				if deletes := s.wallet.Seen(wire.TagSessionDelete); deletes != 1 {
					t.Fatalf("the wallet saw %d deletes", deletes)
				}
			})
		})
	}
}

// TE18 (F.1, delta 5.4): nothing that is logged or traced is a secret or a
// text that the wallet or the relay wrote, and a topic is cut. The wallet
// writes a marker wherever it can write: its metadata, an id, a method, params,
// an error, a result, and what cannot be read at all. The relay writes it into
// an error and into the reason of a close.
func TestClientLogsNoSecret(t *testing.T) {
	const marker = "MARKER-7f3a"
	play(t, func(s *scene, config *Config, wallet *relaytest.WalletOptions) {
		config.Logf = func(format string, args ...any) {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.logs = append(s.logs, fmt.Sprintf(format, args...))
		}
	}, func(t *testing.T, s *scene) {
		s.pair()
		pairing, session := s.pairing(), s.sessionKey()
		topic := wire.Topic(session)
		responder, _ := wire.NewKeyPair(bytes.NewReader(walletSeed[:]))
		s.forge(pairing.Topic, pairing.SymKey, []byte(`{"id":"`+marker+`","jsonrpc":"2.0","method":"wc_`+marker+`","params":"`+marker+`"}`), 0)
		// the pairing topic stays subscribed at the relay when the client has let go of it
		s.relay.FailCalls(wire.MethodUnsubscribe, 1, -32000, marker)
		s.wallet.ApproveWith(s.proposal, skipSettle)
		s.wallet.Send("wc_sessionSettle", map[string]any{
			"relay": map[string]string{"protocol": "irn"},
			"controller": map[string]any{"publicKey": responder.Public.Hex(), "metadata": map[string]any{
				"name": marker, "description": marker, "url": "https://" + marker, "icons": []string{marker}, "redirect": map[string]string{"native": marker + "://"},
			}},
			"namespaces": map[string]*wire.Namespace{"polkadot": {Accounts: []string{testAccount, testChain + ":" + marker}, Methods: []string{testMethod}, Events: []string{marker}}},
			"expiry":     time.Now().Unix() + 3600,
		})
		s.expect("settled", "settled")
		other, _ := wire.NewKey(rand.Reader)
		s.forge(pairing.Topic, pairing.SymKey, []byte(marker), 1234)
		s.forge(topic, other, []byte(marker), wire.TagSessionRequestResponse)
		s.forge(topic, session, []byte(marker), wire.TagSessionRequestResponse)
		s.forge(topic, session, wire.ResultFrame(wire.IdToken(7), marker), wire.TagSessionRequestResponse)
		s.expect("nothing of that is told")
		_, request := s.sign()
		s.wallet.RespondError(request, 4001, marker)
		s.expect("refused", "failed rejected 4001")
		s.relay.CloseSockets("", 4010, marker)
		s.expect("the socket is lost, which is not told")
		_, request = s.sign()
		s.wallet.Respond(request, map[string]string{"signature": testSignature, "note": marker})
		s.expect("the result", "result "+testSignature)
		// an answer to the wallet that the relay does not acknowledge is given up after 30 s
		s.relay.LoseNextPublishAck("")
		s.wallet.Send("wc_sessionPing", marker)
		s.wait(31 * time.Second)
		// behind another app and back, where the socket is closed at once
		s.client.SetForeground(false)
		s.client.SetForeground(true)
		s.client.Close()
		receive(s, s.client.Done())

		secrets := []string{s.uri, "q1w2e3r4t5y6u7i8o9p0", testSignature, testAddress, "test-project", marker, s.proposal.ProposerPublicKey, responder.Public.Hex()}
		// the relay token of each of the three sockets
		handshakes := s.relay.Handshakes()
		for _, handshake := range handshakes {
			secrets = append(secrets, strings.TrimPrefix(handshake.Header.Get("Authorization"), "Bearer "))
		}
		for _, key := range []wire.Key{pairing.SymKey, session} {
			secrets = append(secrets, wire.EncodeBase64(key[:]), fmt.Sprint(key[:]))
			// and no 9 characters of the key or of its topic
			for _, text := range []string{key.Hex(), wire.Topic(key)} {
				for i := 0; i+9 <= len(text); i++ {
					secrets = append(secrets, text[i:i+9])
				}
			}
		}
		s.mu.Lock()
		logs, trace := strings.Join(s.logs, "\n"), strings.Join(s.trace, "\n")
		s.mu.Unlock()
		if len(handshakes) != 3 || len(secrets[8]) < 100 || !strings.Contains(logs, pairing.Topic[:8]) || !strings.Contains(logs, topic[:8]) {
			t.Fatalf("%d sockets, or the log of a whole flow:\n%s", len(handshakes), logs)
		}
		for _, secret := range secrets {
			if strings.Contains(logs+"\n"+trace, secret) {
				t.Fatalf("%q is logged or traced:\n%s\n%s", secret, logs, trace)
			}
		}
		// what the trace says of the same flow, in this order; P and B are the two topics, N an id the client or the wallet made
		lines := strings.Split(regexp.MustCompile(`id=\d{15,}`).ReplaceAllString(strings.NewReplacer(pairing.Topic[:8], "P", topic[:8], "B").Replace(trace), "id=N"), "\n")
		for _, want := range []string{
			"sock dial 1 relay.walletconnect.com", "sock open 1", "pairing topic=P expires +300s", "wait proposal",
			"OUT tag=1100 topic=P id=N request wc_sessionPropose T=0 E=0 R=0", "sock synced 1", "write tag=1100 topic=P id=N sock=1", "ack tag=1100 topic=P id=N",
			"push tag=0 topic=P", "IN tag=0 topic=P id=? request other", "OUT tag=0 topic=P id=? result",
			"push tag=1101 topic=P", "IN tag=1101 topic=P id=N result responderPublicKey=1", "wait settle",
			"push tag=1102 topic=B", "IN tag=1102 topic=B id=N request wc_sessionSettle", "settle ok accounts=2", "OUT tag=1103 topic=B id=N result",
			"push tag=1234 dropped not-held", "IN tag=1109 topic=B dropped cannot-open", "IN tag=1109 topic=B dropped not-jsonrpc",
			"IN tag=1109 topic=B id=7 result", "IN tag=1109 topic=B dropped unexpected-id",
			"wait request", "OUT tag=1108 topic=B id=N request wc_sessionRequest", "IN tag=1109 topic=B id=N error 4001",
			"sock lost 1 age=0s code=4010", "wait request", "OUT tag=1108 topic=B id=N request wc_sessionRequest",
			"sock dial 3 relay.walletconnect.org", "sock open 3", "write tag=1108 topic=B id=N sock=3", "IN tag=1109 topic=B id=N result signature=1",
			"IN tag=1114 topic=B id=N request wc_sessionPing", "OUT tag=1115 topic=B id=N result", "write tag=1115 topic=B id=N sock=3", "give-up tag=1115 topic=B id=N",
			"fg 0", "parked after 0s", "sock close 3 code=1000 parked", "fg 1", "resume 1",
			"end", "OUT tag=1112 topic=B id=N request wc_sessionDelete", "sock dial 6 relay.walletconnect.org", "sock open 6",
			"write tag=1112 topic=B id=N sock=6", "ack tag=1112 topic=B id=N", "sock close 6 code=1000 shutdown",
		} {
			at := slices.Index(lines, want)
			if at < 0 {
				t.Fatalf("the trace has no %q after the lines before it:\n%s", want, trace)
			}
			lines = lines[at+1:]
		}
	})
}

// TE19 (R1): a panic of the owner's callback, or on the loop, ends the
// client and not the process.
func TestClientPanic(t *testing.T) {
	t.Run("OnEvent", func(t *testing.T) {
		play(t, func(s *scene, config *Config, wallet *relaytest.WalletOptions) {
			record := config.OnEvent
			config.OnEvent = func(ev Event) {
				record(ev)
				if ev.Kind == EventPairingReady || ev.Kind == EventClosed {
					panic("boom")
				}
			}
		}, func(t *testing.T, s *scene) {
			s.client.Pair()
			s.wait(latency)
			receive(s, s.client.Done())
			told := s.take()
			s.same("closed, once", names(told, true), "connected true", "ready", "closed wallet 0")
			if detail := told[2].Err.Detail; detail != "internal error" {
				t.Fatalf("detail %q", detail)
			}
		})
	})
	// the hook is the logger, which the loop calls when it has read a settle
	t.Run("the loop", func(t *testing.T) {
		play(t, func(s *scene, config *Config, wallet *relaytest.WalletOptions) {
			config.Logf = func(format string, args ...any) {
				if strings.Contains(format, "settled") {
					panic("boom")
				}
			}
		}, func(t *testing.T, s *scene) {
			s.pair()
			s.wallet.Approve(s.proposal)
			s.wait(latency)
			receive(s, s.client.Done())
			told := s.take()
			s.same("closed, once", names(told, false), "closed wallet 0")
			if detail := told[len(told)-1].Err.Detail; detail != "internal error" {
				t.Fatalf("detail %q", detail)
			}
		})
	})
}
