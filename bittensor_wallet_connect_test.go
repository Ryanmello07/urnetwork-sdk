//go:build !js && !ios_extension

package sdk

// The app-held wallet connection is tested end to end in a synctest bubble: on
// the relay of relaytest, against its wallet on an in-process peer, with a
// scripted challenge fetch. The clock of the connection and of its client is
// the bubble's plus an offset that a test can jump, which is what a
// suspension looks like to them (design G). Each step of a test is given a
// second of the bubble's time, more than the relay and the client take for it.
//
// A bubble cannot end while a goroutine is left in it, so every test also
// shows that a connection whose context ended leaves none behind.

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sdk/walletconnect"
	"github.com/urnetwork/sdk/walletconnect/relaytest"
	"github.com/urnetwork/sdk/walletconnect/wire"
)

const (
	bwcStep      = time.Second
	bwcLoginBody = `{"blockchain":"TAO","purpose":"login"}`

	// the states, as the apps are told them
	bwcIdle              = "idle"
	bwcConnecting        = "connecting"
	bwcAwaitingApproval  = "awaiting_approval"
	bwcAwaitingSignature = "awaiting_signature"
	bwcSigned            = "signed"
	bwcFailed            = "failed"
	bwcClosed            = "closed"
)

var bwcSignature = map[string]string{"signature": bittensorTestSignature}

type bwcListenerFunc func(state string)

func (f bwcListenerFunc) BittensorWalletConnectChanged(state string) { f(state) }

// bwcGoroutine is the number of the goroutine that calls it.
func bwcGoroutine() string {
	stack := make([]byte, 64)
	return strings.Fields(string(stack[:runtime.Stack(stack, false)]))[1]
}

// bwcScene is a connection on a relay, the wallet it talks to,
// and what its listener and its challenge fetch were told.
type bwcScene struct {
	t      *testing.T
	relay  *relaytest.Relay
	wallet *relaytest.Wallet
	c      *BittensorWalletConnect
	cancel context.CancelFunc
	caller string       // the goroutine of the test, which makes every call to the connection
	offset atomic.Int64 // milliseconds the connection's clock is ahead of the bubble's

	mu       sync.Mutex
	calls    []string // what the listener was told since the last look
	onCaller bool     // the listener was called on the goroutine of the test
	fetched  []string // the challenge requests, as the json the server is sent
	// what the challenge fetch answers to its nth call; nil answers the fixture
	fetch func(ctx context.Context, n int) (*AuthWalletChallengeResult, error)
}

// bwcPlay runs f in a bubble with a connection to a wallet app,
// a relay and a wallet.
func bwcPlay(t *testing.T, walletId string, platform string, options relaytest.WalletOptions, f func(t *testing.T, s *bwcScene)) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		s := &bwcScene{t: t, caller: bwcGoroutine(), relay: relaytest.NewRelay(relaytest.RelayOptions{
			BundleIds: []string{"network.ur"}, PackageNames: []string{"com.bringyour.network"},
		})}
		defer s.relay.Close()
		s.wallet = relaytest.NewWallet(s.relay.Peer("wallet"), options)
		defer s.wallet.Close()
		ctx, cancel := context.WithCancel(context.Background())
		appId := map[string]string{BittensorWalletPlatformIos: "network.ur", BittensorWalletPlatformAndroid: "com.bringyour.network"}[platform]
		c, err := newBittensorWalletConnect(ctx, walletId, platform, "test-project", appId)
		if err != nil {
			t.Fatal(err)
		}
		c.nowMillis = func() int64 { return time.Now().UnixMilli() + s.offset.Load() }
		c.fetchChallenge = s.fetchChallenge
		c.configureClient = func(config *walletconnect.Config) { config.DialTLS = s.relay.DialTLS }
		c.AddBittensorWalletConnectListener(s)
		s.c, s.cancel = c, cancel
		// the connection ends with its context
		defer func() {
			cancel()
			synctest.Wait()
		}()
		f(t, s)
	})
}

// bwcPlayNova is bwcPlay for Nova Wallet on an iPhone, and a wallet with its
// one account.
func bwcPlayNova(t *testing.T, f func(t *testing.T, s *bwcScene)) {
	t.Helper()
	bwcPlay(t, BittensorWalletNova, BittensorWalletPlatformIos, relaytest.WalletOptions{}, f)
}

func (s *bwcScene) BittensorWalletConnectChanged(state string) {
	onCaller := bwcGoroutine() == s.caller
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, state)
	s.onCaller = s.onCaller || onCaller
}

func (s *bwcScene) fetchChallenge(ctx context.Context, args *AuthWalletChallengeArgs) (*AuthWalletChallengeResult, error) {
	body, _ := json.Marshal(args)
	s.mu.Lock()
	s.fetched = append(s.fetched, string(body))
	fetch, n := s.fetch, len(s.fetched)
	s.mu.Unlock()
	if fetch != nil {
		return fetch(ctx, n)
	}
	return bittensorTestChallenge(), nil
}

// asked are the challenge requests so far.
func (s *bwcScene) asked() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.fetched)
}

// wait lets d pass, and everything that it sets off.
func (s *bwcScene) wait(d time.Duration) {
	time.Sleep(d)
	synctest.Wait()
}

// expect holds the state of the connection, and what the listener was told
// since the last look, against what is wanted: one call for every state
// entered and one for every change of Connected in a waiting state, in order
// (TC1), never on the goroutine of the test (TC17). No proof is handed out in
// another state than signed (TC8).
func (s *bwcScene) expect(what string, state string, calls ...string) {
	s.t.Helper()
	synctest.Wait()
	s.mu.Lock()
	told, onCaller := s.calls, s.onCaller
	s.calls = nil
	s.mu.Unlock()
	if got := s.c.State(); got != state || !slices.Equal(told, calls) {
		s.t.Fatalf("%s: the state is %s and the listener was told %q; want %s and %q", what, got, told, state, calls)
	}
	if onCaller || state != bwcSigned && s.c.TakeProof() != nil {
		s.t.Fatalf("%s: a listener call on the goroutine of the test (%t), or a proof in the state %s", what, onCaller, state)
	}
}

// bwcTake is what the wallet was handed.
func bwcTake[T any](s *bwcScene, from <-chan T) T {
	s.t.Helper()
	select {
	case value := <-from:
		return value
	default:
		s.t.Fatal("the wallet was handed nothing")
		panic("not reached")
	}
}

// pair has a new connection begin a Sign, and the wallet take the pairing and
// the proposal.
func (s *bwcScene) pair(purpose string, expectedAddress string) *relaytest.Proposal {
	s.t.Helper()
	if err := s.c.Sign(purpose, expectedAddress); err != nil {
		s.t.Fatal(err)
	}
	s.wait(bwcStep)
	// the second call is Connected turning true
	s.expect("the pairing is at the relay", bwcAwaitingApproval, bwcConnecting, bwcConnecting, bwcAwaitingApproval)
	if err := s.wallet.Pair(s.c.PairingUri()); err != nil {
		s.t.Fatal(err)
	}
	s.wait(bwcStep)
	return bwcTake(s, s.wallet.Proposals())
}

// signIn is pair, the wallet's approval, and the request the wallet is then
// handed. The app stays in front, so the approval is read on a socket that is
// up: Connected turns false when the session topic is added and true when it
// was read, which is the first and the last of the four calls.
func (s *bwcScene) signIn(purpose string, expectedAddress string) *relaytest.Request {
	s.t.Helper()
	s.wallet.Approve(s.pair(purpose, expectedAddress))
	s.wait(bwcStep)
	s.expect("the request is with the wallet", bwcAwaitingSignature, bwcAwaitingApproval, bwcConnecting, bwcAwaitingSignature, bwcAwaitingSignature)
	return bwcTake(s, s.wallet.Requests())
}

// again is a later Sign on the wallet session, and the request the wallet is
// handed.
func (s *bwcScene) again(purpose string, expectedAddress string) *relaytest.Request {
	s.t.Helper()
	if err := s.c.Sign(purpose, expectedAddress); err != nil {
		s.t.Fatal(err)
	}
	s.wait(bwcStep)
	s.expect("the next request is with the wallet", bwcAwaitingSignature, bwcConnecting, bwcAwaitingSignature)
	return bwcTake(s, s.wallet.Requests())
}

// answer has the wallet answer a request with a result, which ends the Sign
// in state.
func (s *bwcScene) answer(request *relaytest.Request, result any, state string) {
	s.t.Helper()
	s.wallet.Respond(request, result)
	s.wait(bwcStep)
	s.expect("the wallet answered", state, state)
}

// TC1, sequence 1 of design A.8: an iPhone, two visits to the wallet. Also
// TC4, and what the relay is shown of the app (design B.3 R15).
func TestBittensorWalletConnectTwoVisits(t *testing.T) {
	bwcPlayNova(t, func(t *testing.T, s *bwcScene) {
		c := s.c
		s.expect("nothing asked yet", bwcIdle)
		// (a) the pairing
		if err := c.Sign(BittensorWalletPurposeLogin, ""); err != nil {
			t.Fatal(err)
		}
		s.wait(bwcStep)
		s.expect("(a)", bwcAwaitingApproval, bwcConnecting, bwcConnecting, bwcAwaitingApproval)
		uri := c.PairingUri()
		if query := s.relay.Handshakes()[0].Query; query.Get("bundleId") != "network.ur" || query.Has("packageName") {
			t.Fatalf("the relay was shown %v", query)
		}
		// (b) the wallet is opened; the app leaves the foreground and its socket is closed at once
		if link := c.TakeWalletLink(); !strings.HasPrefix(uri, "wc:") || link != "novawallet://wc?uri="+url.QueryEscape(uri) {
			t.Fatalf("the pairing link is %q", link)
		}
		c.SetForeground(false)
		s.wait(bwcStep)
		s.expect("(b)", bwcAwaitingApproval, bwcAwaitingApproval)
		// (c) the user approves in the wallet: both answers wait at the relay
		s.wallet.Pair(uri)
		s.wait(bwcStep)
		s.wallet.Approve(bwcTake(s, s.wallet.Proposals()))
		s.wait(bwcStep)
		s.expect("(c)", bwcAwaitingApproval)
		// (d) back: the answers are read, the challenge is fetched, the request is sent
		c.SetForeground(true)
		s.wait(bwcStep)
		s.expect("(d)", bwcAwaitingSignature, bwcConnecting, bwcAwaitingSignature, bwcAwaitingSignature)
		request := bwcTake(s, s.wallet.Requests())
		if request.Message != bittensorTestMessage || request.Address != bittensorTestAliceSs58 || c.Address() != bittensorTestAliceSs58 ||
			c.PairingUri() != "" || c.Purpose() != BittensorWalletPurposeLogin || c.WalletId() != BittensorWalletNova {
			t.Fatalf("the request %+v for %s", request, c.Address())
		}
		// (e) the wallet is opened again
		if link := c.TakeWalletLink(); link != "novawallet://request" {
			t.Fatalf("the forward link is %q", link)
		}
		c.SetForeground(false)
		s.wait(bwcStep)
		s.expect("(e)", bwcAwaitingSignature, bwcAwaitingSignature)
		// (f) the user approves the signature and comes back
		s.wallet.Respond(request, bwcSignature)
		c.SetForeground(true)
		s.wait(bwcStep)
		s.expect("(f)", bwcSigned, bwcSigned)
		// (g)
		want := BittensorWalletProof{WalletId: BittensorWalletNova, Purpose: BittensorWalletPurposeLogin,
			Address: bittensorTestAliceSs58, Message: bittensorTestMessage, Signature: bittensorTestSignature}
		if proof := c.TakeProof(); proof == nil || *proof != want {
			t.Fatalf("the proof is %+v", proof)
		}
		c.Close()
		s.wait(bwcStep)
		s.expect("(g)", bwcClosed, bwcClosed)
		if deletes := s.wallet.Seen(wire.TagSessionDelete); deletes != 1 {
			t.Fatalf("the wallet saw %d deletes", deletes)
		}
	})
}

// TC1, sequence 2: Android with the process still running. The approval is
// read in the background and the request is with the wallet while it is in
// front: one visit.
func TestBittensorWalletConnectOneVisit(t *testing.T) {
	bwcPlay(t, BittensorWalletNova, BittensorWalletPlatformAndroid, relaytest.WalletOptions{}, func(t *testing.T, s *bwcScene) {
		c := s.c
		proposal := s.pair(BittensorWalletPurposeLogin, "")
		if query := s.relay.Handshakes()[0].Query; query.Get("packageName") != "com.bringyour.network" || query.Has("bundleId") {
			t.Fatalf("the relay was shown %v", query)
		}
		c.SetForeground(false)
		s.wallet.Approve(proposal)
		s.wait(bwcStep)
		s.expect("read in the background", bwcAwaitingSignature, bwcAwaitingApproval, bwcConnecting, bwcAwaitingSignature, bwcAwaitingSignature)
		s.answer(bwcTake(s, s.wallet.Requests()), bwcSignature, bwcSigned)
		c.SetForeground(true)
		if link := c.TakeWalletLink(); link != "" || c.TakeProof() == nil {
			t.Fatalf("back with the signature: the link %q, or no proof", link)
		}
		s.wait(bwcStep)
		s.expect("nothing more", bwcSigned)
	})
}

// TC1, sequence 3, and TC2: a wallet with no network signs in and then signs
// for the new network, on one wallet session.
func TestBittensorWalletConnectLoginThenCreate(t *testing.T) {
	bwcPlayNova(t, func(t *testing.T, s *bwcScene) {
		c := s.c
		s.answer(s.signIn(BittensorWalletPurposeLogin, ""), bwcSignature, bwcSigned)
		first := c.TakeProof()
		request := s.again(BittensorWalletPurposeCreate, first.Address)
		// TC9: this one is explained on the screen and opened with the button
		if link := c.TakeWalletLink(); link != "" || c.WalletLink() != "novawallet://request" {
			t.Fatalf("a create request: taken %q, for the button %q", link, c.WalletLink())
		}
		s.answer(request, bittensorTestSignature, bwcSigned)
		if second := c.TakeProof(); second == nil || second.Purpose != BittensorWalletPurposeCreate || second.Address != first.Address {
			t.Fatalf("the second proof is %+v", second)
		}
		requests := slices.DeleteFunc(s.relay.Published(), func(p relaytest.Published) bool { return p.Tag != wire.TagSessionRequest })
		if proposals := s.wallet.Seen(wire.TagSessionPropose); proposals != 1 || len(requests) != 2 || requests[0].Topic != requests[1].Topic {
			t.Fatalf("%d proposals and the requests %+v", proposals, requests)
		}
		create := `{"wallet_address":"` + bittensorTestAliceSs58 + `","blockchain":"TAO","purpose":"create"}`
		if asked := s.asked(); !slices.Equal(asked, []string{bwcLoginBody, create}) {
			t.Fatalf("the challenges asked for: %q", asked)
		}
	})
}

// TC1, sequence 4, and TC5: which of the wallet's accounts signs, and how its
// address is spelled to the wallet and to the server (design A.7).
func TestBittensorWalletConnectAccounts(t *testing.T) {
	for _, row := range []struct {
		name, purpose, expected string
		accounts                []string // the addresses the wallet offers on the chain
		asked, address, body    string   // the address in the request; of the connection and the proof; the challenge request
	}{
		{"the first", BittensorWalletPurposeAdd, "", []string{bittensorTestBobSs58, bittensorTestAliceSs58},
			bittensorTestBobSs58, bittensorTestBobSs58, `{"blockchain":"TAO","purpose":"add"}`},
		{"the typed one", BittensorWalletPurposeConnect, bittensorTestAliceSs58, []string{bittensorTestBobSs58, bittensorTestAliceSs58},
			bittensorTestAliceSs58, bittensorTestAliceSs58, `{"wallet_address":"` + bittensorTestAliceSs58 + `","blockchain":"TAO","purpose":"connect"}`},
		{"under another prefix", BittensorWalletPurposeLogin, "", []string{"nothing", bittensorTestAlicePolkadot},
			bittensorTestAlicePolkadot, bittensorTestAliceSs58, bwcLoginBody},
	} {
		t.Run(row.name, func(t *testing.T) {
			accounts := []string{}
			for _, address := range row.accounts {
				accounts = append(accounts, BittensorWalletConnectChain+":"+address)
			}
			bwcPlay(t, BittensorWalletNova, BittensorWalletPlatformIos, relaytest.WalletOptions{Accounts: accounts}, func(t *testing.T, s *bwcScene) {
				request := s.signIn(row.purpose, row.expected)
				s.answer(request, bwcSignature, bwcSigned)
				proof := s.c.TakeProof()
				if request.Address != row.asked || s.c.Address() != row.address || proof.Address != row.address || proof.Purpose != row.purpose ||
					!slices.Equal(s.asked(), []string{row.body}) {
					t.Fatalf("asked %s, the connection %s, the proof %+v, the challenge %q", request.Address, s.c.Address(), proof, s.asked())
				}
				// a later Sign that names no address stays with the account in use
				if later := s.again(row.purpose, ""); later.Address != row.asked {
					t.Fatalf("the later Sign asks %s", later.Address)
				}
			})
		})
	}
}

// TC1, sequence 5: the user comes back after the pairing deadline. What the
// wallet answered in time is still at the relay 330 s after the proposal, and
// is used; at 520 s it is gone, and two empty reads end the pairing.
func TestBittensorWalletConnectLateReturn(t *testing.T) {
	for _, row := range []struct {
		back  time.Duration
		state string
		calls []string
	}{
		{330 * time.Second, bwcAwaitingSignature, []string{bwcConnecting, bwcAwaitingSignature, bwcAwaitingSignature}},
		{520 * time.Second, bwcClosed, []string{bwcAwaitingApproval, bwcClosed}},
	} {
		t.Run(fmt.Sprint(row.back), func(t *testing.T) {
			bwcPlayNova(t, func(t *testing.T, s *bwcScene) {
				start := time.Now()
				proposal := s.pair(BittensorWalletPurposeLogin, "")
				s.c.SetForeground(false)
				s.wait(200*time.Second - time.Since(start))
				s.wallet.Approve(proposal)
				s.wait(row.back - time.Since(start))
				s.expect("nothing fails while the app is away", bwcAwaitingApproval, bwcAwaitingApproval)
				s.c.SetForeground(true)
				s.wait(3 * bwcStep)
				s.expect("back", row.state, row.calls...)
				if result := s.c.Result(); (row.state == bwcClosed) != (result != nil && result.BridgeErrorCode == BittensorWalletBridgeErrorWalletConnectExpired) {
					t.Fatalf("the result is %+v", result)
				}
			})
		})
	}
}

// bwcLog takes what is logged through connect's default logger: at every
// verbosity, or with what is above the default one kept apart in verbose.
type bwcLog struct {
	mu      sync.Mutex
	lines   []string
	verbose *bwcLog
}

func (l *bwcLog) Infof(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}
func (l *bwcLog) Info(args ...any)                    { l.Infof("%s", fmt.Sprint(args...)) }
func (l *bwcLog) Warningf(format string, args ...any) { l.Infof(format, args...) }
func (l *bwcLog) Errorf(format string, args ...any)   { l.Infof(format, args...) }
func (l *bwcLog) V(int32) connect.Verbose             { return cmp.Or(l.verbose, l) }
func (l *bwcLog) Enabled() bool                       { return true }

// A trace line (delta 5.3): the clock of the connection, and then a line the
// connection writes itself, as a whole, or one of its client, which package
// walletconnect holds against the forms of its own.
var bwcTraceLine = regexp.MustCompile(`^\d\d:\d\d:\d\d\.\d{3} (?:` + strings.Join([]string{
	`proposal T=[01] E=[01] R=[01] link=(?:https|scheme|bare) bg=\d+ ttl=\d+`,
	`sign (?:login|create|add|connect) first=[01]`,
	`state (?:idle|connecting|awaiting_approval|awaiting_signature|signed|failed|closed) -> [a-z_]+(?: [a-z_]+(?:/[a-z_]+)?)?`,
	`connected [01]`,
	`link (?:pair|forward) taken`,
	`challenge attempt \d+ (?:ok|failed)`,
	`request id=\d+`,
	`signature len=\d+ accepted=[01]`,
	`proof taken`,
	`(?:sock|fg|parked|resume|stopped|pairing|wait|OUT|write|rewrite|ack|give-up|push|IN|settle|deadline|read|expired|unreachable|end)(?: .*)?`,
}, "|") + `)$`)

// bwcHoldTrace holds the trace of a connection against its rule: every line is
// one it may write, and none holds one of the texts.
func bwcHoldTrace(t *testing.T, c *BittensorWalletConnect, texts ...string) []string {
	t.Helper()
	lines := c.TraceLines().getAll()
	for _, line := range lines {
		if !bwcTraceLine.MatchString(line) || slices.ContainsFunc(texts, func(text string) bool { return strings.Contains(line, text) }) {
			t.Errorf("traced: %q", line)
		}
	}
	return lines
}

// TC6, TC11, TC12 and sequence 6 of design A.8: every way a Sign ends without
// a proof, as the app is told it (design A.5): the state, the two codes and
// the fixed sentence, whether the wallet session was deleted, and how often a
// challenge was asked for. What the wallet wrote is in no result and in no
// log line.
func TestBittensorWalletConnectFailures(t *testing.T) {
	const (
		marker      = "MARKER-7f3a"
		declined    = "The request was declined in the wallet."
		expired     = "The request expired before the wallet answered."
		unreachable = "The wallet connection service could not be reached."
		noAccount   = "The wallet has no Bittensor account to sign with."
		notHeld     = "The wallet does not hold the address you entered."
		noChain     = "The wallet does not support Bittensor sign-in."
		incomplete  = "The wallet could not complete the request."
		ended       = "The wallet ended the connection."
	)
	log := &bwcLog{}
	connect.SetDefaultLogger(log)
	defer connect.SetDefaultLogger(nil)

	login := BittensorWalletPurposeLogin
	noRoute := errors.New("no route")
	// the wallet approves, and the challenge fetch answers as scripted
	approved := func(fetch func(s *bwcScene, ctx context.Context, n int) (*AuthWalletChallengeResult, error), wait time.Duration) func(s *bwcScene) {
		return func(s *bwcScene) {
			s.fetch = func(ctx context.Context, n int) (*AuthWalletChallengeResult, error) { return fetch(s, ctx, n) }
			s.wallet.Approve(s.pair(login, ""))
			s.wait(wait)
		}
	}
	// The clock jumps 5 min, as it does over a suspension. Not in the instant
	// the fetch begins: what the relay answers in that instant would be read
	// before the jump in one run and after it in another.
	jump := func(s *bwcScene) {
		time.Sleep(100 * time.Millisecond)
		s.offset.Add(300_000)
	}
	// the process is suspended in each of the first fetches, and none succeeds
	suspended := func(fetches int) func(s *bwcScene) {
		return approved(func(s *bwcScene, _ context.Context, n int) (*AuthWalletChallengeResult, error) {
			if n <= fetches {
				jump(s)
				time.Sleep(2 * time.Second)
			}
			return nil, noRoute
		}, 18*time.Second)
	}
	// the wallet approves with a settle of its own
	settled := func(accounts []string) func(s *bwcScene) {
		return func(s *bwcScene) {
			s.wallet.ApproveWith(s.pair(login, ""), func(settle *relaytest.SettleEdit) { settle.Accounts = accounts })
		}
	}
	// the wallet answers the proposal, or the request, with an error
	rejected := func(code int) func(s *bwcScene) {
		return func(s *bwcScene) { s.wallet.Reject(s.pair(login, ""), code, marker) }
	}
	refused := func(code int) func(s *bwcScene) {
		return func(s *bwcScene) { s.wallet.RespondError(s.signIn(login, ""), code, marker) }
	}
	for _, row := range []struct {
		name  string
		drive func(s *bwcScene)
		// what the listener is told from the helper's last look on, the last of
		// it being the state the Sign ends in; and the result
		calls, code, bridge, message string
		deletes, fetches             int
	}{
		// the pairing
		{"the connection declined", rejected(5000), "closed", "wallet_error", "user_rejected", declined, 0, 0},
		{"the proposal not supported", rejected(5100), "closed", "wallet_error", "unsupported_chain", noChain, 0, 0},
		{"another error to the proposal", rejected(9999), "closed", "wallet_error", "wallet_error", incomplete + " (code 9999)", 0, 0},
		{"no answer to the proposal", func(s *bwcScene) {
			s.pair(login, "")
			s.wait(300 * time.Second)
		}, "closed", "wallet_error", "walletconnect_expired", expired, 0, 0},
		{"the relay refuses the app", func(s *bwcScene) {
			s.relay.RefuseHandshakes(1, 403, `{"error":"Project not found"}`)
			s.c.Sign(login, "")
		}, "connecting closed", "wallet_error", "walletconnect_unavailable", unreachable, 0, 0},
		{"a session on another chain", settled([]string{"polkadot:91b171bb158e2d3848fa23a9f1c25182:" + bittensorTestAliceSs58}),
			"awaiting_approval closed", "wallet_error", "unsupported_chain", noChain, 1, 0},
		{"a session with no account", settled([]string{}), "awaiting_approval closed", "wallet_error", "no_account", noAccount, 1, 0},
		{"a session whose account is no address", settled([]string{BittensorWalletConnectChain + ":nothing"}),
			"awaiting_approval closed", "wallet_error", "no_account", noAccount, 1, 0},
		{"the typed address is not the wallet's", func(s *bwcScene) {
			s.wallet.Approve(s.pair(BittensorWalletPurposeConnect, bittensorTestBobSs58))
		}, "awaiting_approval closed", "wallet_error", "address_not_in_wallet", notHeld, 1, 0},
		// the challenge
		{"no challenge", func(s *bwcScene) {
			approved(func(*bwcScene, context.Context, int) (*AuthWalletChallengeResult, error) {
				return nil, noRoute
			}, 3*time.Second)(s)
			// the attempts are 1 s and 3 s apart: the third is still to come
			if asked := len(s.asked()); asked != 2 {
				s.t.Fatalf("%d attempts in 3 s", asked)
			}
		}, "awaiting_approval connecting connecting failed", "no_challenge", "", "", 0, 3},
		// an attempt the process was suspended in is not counted, three times at most
		{"a suspension in the first fetch", suspended(1), "awaiting_approval connecting failed", "no_challenge", "", "", 0, 4},
		{"a suspension in every fetch", suspended(9), "awaiting_approval connecting failed", "no_challenge", "", "", 0, 6},
		{"a challenge request that is never answered", approved(func(_ *bwcScene, ctx context.Context, _ int) (*AuthWalletChallengeResult, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}, 59*time.Second), "awaiting_approval connecting connecting failed", "no_challenge", "", "", 0, 3},
		// 60 s of running time end the leg: the fourth attempt is the first that counts, and the last
		{"never answered, and a suspension in every fetch", approved(func(s *bwcScene, ctx context.Context, _ int) (*AuthWalletChallengeResult, error) {
			jump(s)
			<-ctx.Done()
			return nil, ctx.Err()
		}, 61*time.Second), "awaiting_approval connecting failed", "no_challenge", "", "", 0, 4},
		{"a challenge that is none", approved(func(*bwcScene, context.Context, int) (*AuthWalletChallengeResult, error) {
			return &AuthWalletChallengeResult{MessageTemplate: "Sign in"}, nil
		}, 0), "awaiting_approval connecting failed", "invalid_challenge", "", "", 0, 1},
		// the signature
		{"the signature declined", refused(4001), "failed", "wallet_error", "user_rejected", declined, 0, 1},
		{"the request expired at the wallet", refused(8000), "failed", "wallet_error", "walletconnect_expired", expired, 0, 1},
		{"the request not supported", refused(5101), "closed", "wallet_error", "unsupported_chain", noChain, 1, 1},
		{"another error to the request", refused(9999), "failed", "wallet_error", "wallet_error", incomplete + " (code 9999)", 0, 1},
		{"the wallet ended the session", func(s *bwcScene) {
			s.signIn(login, "")
			s.wallet.DeleteSession()
		}, "closed", "wallet_error", "wallet_error", ended, 0, 1},
		{"the relay out of reach when the challenge expired", func(s *bwcScene) {
			s.signIn(login, "")
			s.relay.SetOffline(true)
			s.relay.Drop("")
			s.offset.Add(301_000)
			s.wait(22 * time.Second)
		}, "awaiting_signature failed", "wallet_error", "walletconnect_unavailable", unreachable, 0, 1},
		{"a signature that is none", func(s *bwcScene) {
			s.wallet.Respond(s.signIn(login, ""), marker)
		}, "failed", "invalid_signature", "", "", 0, 1},
		{"a signature after the challenge expired", func(s *bwcScene) {
			request := s.signIn(login, "")
			s.offset.Add(301_000)
			s.wallet.Respond(request, bwcSignature)
		}, "awaiting_signature failed", "challenge_expired", "", "", 0, 1},
	} {
		t.Run(row.name, func(t *testing.T) {
			bwcPlayNova(t, func(t *testing.T, s *bwcScene) {
				s.c.SetTrace(true)
				row.drive(s)
				s.wait(2 * bwcStep)
				calls := strings.Fields(row.calls)
				s.expect("the end", calls[len(calls)-1], calls...)
				// the trace has the codes of the end, and of a wallet's error its number alone (delta 5.4)
				lines, ended := bwcHoldTrace(t, s.c, marker), ""
				for _, line := range lines {
					if strings.Contains(line, " state ") {
						ended = line
					}
				}
				if end := " -> " + calls[len(calls)-1] + " " + strings.TrimSuffix(row.code+"/"+row.bridge, "/"); !strings.HasSuffix(ended, end) ||
					strings.Contains(row.message, "9999") != slices.ContainsFunc(lines, func(line string) bool { return strings.HasSuffix(line, " error 9999") }) {
					t.Fatalf("the trace does not end in %q, or has no code of the wallet's error: %q", end, lines)
				}
				want := BittensorWalletResult{ErrorCode: row.code, BridgeErrorCode: row.bridge, ErrorMessage: row.message}
				if result := s.c.Result(); result == nil || *result != want {
					t.Fatalf("the result is %+v, want %+v", result, want)
				}
				if deletes, fetches := s.wallet.Seen(wire.TagSessionDelete), len(s.asked()); deletes != row.deletes || fetches != row.fetches {
					t.Fatalf("the wallet saw %d deletes and %d challenges were asked for; want %d and %d", deletes, fetches, row.deletes, row.fetches)
				}
			})
		})
	}
	tagged := 0
	for _, line := range log.lines {
		// what a wallet wrote, or a panic that connect.HandleError contained
		if strings.Contains(line, marker) || strings.Contains(line, "Unexpected error") {
			t.Fatalf("logged: %s", line)
		}
		if strings.HasPrefix(line, "[bwc]") {
			tagged++
		}
	}
	if tagged == 0 {
		t.Fatalf("nothing of the client was logged, of %d lines", len(log.lines))
	}
}

// TC3: the challenge requests as the server is sent them, on the real clock,
// with the Api of an app.
func TestBittensorWalletConnectChallengeRequests(t *testing.T) {
	var mu sync.Mutex
	requests := []string{}
	_, api := newTestApi(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		requests = append(requests, r.URL.Path+" "+string(body))
		mu.Unlock()
		json.NewEncoder(w).Encode(bittensorTestChallenge())
	}))
	relay := relaytest.NewRelay(relaytest.RelayOptions{})
	defer relay.Close()
	wallet := relaytest.NewWallet(relay.Peer("wallet"), relaytest.WalletOptions{})
	defer wallet.Close()
	c, err := NewBittensorWalletConnect(api, BittensorWalletWalletConnect, BittensorWalletPlatformIos, "test-project", "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.configureClient = func(config *walletconnect.Config) { config.DialTLS = relay.DialTLS }
	states := make(chan string, 64)
	c.AddBittensorWalletConnectListener(bwcListenerFunc(func(state string) { states <- state }))
	paired := false
	sign := func(purpose string, expectedAddress string) *BittensorWalletProof {
		t.Helper()
		if err := c.Sign(purpose, expectedAddress); err != nil {
			t.Fatal(err)
		}
		for limit := time.After(20 * time.Second); ; {
			select {
			case state := <-states:
				// once: a second call in that state is Connected changing
				if state == bwcAwaitingApproval && !paired {
					paired = true
					wallet.Pair(c.PairingUri())
				}
				if state == bwcSigned {
					return c.TakeProof()
				}
			case proposal := <-wallet.Proposals():
				wallet.Approve(proposal)
			case request := <-wallet.Requests():
				wallet.Respond(request, bwcSignature)
			case <-limit:
				t.Fatalf("no proof for %s; the state is %s", purpose, c.State())
			}
		}
	}
	proof := sign(BittensorWalletPurposeLogin, "")
	sign(BittensorWalletPurposeCreate, proof.Address)
	mu.Lock()
	defer mu.Unlock()
	want := []string{"/auth/wallet-challenge " + bwcLoginBody,
		`/auth/wallet-challenge {"wallet_address":"` + bittensorTestAliceSs58 + `","blockchain":"TAO","purpose":"create"}`}
	if !slices.Equal(requests, want) {
		t.Fatalf("the server was sent %q, want %q", requests, want)
	}
}

// TC7 and TC11: a Sign that fails at the signature keeps the wallet session,
// and the next one asks on it with no second proposal. And the forms of a
// signature that are taken.
func TestBittensorWalletConnectSignsAgainAfterAFailure(t *testing.T) {
	bwcPlayNova(t, func(t *testing.T, s *bwcScene) {
		login := BittensorWalletPurposeLogin
		s.wallet.RespondError(s.signIn(login, ""), 4001, "no")
		s.wait(bwcStep)
		s.expect("declined", bwcFailed, bwcFailed)
		s.answer(s.again(login, ""), "0x"+strings.Repeat("ab", 63), bwcFailed)
		if code := s.c.Result().ErrorCode; code != BittensorWalletErrorInvalidSignature {
			t.Fatalf("a signature of 63 bytes: %s", code)
		}
		// 65 bytes, the first of which names the kind of key, and the bare string
		for _, result := range []any{map[string]string{"signature": "0x01" + strings.Repeat("ab", 64)}, bittensorTestSignature} {
			s.answer(s.again(login, ""), result, bwcSigned)
			if proof := s.c.TakeProof(); proof == nil || proof.Signature != bittensorTestSignature || s.c.Result() != nil {
				t.Fatalf("the proof of %v is %+v", result, proof)
			}
		}
		if proposals, requests := s.wallet.Seen(wire.TagSessionPropose), s.wallet.Seen(wire.TagSessionRequest); proposals != 1 || requests != 4 {
			t.Fatalf("the wallet saw %d proposals and %d requests", proposals, requests)
		}
	})
}

// TC8: a proof is handed out once, and not after its challenge expired; one
// that waits to be taken outlives the wallet session (design A.3 rules 2, 8).
func TestBittensorWalletConnectTakeProof(t *testing.T) {
	for name, after := range map[string]func(s *bwcScene){
		"once": func(s *bwcScene) {
			if s.c.TakeProof() == nil || s.c.TakeProof() != nil {
				s.t.Fatal("not once")
			}
			s.expect("taken", bwcSigned)
		},
		"expired": func(s *bwcScene) {
			s.offset.Add(300_000)
			if proof, result := s.c.TakeProof(), s.c.Result(); proof != nil || result == nil || *result != (BittensorWalletResult{ErrorCode: BittensorWalletErrorExpired}) {
				s.t.Fatalf("the proof %+v, the result %+v", proof, result)
			}
			s.expect("the challenge expired while the proof waited", bwcFailed, bwcFailed)
		},
		"the session ended": func(s *bwcScene) {
			s.wallet.DeleteSession()
			s.wait(bwcStep)
			s.expect("the proof waits", bwcSigned)
			if err := s.c.Sign(BittensorWalletPurposeLogin, ""); err == nil || !strings.HasPrefix(err.Error(), "closed: ") {
				s.t.Fatalf("a Sign on a session that ended: %v", err)
			}
			if s.c.TakeProof() == nil || s.c.Result() != nil {
				s.t.Fatal("no proof, or a result")
			}
			s.expect("taken", bwcClosed, bwcClosed)
		},
	} {
		t.Run(name, func(t *testing.T) {
			bwcPlayNova(t, func(t *testing.T, s *bwcScene) {
				s.answer(s.signIn(BittensorWalletPurposeLogin, ""), bwcSignature, bwcSigned)
				after(s)
			})
		})
	}
}

// TC9: the wallet is opened without a tap once for every waiting state, and
// only when the app is in front and has read what the wallet sent; WalletLink
// is the same link for the button, every time.
func TestBittensorWalletConnectTakeWalletLink(t *testing.T) {
	login := BittensorWalletPurposeLogin
	bwcPlay(t, BittensorWalletNova, BittensorWalletPlatformAndroid, relaytest.WalletOptions{}, func(t *testing.T, s *bwcScene) {
		c := s.c
		proposal := s.pair(login, "")
		// to this wallet on android the pairing is handed as it is
		uri := c.PairingUri()
		if c.WalletLink() != uri || c.TakeWalletLink() != uri || c.TakeWalletLink() != "" || c.WalletLink() != uri {
			t.Fatal("the pairing link is not taken once, or not the one for the button")
		}
		// the request reaches the wallet while the app is behind it
		c.SetForeground(false)
		s.wallet.Approve(proposal)
		s.wait(bwcStep)
		s.expect("in the background", bwcAwaitingSignature, bwcAwaitingApproval, bwcConnecting, bwcAwaitingSignature, bwcAwaitingSignature)
		if link := c.TakeWalletLink(); link != "" || !c.Connected() {
			t.Fatalf("%q was taken in the background", link)
		}
		c.SetForeground(true)
		if link := c.TakeWalletLink(); link != "" || c.Connected() {
			t.Fatalf("%q was taken before what the wallet sent was read", link)
		}
		s.wait(bwcStep)
		s.expect("in front again", bwcAwaitingSignature, bwcAwaitingSignature, bwcAwaitingSignature)
		if c.TakeWalletLink() != "novawallet://request" || c.TakeWalletLink() != "" || c.WalletLink() != "novawallet://request" {
			t.Fatal("the forward link is not taken once, or not the one for the button")
		}
	})
	// SetForeground counts before the first Sign too. Without that the client
	// would dial behind another app, and Connected would stay false once the
	// app is in front, so that the wallet were never opened.
	bwcPlayNova(t, func(t *testing.T, s *bwcScene) {
		s.c.SetForeground(false)
		if err := s.c.Sign(login, ""); err != nil {
			t.Fatal(err)
		}
		s.wait(bwcStep)
		s.expect("behind another app", bwcConnecting, bwcConnecting)
		s.c.SetForeground(true)
		s.wait(bwcStep)
		s.expect("in front", bwcAwaitingApproval, bwcConnecting, bwcAwaitingApproval)
		if dials := s.relay.Dials(); dials != 1 || s.c.TakeWalletLink() == "" {
			t.Fatalf("%d dials, or no link to open", dials)
		}
	})
	// the entry of any wallet has no link, and on ios Talisman's none that brings it forward
	for walletId, pairing := range map[string]string{BittensorWalletWalletConnect: "", BittensorWalletTalisman: "https://talisman.xyz/wc?uri=wc:"} {
		t.Run(walletId, func(t *testing.T) {
			bwcPlay(t, walletId, BittensorWalletPlatformIos, relaytest.WalletOptions{}, func(t *testing.T, s *bwcScene) {
				proposal := s.pair(login, "")
				if pairing != "" {
					pairing += url.QueryEscape(strings.TrimPrefix(s.c.PairingUri(), "wc:"))
				}
				if s.c.WalletLink() != pairing || s.c.TakeWalletLink() != pairing {
					t.Fatalf("the pairing link is %q", s.c.WalletLink())
				}
				s.wallet.Approve(proposal)
				s.wait(bwcStep)
				if link := s.c.WalletLink() + s.c.TakeWalletLink(); link != "" || s.c.State() != bwcAwaitingSignature {
					t.Fatalf("the forward link is %q in %s", link, s.c.State())
				}
			})
		})
	}
	// On android Talisman is brought forward by starting its app, for which
	// there is no link (delta 3.3): what is taken once, and what the button
	// gets, is the mark that says so.
	bwcPlay(t, BittensorWalletTalisman, BittensorWalletPlatformAndroid, relaytest.WalletOptions{}, func(t *testing.T, s *bwcScene) {
		s.signIn(login, "")
		if c := s.c; c.TakeWalletLink() != BittensorWalletLinkLaunchPackage || c.TakeWalletLink() != "" || c.WalletLink() != BittensorWalletLinkLaunchPackage {
			t.Fatal("the forward step is not taken once, or not the one for the button")
		}
	})
}

// TC10: a connection serves one purpose family (design A.3 rule 5).
func TestBittensorWalletConnectPurposeFamily(t *testing.T) {
	refused := func(s *bwcScene, purposes ...string) {
		state := s.c.State()
		for _, purpose := range purposes {
			if err := s.c.Sign(purpose, ""); err == nil || !strings.HasPrefix(err.Error(), "purpose_mismatch: ") {
				s.t.Fatalf("a Sign for %s: %v", purpose, err)
			}
		}
		s.expect("unchanged", state)
	}
	bwcPlayNova(t, func(t *testing.T, s *bwcScene) {
		s.answer(s.signIn(BittensorWalletPurposeLogin, ""), bwcSignature, bwcSigned)
		s.again(BittensorWalletPurposeCreate, s.c.TakeProof().Address)
		refused(s, BittensorWalletPurposeAdd, BittensorWalletPurposeConnect)
	})
	bwcPlayNova(t, func(t *testing.T, s *bwcScene) {
		s.pair(BittensorWalletPurposeAdd, "")
		refused(s, BittensorWalletPurposeLogin, BittensorWalletPurposeCreate, BittensorWalletPurposeConnect)
	})
}

// TC13: what the constructor and Sign refuse, by the code their text starts
// with (design A.5). A Sign that is refused changes nothing.
func TestBittensorWalletConnectRefusals(t *testing.T) {
	_, api := newTestApi(t, http.NotFoundHandler())
	for _, row := range []struct {
		api                                 *Api
		walletId, platform, projectId, text string
	}{
		{api, BittensorWalletNova, BittensorWalletPlatformMacos, "project", "unsupported_platform: "},
		{api, BittensorWalletTaoCom, BittensorWalletPlatformIos, "project", "unsupported_wallet: "},
		{api, BittensorWalletNova, BittensorWalletPlatformIos, "", "walletconnect_unavailable: "},
		{nil, BittensorWalletNova, BittensorWalletPlatformIos, "project", "no_challenge: "},
	} {
		if c, err := NewBittensorWalletConnect(row.api, row.walletId, row.platform, row.projectId, ""); c != nil || err == nil || !strings.HasPrefix(err.Error(), row.text) {
			t.Fatalf("a connection that is to be refused with %q: %v", row.text, err)
		}
	}
	bwcPlayNova(t, func(t *testing.T, s *bwcScene) {
		refused := func(purpose string, expectedAddress string, text string) {
			t.Helper()
			state := s.c.State()
			if err := s.c.Sign(purpose, expectedAddress); err == nil || !strings.HasPrefix(err.Error(), text) {
				t.Fatalf("a Sign that is to be refused with %q: %v", text, err)
			}
			s.expect("unchanged", state)
		}
		refused("vote", "", "unknown purpose: ")
		refused(BittensorWalletPurposeLogin, bittensorTestAlicePolkadot, "invalid_ss58_address: ")
		s.pair(BittensorWalletPurposeLogin, "")
		refused(BittensorWalletPurposeLogin, "", "busy: ")
		s.c.Close()
		s.expect("closed", bwcClosed, bwcClosed)
		refused(BittensorWalletPurposeLogin, "", "closed: ")
	})
}

// TC14: the session of a Sign has no redirect link, so no return url can be
// handed to it (design F.6).
func TestBittensorWalletConnectSessionTakesNoReturn(t *testing.T) {
	session := newBittensorWalletConnectSession(BittensorWalletNova, BittensorWalletPlatformIos, BittensorWalletPurposeLogin)
	uri := bittensorTestRedirectLink + "?address=" + bittensorTestAliceSs58
	if result := session.HandleBridgeReturn(uri, bittensorTestNowMillis); session.IsReturn(uri) || result.ErrorCode != BittensorWalletErrorNotReturn ||
		session.Transport() != BittensorWalletTransportWalletConnect {
		t.Fatalf("a return was taken (%t), answered %s, on the transport %s", session.IsReturn(uri), result.ErrorCode, session.Transport())
	}
}

// The return links an app may name (delta 2.3, 2.4): what is refused, what a
// wallet is shown of them in the proposal, beside the topic and the expiry of
// the pairing, and TC14 again on a connection that named them: a link opened
// with a proof in it is no return, whatever it is.
func TestBittensorWalletConnectReturnLinks(t *testing.T) {
	const native, universal = "com.bringyour.network.wallet://return", "https://ur.io/wallet/return"
	login := BittensorWalletPurposeLogin
	// the redirect of a proposal the wallet was handed ("" = it has none),
	// which also carries the topic and the expiry of the pairing uri
	redirect := func(s *bwcScene, proposal *relaytest.Proposal) string {
		s.t.Helper()
		var params struct {
			PairingTopic    string
			ExpiryTimestamp int64
			Proposer        struct {
				Metadata struct{ Redirect json.RawMessage }
			}
		}
		pairing, err := wire.ParsePairingUri(s.c.PairingUri())
		if err != nil || json.Unmarshal(proposal.Params, &params) != nil || params.PairingTopic != pairing.Topic || params.ExpiryTimestamp != pairing.ExpiryUnix {
			s.t.Fatalf("the proposal %s (%v)", proposal.Params, err)
		}
		return string(params.Proposer.Metadata.Redirect)
	}
	for _, row := range []struct{ native, universal, redirect string }{
		{"", "", ""},
		{native, "", `{"native":"` + native + `"}`},
		{"", universal, `{"universal":"` + universal + `"}`},
	} {
		bwcPlayNova(t, func(t *testing.T, s *bwcScene) {
			// a link that was named is taken back by naming none
			if err := errors.Join(s.c.SetReturnLinks(native, universal), s.c.SetReturnLinks(row.native, row.universal)); err != nil {
				t.Fatal(err)
			}
			if got := redirect(s, s.pair(login, "")); got != row.redirect {
				t.Fatalf("the redirect of (%q, %q) is %s", row.native, row.universal, got)
			}
		})
	}

	bwcPlay(t, BittensorWalletTalisman, BittensorWalletPlatformAndroid, relaytest.WalletOptions{}, func(t *testing.T, s *bwcScene) {
		c := s.c
		for _, taken := range [][2]string{
			{"app://" + strings.Repeat("a", 122), "https://ur.io"}, // 128 bytes
			{"app.example://back/path", "https://ur.io/back/"},
			{native, universal},
		} {
			if err := c.SetReturnLinks(taken[0], taken[1]); err != nil {
				t.Fatalf("%q: %v", taken, err)
			}
		}
		// each of these is refused, by itself, and changes nothing
		refused := func(nativeLink string, universalLink string) {
			t.Helper()
			if err := c.SetReturnLinks(nativeLink, universalLink); err == nil || !strings.HasPrefix(err.Error(), "invalid_return_link: ") ||
				strings.Contains(err.Error(), nativeLink) || strings.Contains(err.Error(), universalLink) {
				t.Fatalf("(%q, %q): %v", nativeLink, universalLink, err)
			}
		}
		for _, link := range []string{
			"app://back?x=1", "app://back?", "app://back#x", "app://back#", // a query, a fragment
			"app://user@back", "app://ba ck", "app://back\n", "app://b\x00ack", "app://b\u00e4ck", // userinfo; a space, a control character, no ascii
			"app://" + strings.Repeat("a", 123),                    // 129 bytes
			"back", "//back", "app:back", "app:///back", "://back", // no scheme, or no host behind it
			"http://back", "https://back", "wc://back", "file://back", "content://back", "intent://back", "javascript://back", "data://back",
			"ur://back", "UR://back", "urnetwork://back", // the schemes the apps act on
			"app://bittensor-sign-message", "app://Bittensor-Sign-Message:1/x", // the return of the browser bridge
		} {
			refused(link, "https://other.example/back")
		}
		for _, link := range []string{
			"https://ur.io/back?x=1", "https://ur.io/back#x", "https://user@ur.io/back", "https://ur.io:8443/back", "https://ur.io:/back",
			"https://ur.io/ba ck", "https://ur.io/" + strings.Repeat("a", 115),
			"http://ur.io/back", "app://back", "ur.io/back", "https:///back", "https:ur.io",
		} {
			refused("other.example://back", link)
		}
		proposal := s.pair(login, "")
		if got := redirect(s, proposal); got != `{"native":"`+native+`","universal":"`+universal+`"}` {
			t.Fatalf("the redirect is %s", got)
		}
		// a Sign was accepted: the proposal may be at the relay
		if err := c.SetReturnLinks("", ""); err == nil || !strings.HasPrefix(err.Error(), "busy: ") {
			t.Fatalf("after a Sign: %v", err)
		}
		s.wallet.Approve(proposal)
		s.wait(bwcStep)
		s.expect("the request is with the wallet", bwcAwaitingSignature, bwcAwaitingApproval, bwcConnecting, bwcAwaitingSignature, bwcAwaitingSignature)
		// the session of the Sign waits for the wallet now, and takes no link for its answer
		c.stateLock.Lock()
		session := c.session
		c.stateLock.Unlock()
		for _, link := range []string{native, universal} {
			uri := link + "?address=" + bittensorTestAliceSs58 + "&signature=" + bittensorTestSignature + "&purpose=login"
			if result := session.HandleBridgeReturn(uri, c.nowMillis()); session.IsReturn(link) || session.IsReturn(uri) || result.ErrorCode != BittensorWalletErrorNotReturn {
				t.Fatalf("a return on %s was taken (%t), answered %s", link, session.IsReturn(uri), result.ErrorCode)
			}
		}
		s.expect("nothing changed", bwcAwaitingSignature)
		if c.Result() != nil {
			t.Fatalf("a result: %+v", c.Result())
		}
		s.answer(bwcTake(s, s.wallet.Requests()), bwcSignature, bwcSigned)
	})
}

// TC17: a listener may call every method of the connection from inside a
// call, and one that panics stops neither the calls to the next listener nor
// the process. That no call is made on the goroutine of the caller is held
// by expect, in every test.
func TestBittensorWalletConnectListeners(t *testing.T) {
	bwcPlayNova(t, func(t *testing.T, s *bwcScene) {
		c := s.c
		c.AddBittensorWalletConnectListener(bwcListenerFunc(func(string) { panic("a listener that panics") }))
		told := []string{}
		c.AddBittensorWalletConnectListener(bwcListenerFunc(func(state string) {
			line := state + " in " + c.State() + c.TakeWalletLink()
			if c.TakeProof() != nil || c.Sign(BittensorWalletPurposeLogin, "") == nil {
				line += ", with a proof or a second Sign"
			}
			c.Close()
			s.mu.Lock()
			defer s.mu.Unlock()
			told = append(told, line)
		}))
		if err := c.Sign(BittensorWalletPurposeLogin, ""); err != nil {
			t.Fatal(err)
		}
		s.wait(bwcStep)
		s.expect("closed from inside a call", bwcClosed, bwcConnecting, bwcClosed)
		s.mu.Lock()
		defer s.mu.Unlock()
		if want := []string{"connecting in connecting", "closed in closed"}; !slices.Equal(told, want) {
			t.Fatalf("the listener after the one that panics was told %q, want %q", told, want)
		}
	})
}

// TC18: Close ends the connection at once and for good, and deletes the
// wallet session if there is one. A connection also ends with the context it
// was made under.
func TestBittensorWalletConnectClose(t *testing.T) {
	// the challenge is asked for, each attempt failing after 2 s: they end 2 s, 5 s and 10 s after the approval
	fetching := func(wait time.Duration) func(s *bwcScene) {
		return func(s *bwcScene) {
			s.fetch = func(context.Context, int) (*AuthWalletChallengeResult, error) {
				time.Sleep(2 * time.Second)
				return nil, errors.New("no route")
			}
			s.wallet.Approve(s.pair(BittensorWalletPurposeLogin, ""))
			s.wait(wait)
			s.expect("the challenge is asked for", bwcConnecting, bwcAwaitingApproval, bwcConnecting, bwcConnecting)
		}
	}
	for _, row := range []struct {
		name    string
		reach   func(s *bwcScene)
		deletes int
	}{
		{"while the wallet is asked to connect", func(s *bwcScene) { s.pair(BittensorWalletPurposeLogin, "") }, 0},
		{"while the wallet is asked to sign", func(s *bwcScene) { s.signIn(BittensorWalletPurposeLogin, "") }, 1},
		{"after a Sign that failed", func(s *bwcScene) {
			s.answer(s.signIn(BittensorWalletPurposeLogin, ""), "", bwcFailed)
		}, 1},
		{"with a proof that was not taken", func(s *bwcScene) {
			s.answer(s.signIn(BittensorWalletPurposeLogin, ""), bwcSignature, bwcSigned)
		}, 1},
		// a fetch that returns after Close does nothing, and no other follows it
		{"while the first attempt at the challenge is on its way", fetching(time.Second), 1},
		{"while the last attempt at the challenge is on its way", fetching(9 * time.Second), 1},
	} {
		t.Run(row.name, func(t *testing.T) {
			bwcPlayNova(t, func(t *testing.T, s *bwcScene) {
				row.reach(s)
				c, asked := s.c, len(s.asked())
				c.Close()
				if c.State() != bwcClosed || c.Result() != nil || c.PairingUri()+c.WalletLink()+c.TakeWalletLink() != "" || c.TakeProof() != nil || c.Connected() {
					t.Fatalf("after Close: the state %s, the result %+v, the link %q", c.State(), c.Result(), c.WalletLink())
				}
				c.Close()
				s.wait(3 * bwcStep)
				s.expect("closed once", bwcClosed, bwcClosed)
				if deletes := s.wallet.Seen(wire.TagSessionDelete); deletes != row.deletes || len(s.asked()) != asked {
					t.Fatalf("the wallet saw %d deletes, and %d challenges were asked for after Close", deletes, len(s.asked())-asked)
				}
			})
		})
	}
	// A Sign that waits is told that it is over, as when the wallet ends the
	// session; the result of one that failed is kept (design A.3 rule 7).
	for code, bridge := range map[int]string{0: BittensorWalletBridgeErrorWallet, 4001: BittensorWalletBridgeErrorUserRejected} {
		bwcPlayNova(t, func(t *testing.T, s *bwcScene) {
			if request := s.signIn(BittensorWalletPurposeLogin, ""); code != 0 {
				s.wallet.RespondError(request, code, "no")
				s.wait(bwcStep)
				s.expect("declined", bwcFailed, bwcFailed)
			}
			s.cancel()
			s.wait(bwcStep)
			s.expect("the context ended", bwcClosed, bwcClosed)
			if result := s.c.Result(); result == nil || result.BridgeErrorCode != bridge {
				t.Fatalf("the result is %+v, want %s", result, bridge)
			}
		})
	}
}

// The trace of a device test (delta 5): a login and a create on Talisman and
// android, in which the wallet writes a marker wherever a wallet can write.
// The trace says what happened, in order and with the clock of the connection
// in front; neither it nor the log holds a secret or the marker; every line is
// in the sdk log at the default verbosity; it is still there after Close. A
// connection that was never told to trace keeps nothing and logs nothing at
// that verbosity.
func TestBittensorWalletConnectTrace(t *testing.T) {
	const marker = "MARKER-7f3a"
	seed := wire.Key{0: 9, 31: 9}
	responder, _ := wire.NewKeyPair(bytes.NewReader(seed[:]))
	defer connect.SetDefaultLogger(nil)
	for _, traced := range []bool{false, true} {
		verbose := &bwcLog{}
		log := &bwcLog{verbose: verbose}
		connect.SetDefaultLogger(log)
		bwcPlay(t, BittensorWalletTalisman, BittensorWalletPlatformAndroid, relaytest.WalletOptions{Seed: seed}, func(t *testing.T, s *bwcScene) {
			c := s.c
			if traced {
				c.SetTrace(true)
			}
			proposal := s.pair(BittensorWalletPurposeLogin, "")
			uri, link := c.PairingUri(), c.TakeWalletLink()
			pairing, _ := wire.ParsePairingUri(uri)
			proposer, _ := wire.ParseKey(proposal.ProposerPublicKey)
			session, _ := wire.DeriveSymKey(seed, proposer)
			// a stranger who has the pairing, then the wallet with a settle and a request of its own making
			stranger := s.relay.Peer("stranger")
			defer stranger.Close()
			forged, _ := wire.SealRandom(pairing.SymKey, rand.Reader, []byte(`{"id":"`+marker+`","jsonrpc":"2.0","method":"wc_`+marker+`","params":"`+marker+`"}`))
			stranger.Publish(pairing.Topic, forged, 0, wire.TtlFiveMinutes)
			s.wallet.ApproveWith(proposal, func(settle *relaytest.SettleEdit) { settle.SkipSettle = true })
			_, err := s.wallet.Send("wc_sessionSettle", map[string]any{
				"relay": map[string]string{"protocol": "irn"},
				"controller": map[string]any{"publicKey": responder.Public.Hex(), "metadata": map[string]any{
					"name": marker, "description": marker, "url": "https://" + marker, "icons": []string{marker}, "redirect": map[string]string{"native": marker + "://"},
				}},
				"namespaces": map[string]*wire.Namespace{"polkadot": {
					Accounts: []string{BittensorWalletConnectChain + ":" + bittensorTestAliceSs58, BittensorWalletConnectChain + ":" + marker},
					Methods:  []string{BittensorWalletConnectMethod}, Events: []string{marker},
				}},
				"expiry": time.Now().Unix() + 3600,
			})
			if _, unknown := s.wallet.Send("wc_"+marker, marker); err != nil || unknown != nil {
				t.Fatalf("the settle (%v) or a request of the wallet (%v) was not answered", err, unknown)
			}
			s.wait(bwcStep)
			request := bwcTake(s, s.wallet.Requests())
			forward := c.TakeWalletLink()
			s.wallet.Respond(request, map[string]string{"signature": bittensorTestSignature, "note": marker})
			s.wait(bwcStep)
			proof := c.TakeProof()
			if proof == nil || forward != BittensorWalletLinkLaunchPackage || c.Sign(BittensorWalletPurposeCreate, proof.Address) != nil {
				t.Fatalf("the proof %+v, the forward step %q, or no second Sign", proof, forward)
			}
			s.wait(bwcStep)
			s.wallet.RespondError(bwcTake(s, s.wallet.Requests()), 4001, marker)
			s.wait(bwcStep)
			c.Close()
			s.wait(bwcStep)

			token := strings.TrimPrefix(s.relay.Handshakes()[0].Header.Get("Authorization"), "Bearer ")
			secrets := []string{uri, link, url.QueryEscape(uri), token, "test-project", marker, proposal.ProposerPublicKey, responder.Public.Hex(),
				bittensorTestAliceSs58, "q1w2e3r4t5y6u7i8o9p0a1s2d3f4g5h6j7k8l9z0x1c", "Sign in to URnetwork", strings.Repeat("ab", 64)}
			for _, key := range []wire.Key{pairing.SymKey, session} {
				secrets = append(secrets, wire.EncodeBase64(key[:]), fmt.Sprint(key[:]))
				// and no 9 characters of the key or of its topic
				for _, text := range []string{key.Hex(), wire.Topic(key)} {
					for i := 0; i+9 <= len(text); i++ {
						secrets = append(secrets, text[i:i+9])
					}
				}
			}
			lines := bwcHoldTrace(t, c, secrets...)
			logged := []string{}
			for _, line := range slices.Concat(log.lines, verbose.lines) {
				if slices.ContainsFunc(secrets, func(secret string) bool { return strings.Contains(line, secret) }) {
					t.Fatalf("logged: %s", line)
				}
			}
			for _, line := range log.lines {
				if text, tagged := strings.CutPrefix(line, "[bwc] "); tagged {
					logged = append(logged, text)
				}
			}
			if len(token) < 100 || !strings.HasPrefix(link, "https://talisman.xyz/wc?uri=wc:") || !slices.Equal(logged, lines) ||
				!slices.ContainsFunc(verbose.lines, func(line string) bool { return strings.HasPrefix(line, "[bwc]") }) {
				t.Fatalf("the token %q, the link %q, or the log at the default verbosity %q is not the trace %q", token, link, logged, lines)
			}
			if !traced {
				if list := c.TraceLines(); list == nil || list.Len() != 0 {
					t.Fatalf("a trace that was never on: %q", lines)
				}
				return
			}
			p, b, trace := "topic="+pairing.Topic[:8]+" ", "topic="+wire.Topic(session)[:8]+" ", strings.Join(lines, "\n")+"\n"
			rest, first := strings.CutPrefix(trace, "00:00:00.000 proposal T=1 E=1 R=0 link=https bg=45 ttl=300\n00:00:00.000 sign login first=1\n")
			// Lines of which each follows the one before by cause. "request id=" is not among them: the challenge
			// goroutine writes it when SignMessage has returned, and the loop that call woke writes its OUT line
			// before it or behind it. It is counted below.
			for _, want := range []string{
				" state idle -> connecting\n", " sock dial 1 relay.walletconnect.com\n", " OUT tag=1100 " + p,
				" request wc_sessionPropose T=1 E=1 R=0\n", " state connecting -> awaiting_approval\n", " link pair taken\n",
				" IN tag=0 " + p + "id=? request other\n", " IN tag=1101 " + p, " IN tag=1102 " + b, " settle ok accounts=2\n", " OUT tag=1103 " + b,
				" challenge attempt 1 ok\n", " OUT tag=1108 " + b, " state connecting -> awaiting_signature\n", " link forward taken\n",
				" IN tag=1109 " + b, " result signature=1\n", " signature len=130 accepted=1\n", " state awaiting_signature -> signed\n", " proof taken\n",
				" sign create first=0\n", " state signed -> connecting\n", " OUT tag=1108 " + b, " error 4001\n",
				" state awaiting_signature -> failed wallet_error/user_rejected\n", " state failed -> closed\n", " OUT tag=1112 " + b,
			} {
				_, after, found := strings.Cut(rest, want)
				if !found || !first {
					t.Fatalf("the trace does not begin with what is sent and the Sign, or has no %q after the lines before it:\n%s", want, trace)
				}
				rest = after
			}
			// a request of the wallet's own making, by its number and never by its name; the request line of each
			// of the two Signs; and the list is a copy
			copied := c.TraceLines()
			copied.Add(marker)
			if !strings.Contains(trace, " IN tag=0 "+b) || strings.Count(trace, " request other\n") != 2 || strings.Count(trace, " request id=") != 2 || c.TraceLines().Len() != len(lines) {
				t.Fatalf("the trace:\n%s", trace)
			}
		})
	}
}

// The trace keeps the last 256 lines, each with the clock of the connection
// in front, takes none while it is off, and keeps what it has when it is
// turned off.
func TestBittensorWalletConnectTraceKeepsTheLastLines(t *testing.T) {
	connect.SetDefaultLogger(&bwcLog{})
	defer connect.SetDefaultLogger(nil)
	c, err := newBittensorWalletConnect(context.Background(), BittensorWalletTalisman, BittensorWalletPlatformAndroid, "test-project", "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.nowMillis = func() int64 { return bittensorTestNowMillis + 123 }
	c.tracef("before")
	c.SetTrace(true)
	for i := range 257 {
		c.tracef("line %d", i+1)
	}
	c.SetTrace(false)
	c.tracef("after")
	if lines := c.TraceLines(); lines.Len() != 256 || lines.Get(0) != "14:00:00.123 line 2" || lines.Get(255) != "14:00:00.123 line 257" {
		t.Fatalf("%d lines, from %q to %q", lines.Len(), lines.Get(0), lines.Get(lines.Len()-1))
	}
}

// The options of a device test (delta 6): what a connection that was never
// told sends and does, and what each option changes of it. The members of the
// proposal are held as the wallet was handed them, and the first line of the
// trace and the line of the proposal itself say the same. A call that is
// refused changes nothing, and none is taken once a Sign was accepted.
func TestBittensorWalletConnectDeviceTestOptions(t *testing.T) {
	connect.SetDefaultLogger(&bwcLog{})
	defer connect.SetDefaultLogger(nil)
	const native = "com.bringyour.network.wallet://return"
	login, bit := BittensorWalletPurposeLogin, bittensorWalletTraceBit
	for _, row := range []struct {
		options       string // "none": SetDeviceTestOptions is not called
		native        string
		topic, expiry bool
		link          string
		background    int
		ttl           int64
		late          time.Duration // the wallet takes the pairing that long after it was made
	}{
		{"none", "", true, true, "https", 45, 300, 0},
		{"", native, true, true, "https", 45, 300, 0},
		{"-T", "", false, true, "https", 45, 300, 0},
		{" -e ", "", true, false, "https", 45, 300, 0},
		{"-E,-T,link=https", "", false, false, "https", 45, 300, 0},
		{"link=scheme,bg=0", "", true, true, "scheme", 0, 300, 0},
		{"LINK=Bare , BG=60 , TTL=60", "", true, true, "bare", 60, 60, 0},
		// the pairing of an hour: 400 s on the proposal is still at the relay and the approval is taken
		{"ttl=3600", "", true, true, "https", 45, 3600, 400 * time.Second},
	} {
		bwcPlay(t, BittensorWalletTalisman, BittensorWalletPlatformAndroid, relaytest.WalletOptions{}, func(t *testing.T, s *bwcScene) {
			c, start := s.c, time.Now().Unix()
			c.SetTrace(true)
			err := c.SetReturnLinks(row.native, "")
			if row.options != "none" {
				err = errors.Join(err, c.SetDeviceTestOptions(row.options))
			}
			if err = errors.Join(err, c.Sign(login, "")); err != nil {
				t.Fatalf("%q: %v", row.options, err)
			}
			s.wait(bwcStep)
			uri := c.PairingUri()
			pairing, err := wire.ParsePairingUri(uri)
			link := map[string]string{"https": "https://talisman.xyz/wc?uri=wc:" + url.QueryEscape(strings.TrimPrefix(uri, "wc:")),
				"scheme": "talisman://wc?uri=" + url.QueryEscape(uri), "bare": uri}[row.link]
			if err != nil || pairing.ExpiryUnix != start+row.ttl || c.WalletLink() != link || c.TakeWalletLink() != link {
				t.Fatalf("%q: the pairing %v (%v), made at %d, and the link %q, want %q", row.options, pairing, err, start, c.WalletLink(), link)
			}
			s.wait(row.late)
			s.wallet.Pair(uri)
			s.wait(bwcStep)
			proposal := bwcTake(s, s.wallet.Proposals())
			var params struct {
				PairingTopic    *string
				ExpiryTimestamp *int64
				Proposer        struct {
					Metadata struct{ Redirect json.RawMessage }
				}
			}
			sent, bits := s.relay.Published()[0], fmt.Sprintf("T=%d E=%d R=%d", bit(row.topic), bit(row.expiry), bit(row.native != ""))
			if err := json.Unmarshal(proposal.Params, &params); err != nil || (params.PairingTopic != nil) != row.topic || (params.ExpiryTimestamp != nil) != row.expiry ||
				row.topic && *params.PairingTopic != pairing.Topic || row.expiry && *params.ExpiryTimestamp != pairing.ExpiryUnix ||
				(params.Proposer.Metadata.Redirect != nil) != (row.native != "") || sent.Tag != wire.TagSessionPropose || int64(sent.Ttl) != row.ttl {
				t.Fatalf("%q: the proposal %s (%v), kept by the relay for %d s, of the pairing %+v", row.options, proposal.Params, err, sent.Ttl, pairing)
			}
			lines := bwcHoldTrace(t, c, uri, url.QueryEscape(uri))
			if lines[0] != fmt.Sprintf("00:00:00.000 proposal %s link=%s bg=%d ttl=%d", bits, row.link, row.background, row.ttl) ||
				!slices.ContainsFunc(lines, func(line string) bool { return strings.HasSuffix(line, " request wc_sessionPropose "+bits) }) ||
				!slices.ContainsFunc(lines, func(line string) bool { return strings.HasSuffix(line, fmt.Sprintf(" expires +%ds", row.ttl)) }) {
				t.Fatalf("%q: the trace does not say %s for %d s: %q", row.options, bits, row.ttl, lines)
			}
			// behind the wallet the socket is kept for the seconds of bg, and the flow goes on
			c.SetForeground(false)
			s.wait(bwcStep)
			sockets := s.relay.OpenSockets("")
			c.SetForeground(true)
			s.wallet.Approve(proposal)
			s.wait(3 * bwcStep)
			if (sockets == 0) != (row.background == 0) || c.State() != bwcAwaitingSignature {
				t.Fatalf("%q: %d sockets a second behind the wallet, and %s after its approval", row.options, sockets, c.State())
			}
		})
	}

	bwcPlay(t, BittensorWalletTalisman, BittensorWalletPlatformAndroid, relaytest.WalletOptions{}, func(t *testing.T, s *bwcScene) {
		c := s.c
		// each call replaces the options of the one before, and with none a connection is as it was made
		for _, options := range []string{"-T,-E,link=bare,bg=60,ttl=3600", " link=SCHEME , bg=0 , ttl=60 ", "", "-e", "  ", "-T"} {
			if err := c.SetDeviceTestOptions(options); err != nil || (strings.TrimSpace(options) == "") != (c.deviceTest == bittensorWalletDeviceTest{}) {
				t.Fatalf("%q: %v, and the options are %+v", options, err, c.deviceTest)
			}
		}
		// each of these is refused, for the option that is named, and changes nothing
		refused := func(c *BittensorWalletConnect, options string, option string) {
			t.Helper()
			if err := c.SetDeviceTestOptions(options); err == nil || err.Error() != "invalid_options: "+option {
				t.Fatalf("%q: %v", options, err)
			}
		}
		for options, option := range map[string]string{
			"-X": "-X", "T": "T", "-T=1": "-T=1", "-R": "-R", "-E,-T,-e": "-e", "-T,": "", ",": "", // unknown, twice, empty
			"link=web": "link=web", "link=": "link=", "link": "link", "link=scheme,link=bare": "link=bare",
			"bg=61": "bg=61", "bg=-1": "bg=-1", "bg=": "bg=", "bg=x": "bg=x", "bg=1,bg=2": "bg=2",
			"ttl=59": "ttl=59", "ttl=30": "ttl=30", "ttl=3601": "ttl=3601", "ttl=1e3": "ttl=1e3", "-E, ttl = 60": "ttl = 60",
		} {
			refused(c, options, option)
		}
		proposal := s.pair(login, "")
		if text := string(proposal.Params); strings.Contains(text, "pairingTopic") || !strings.Contains(text, "expiryTimestamp") || c.WalletLink() == c.PairingUri() {
			t.Fatalf("after the calls that were refused the proposal is %s and the link %q", text, c.WalletLink())
		}
		// a Sign was accepted: the proposal may be at the relay
		if err := c.SetDeviceTestOptions(""); err == nil || !strings.HasPrefix(err.Error(), "busy: ") {
			t.Fatalf("after a Sign: %v", err)
		}
		refused(c, "-X", "-X")
		// an entry with one form of the pairing link has no other
		nova, err := newBittensorWalletConnect(t.Context(), BittensorWalletNova, BittensorWalletPlatformIos, "test-project", "")
		if err != nil || nova.SetDeviceTestOptions("link=https,-T,bg=10") != nil {
			t.Fatalf("nova on ios: %v", err)
		}
		refused(nova, "link=scheme", "link=scheme")
		refused(nova, "link=bare", "link=bare")
	})
}
