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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

// bwcLog takes what is logged through connect's default logger, at every
// verbosity.
type bwcLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *bwcLog) Infof(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}
func (l *bwcLog) Info(args ...any)                    { l.Infof("%s", fmt.Sprint(args...)) }
func (l *bwcLog) Warningf(format string, args ...any) { l.Infof(format, args...) }
func (l *bwcLog) Errorf(format string, args ...any)   { l.Infof(format, args...) }
func (l *bwcLog) V(int32) connect.Verbose             { return l }
func (l *bwcLog) Enabled() bool                       { return true }

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
				row.drive(s)
				s.wait(2 * bwcStep)
				calls := strings.Fields(row.calls)
				s.expect("the end", calls[len(calls)-1], calls...)
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
