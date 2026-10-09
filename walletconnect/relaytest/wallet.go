//go:build !js && !ios_extension

package relaytest

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sdk/walletconnect/wire"
)

const (
	// Bittensor, and the address of the development account //Alice
	defaultChain   = "polkadot:2f0555cc76fc2840a25a6ea3b9637146"
	defaultAddress = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
	defaultMethod  = "polkadot_signMessage"
	// how long a session lasts that the wallet settles
	sessionSeconds = 7 * 24 * 60 * 60
	// how long Send waits for the dapp's answer
	answerWait = 5 * time.Second

	methodPropose = "wc_sessionPropose"
	methodSettle  = "wc_sessionSettle"
	methodRequest = "wc_sessionRequest"
)

// the tag and the time to live a wallet publishes its own requests with
var requestTags = map[string][2]int{
	"wc_pairingDelete": {wire.TagPairingDelete, wire.TtlOneDay},
	"wc_pairingPing":   {wire.TagPairingPing, wire.TtlPing},
	methodSettle:       {wire.TagSessionSettle, wire.TtlFiveMinutes},
	"wc_sessionUpdate": {wire.TagSessionUpdate, wire.TtlOneDay},
	"wc_sessionExtend": {wire.TagSessionExtend, wire.TtlOneDay},
	"wc_sessionEvent":  {wire.TagSessionEvent, wire.TtlFiveMinutes},
	"wc_sessionDelete": {wire.TagSessionDelete, wire.TtlOneDay},
	"wc_sessionPing":   {wire.TagSessionPing, wire.TtlPing},
}

// WalletOptions says what the wallet holds and how it behaves.
type WalletOptions struct {
	// The wallet is handed its connection, so it makes no relay key. The
	// seed is the private key of its key agreement: with it a test can
	// derive the session key. The zero key means random.
	Seed     wire.Key
	Chain    string   // default "polkadot:2f0555cc76fc2840a25a6ea3b9637146"
	Accounts []string // CAIP-10; default one account on Chain with the ss58 address of //Alice
	Methods  []string // default {"polkadot_signMessage"}
	Dedup    bool     // true: a request delivered twice is served once; false: it is reported again
}

// Proposal is a wc_sessionPropose the wallet was handed.
type Proposal struct {
	Id                json.RawMessage
	ProposerPublicKey string
	Params            json.RawMessage
}

// Request is a wc_sessionRequest the wallet was handed.
type Request struct {
	Id      json.RawMessage
	ChainId string
	Method  string
	Address string
	Message string
}

// SettleEdit is what ApproveWith may change before sending.
type SettleEdit struct {
	Accounts      []string
	Methods       []string
	NamespaceKey  string
	ControllerKey string          // hex; default the responder key
	Expiry        json.RawMessage // default a number seven days ahead
	SkipSettle    bool
}

// channel is a topic with its key: the pairing or the session.
type channel struct {
	topic string
	key   wire.Key
}

// Wallet is the wallet side of one session, for tests. It does what it is
// told, which includes what no wallet should do, and nothing by itself: it
// answers no proposal, no request and no delete. Every method is safe to call
// from any goroutine.
type Wallet struct {
	conn      Conn
	options   WalletOptions
	keys      *wire.KeyPair
	proposals chan *Proposal
	requests  chan *Request
	done      chan struct{}
	closing   sync.Once

	mu      sync.Mutex
	pairing *channel
	session *channel
	lastId  int64
	seen    map[int]int
	served  map[string]bool             // the requests that were reported, by id
	waiting map[string]chan *wire.Frame // the answers Send waits for, by id
}

// NewWallet makes a wallet on a connection, which it reads from now on and
// closes with Close.
func NewWallet(conn Conn, options WalletOptions) *Wallet {
	if options.Chain == "" {
		options.Chain = defaultChain
	}
	if options.Accounts == nil {
		options.Accounts = []string{options.Chain + ":" + defaultAddress}
	}
	if options.Methods == nil {
		options.Methods = []string{defaultMethod}
	}
	var source io.Reader = rand.Reader
	if options.Seed != (wire.Key{}) {
		source = bytes.NewReader(options.Seed[:])
	}
	// neither source fails
	keys, _ := wire.NewKeyPair(source)
	w := &Wallet{
		conn:      conn,
		options:   options,
		keys:      keys,
		proposals: make(chan *Proposal, 16),
		requests:  make(chan *Request, 16),
		done:      make(chan struct{}),
		seen:      map[int]int{},
		served:    map[string]bool{},
		waiting:   map[string]chan *wire.Frame{},
	}
	go w.read()
	return w
}

// read takes what the connection hands the wallet until it is closed.
func (w *Wallet) read() {
	for message := range w.conn.Messages() {
		w.mu.Lock()
		w.seen[message.Tag]++
		var held *channel
		for _, ch := range []*channel{w.pairing, w.session} {
			if ch != nil && ch.topic == message.Topic {
				held = ch
			}
		}
		w.mu.Unlock()
		if held == nil {
			continue
		}
		plaintext, err := wire.Open(held.key, message.Message)
		if err != nil {
			continue
		}
		frame, err := wire.ParseFrame(plaintext)
		if err != nil {
			continue
		}
		id := string(frame.Id)
		switch frame.Method {
		case "":
			w.mu.Lock()
			answer := w.waiting[id]
			delete(w.waiting, id)
			w.mu.Unlock()
			if answer != nil {
				answer <- frame
			}
		case methodPropose:
			var params struct {
				Proposer struct {
					PublicKey string `json:"publicKey"`
				} `json:"proposer"`
			}
			json.Unmarshal(frame.Params, &params)
			select {
			case w.proposals <- &Proposal{Id: frame.Id, ProposerPublicKey: params.Proposer.PublicKey, Params: frame.Params}:
			case <-w.done:
			}
		case methodRequest:
			var params struct {
				Request struct {
					Method string `json:"method"`
					Params struct {
						Address string `json:"address"`
						Message string `json:"message"`
					} `json:"params"`
				} `json:"request"`
				ChainId string `json:"chainId"`
			}
			json.Unmarshal(frame.Params, &params)
			w.mu.Lock()
			again := w.served[id]
			w.served[id] = true
			w.mu.Unlock()
			if again && w.options.Dedup {
				continue
			}
			request := &Request{Id: frame.Id, ChainId: params.ChainId, Method: params.Request.Method,
				Address: params.Request.Params.Address, Message: params.Request.Params.Message}
			select {
			case w.requests <- request:
			case <-w.done:
			}
		}
	}
}

// publish seals a frame and publishes it on the pairing or the session topic.
func (w *Wallet) publish(ch *channel, frame []byte, tag int, ttl int) error {
	if ch == nil {
		return errors.New("relaytest: the wallet does not hold the topic yet")
	}
	message, err := wire.SealRandom(ch.key, rand.Reader, frame)
	if err != nil {
		return err
	}
	return w.conn.Publish(ch.topic, message, tag, ttl)
}

// channels are the pairing and the session of the moment.
func (w *Wallet) channels() (pairing *channel, session *channel) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.pairing, w.session
}

// Pair takes a pairing uri, as a wallet does that scanned or was handed it:
// the proposal that waits on its topic comes on Proposals.
func (w *Wallet) Pair(uri string) error {
	pairing, err := wire.ParsePairingUri(uri)
	if err != nil {
		return err
	}
	w.mu.Lock()
	w.pairing = &channel{topic: pairing.Topic, key: pairing.SymKey}
	w.mu.Unlock()
	return w.conn.Subscribe(pairing.Topic)
}

// Proposals are the proposals the wallet was handed, in order.
func (w *Wallet) Proposals() <-chan *Proposal { return w.proposals }

// Approve settles a session with what the wallet holds and approves the
// proposal: tag 1102 on the session topic, then tag 1101 on the pairing
// topic. The settle is at the relay before the dapp can know its topic.
func (w *Wallet) Approve(p *Proposal) error { return w.ApproveWith(p, nil) }

// ApproveWith is Approve with a settle that edit has changed.
func (w *Wallet) ApproveWith(p *Proposal, edit func(settle *SettleEdit)) error {
	proposer, err := wire.ParseKey(p.ProposerPublicKey)
	if err != nil {
		return err
	}
	symKey, err := wire.DeriveSymKey(w.keys.Private, proposer)
	if err != nil {
		return err
	}
	session := &channel{topic: wire.Topic(symKey), key: symKey}
	w.mu.Lock()
	w.session = session
	pairing := w.pairing
	w.mu.Unlock()
	if err := w.conn.Subscribe(session.topic); err != nil {
		return err
	}
	namespace, _, _ := strings.Cut(w.options.Chain, ":")
	settle := SettleEdit{
		Accounts:      w.options.Accounts,
		Methods:       w.options.Methods,
		NamespaceKey:  namespace,
		ControllerKey: w.keys.Public.Hex(),
		Expiry:        strconv.AppendInt(nil, time.Now().Unix()+sessionSeconds, 10),
	}
	if edit != nil {
		edit(&settle)
	}
	relay := map[string]string{"protocol": "irn"}
	if !settle.SkipSettle {
		params := map[string]any{
			"relay":      relay,
			"controller": map[string]string{"publicKey": settle.ControllerKey},
			"namespaces": map[string]*wire.Namespace{
				settle.NamespaceKey: {Accounts: settle.Accounts, Methods: settle.Methods, Events: []string{}},
			},
			"expiry": settle.Expiry,
		}
		if _, err := w.ask(session, methodSettle, params, false); err != nil {
			return err
		}
	}
	result := map[string]any{"relay": relay, "responderPublicKey": w.keys.Public.Hex()}
	return w.publish(pairing, wire.ResultFrame(p.Id, result), wire.TagSessionProposeApprove, wire.TtlFiveMinutes)
}

// Reject answers the proposal with an error, tag 1120.
func (w *Wallet) Reject(p *Proposal, code int, message string) error {
	pairing, _ := w.channels()
	return w.publish(pairing, wire.ErrorFrame(p.Id, code, message), wire.TagSessionProposeReject, wire.TtlFiveMinutes)
}

// DeletePairing publishes wc_pairingDelete on the pairing topic.
func (w *Wallet) DeletePairing() error {
	pairing, _ := w.channels()
	_, err := w.ask(pairing, "wc_pairingDelete", deleteReason, false)
	return err
}

// Requests are the session requests the wallet was handed, in order.
func (w *Wallet) Requests() <-chan *Request { return w.requests }

// Respond answers a request with a result, tag 1109.
func (w *Wallet) Respond(r *Request, result any) error {
	_, session := w.channels()
	return w.publish(session, wire.ResultFrame(r.Id, result), wire.TagSessionRequestResponse, wire.TtlFiveMinutes)
}

// RespondError answers a request with an error, tag 1109.
func (w *Wallet) RespondError(r *Request, code int, message string) error {
	_, session := w.channels()
	return w.publish(session, wire.ErrorFrame(r.Id, code, message), wire.TagSessionRequestResponse, wire.TtlFiveMinutes)
}

// DeleteSession publishes wc_sessionDelete on the session topic.
func (w *Wallet) DeleteSession() error {
	_, session := w.channels()
	_, err := w.ask(session, "wc_sessionDelete", deleteReason, false)
	return err
}

// Send publishes a request of the wallet's own on the session topic and
// returns the dapp's answer; none within five seconds is an error.
func (w *Wallet) Send(method string, params any) (*wire.Frame, error) {
	_, session := w.channels()
	return w.ask(session, method, params, true)
}

// SendOnPairing is Send on the pairing topic.
func (w *Wallet) SendOnPairing(method string, params any) (*wire.Frame, error) {
	pairing, _ := w.channels()
	return w.ask(pairing, method, params, true)
}

// the reason a wallet gives for ending a pairing or a session
var deleteReason = map[string]any{"code": 6000, "message": "User disconnected."}

// ask publishes a request with a new id and, when wait is set, waits for the
// answer to it.
func (w *Wallet) ask(ch *channel, method string, params any, wait bool) (*wire.Frame, error) {
	w.mu.Lock()
	// two ids of one millisecond can be equal
	id := max(wire.NewPeerId(time.Now().UnixMilli(), rand.Reader), w.lastId+1)
	w.lastId = id
	answer := make(chan *wire.Frame, 1)
	if wait {
		w.waiting[string(wire.IdToken(id))] = answer
	}
	w.mu.Unlock()
	tag, ttl := wire.TagUnsupported, wire.TtlFiveMinutes
	if known, ok := requestTags[method]; ok {
		tag, ttl = known[0], known[1]
	}
	if err := w.publish(ch, wire.RequestFrame(id, method, params), tag, ttl); err != nil || !wait {
		return nil, err
	}
	timeout := time.NewTimer(answerWait)
	defer timeout.Stop()
	select {
	case frame := <-answer:
		return frame, nil
	case <-timeout.C:
		return nil, errors.New("relaytest: the dapp did not answer")
	case <-w.done:
		return nil, errors.New("relaytest: the wallet is closed")
	}
}

// Seen is the number of messages with this relay tag the wallet was handed
// so far, whatever they hold.
func (w *Wallet) Seen(tag int) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.seen[tag]
}

// Close closes the wallet and its connection. It can be called more than
// once.
func (w *Wallet) Close() {
	w.closing.Do(func() { close(w.done) })
	w.conn.Close()
}
