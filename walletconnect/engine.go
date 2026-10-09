//go:build !js && !ios_extension

package walletconnect

import (
	"encoding/json"
	"regexp"
	"time"

	"github.com/urnetwork/sdk/walletconnect/wire"
)

// The methods of the pairing and Sign protocols that are read here.
const (
	methodPairingDelete  = "wc_pairingDelete"
	methodPairingPing    = "wc_pairingPing"
	methodSessionPropose = "wc_sessionPropose"
	methodSessionSettle  = "wc_sessionSettle"
	methodSessionRequest = "wc_sessionRequest"
	methodSessionDelete  = "wc_sessionDelete"

	// sign/error-codes: an unknown method, and a settle that is refused for
	// another reason than its namespaces
	codeUnsupportedMethod = 1001
	codeSettlementFailed  = 7000
)

// What a wallet asks on the session topic and is answered true, with the tag
// and the time to live of the answer. None of it changes anything here
// (design B.4).
var sessionAnswers = map[string][2]int{
	"wc_sessionPing":   {wire.TagSessionPingResponse, wire.TtlPing},
	"wc_sessionEvent":  {wire.TagSessionEventResponse, wire.TtlFiveMinutes},
	"wc_sessionUpdate": {wire.TagSessionUpdateResponse, wire.TtlOneDay},
	"wc_sessionExtend": {wire.TagSessionExtendResponse, wire.TtlOneDay},
}

// The words by which the text of a wallet's error is taken for a refusal of
// the user (design A.4). The text is matched and never kept.
var rejectText = regexp.MustCompile(`(?i)\b(rejected|cancell?ed|declined|denied)\b`)

// Config.Rand failed where a key or an iv was to be made. Nothing can be
// sent then, and the recover of the loop ends the client with its internal
// error (R1).
const noRandom = "walletconnect: the random source failed"

const (
	waitProposal = iota + 1
	waitSettle
	waitRequest
)

// wait is the one answer the engine waits for, with its deadline (R12).
type wait struct {
	kind     int
	topic    string        // a response counts on this topic only (R10)
	id       int64         // of the proposal or the request; a settle is no response and has none
	entry    *publishEntry // the publish it answers
	deadline int64         // wall clock, unix milliseconds

	// from the tick that saw the deadline passed
	marked bool
	seq    int64 // a read with this seq or a later one began after that tick
	reads  int   // of those, the ones that are over
	grace  int64 // the ticks left for them
}

// session is the session topic with its key, held from the approval on.
type session struct {
	topic     string
	key       wire.Key
	responder string // the wallet's public key as the approval gave it
}

// engine is the Sign protocol of one client: one pairing, one session, one
// request at a time. It is the handler of the transport, and the transport's
// loop owns every field: the methods run as callbacks of the transport or in
// a function passed to its do.
type engine struct {
	client *Client
	config *Config
	timing *Timing
	tr     *transport
	keys   *wire.KeyPair // of the key agreement; the proposal carries the public key

	paired     bool
	foreground bool
	closing    bool   // end was called
	closeErr   *Error // what EventClosed will say

	pairing *wire.Pairing // from the first socket until a settle is taken
	session *session
	settled bool
	wait    *wait
	// R17: the ticks left for the relay to acknowledge the proposal, 0 when
	// that is over. The proposal has no give-up of its own: it is queued
	// only when a socket opened, and this count also runs when none ever
	// does.
	firstConnect int64
	linger       int64 // R21: ticks in the foreground with a session and no request
}

// setWait changes what the engine waits for; a socket is kept while it waits
// for something (R4).
func (e *engine) setWait(w *wait) {
	e.wait = w
	e.tr.setWanted(w != nil)
}

// publish seals a frame under the key of its topic and queues it. giveUp is
// running time, 0 for never.
func (e *engine) publish(topic string, key wire.Key, frame []byte, tag int, ttl int, giveUp time.Duration) *publishEntry {
	message, err := wire.SealRandom(key, e.config.Rand, frame)
	if err != nil {
		panic(noRandom)
	}
	return e.tr.publish(topic, message, tag, ttl, e.tr.ticks(giveUp), nil)
}

// pair is Pair, on the loop.
func (e *engine) pair() {
	if e.paired {
		return
	}
	e.paired = true
	e.firstConnect = e.tr.ticks(e.timing.FirstConnect)
	e.tr.setWanted(true)
}

// request is SignMessage, on the loop.
func (e *engine) request(id int64, address string, message string, deadlineMillis int64) {
	switch {
	case !e.settled:
		e.client.emit(Event{Kind: EventRequestFailed, RequestId: id, Err: &Error{Kind: ErrDeleted, Detail: "there is no session"}})
	case e.wait != nil:
		e.client.emit(Event{Kind: EventRequestFailed, RequestId: id, Err: &Error{Kind: ErrWallet, Detail: "a request is pending"}})
	default:
		s := e.session
		w := &wait{kind: waitRequest, topic: s.topic, id: id, deadline: deadlineMillis}
		e.setWait(w)
		w.entry = e.publish(s.topic, s.key, wire.SessionRequest(id, e.config.Chain, e.config.Method, address, message),
			wire.TagSessionRequest, wire.TtlFiveMinutes, 0)
	}
}

// end is the one way out (R19): the wait is over, the wallet is told when it
// may list the session, no key is kept, and the transport writes what is
// queued and stops. EventClosed follows when its loop has ended.
func (e *engine) end(err *Error) {
	if e.closing {
		return
	}
	e.closing, e.closeErr = true, err
	if w := e.wait; w != nil {
		e.tr.cancelPublish(w.entry) // what was not acknowledged is not written again
	}
	if s := e.session; s != nil {
		e.publish(s.topic, s.key, wire.SessionDeleteRequest(e.client.newId()), wire.TagSessionDelete, wire.TtlOneDay, e.timing.CloseFlush)
	}
	e.wait, e.pairing, e.session, e.keys, e.settled = nil, nil, nil, nil, false
	if err != nil {
		e.tr.logf("walletconnect: ending: %s, code %d", err.Kind, err.Code)
	} else {
		e.tr.logf("walletconnect: ending")
	}
	e.tr.shutdown(e.tr.ticks(e.timing.CloseFlush))
}

// fail ends the wait for a reason of the client's own. A request that fails
// leaves the session; the pairing and the settle end the client (design A.4).
func (e *engine) fail(kind ErrorKind, detail string) {
	err := &Error{Kind: kind, Detail: detail}
	if w := e.wait; w.kind == waitRequest {
		e.endRequest(Event{Kind: EventRequestFailed, RequestId: w.id, Err: err})
	} else {
		e.end(err)
	}
}

// endRequest ends the pending request with what is told of it.
func (e *engine) endRequest(ev Event) {
	e.tr.logf("walletconnect: request %d ended, failed %t", ev.RequestId, ev.Err != nil)
	e.tr.cancelPublish(e.wait.entry)
	e.setWait(nil)
	e.linger = 0
	e.client.emit(ev)
}

// onOpen makes the pairing when the first socket has opened, so that its five
// minutes begin when the relay can be reached (design A.9). The topic and the
// waiter are there before the proposal is published (R7).
func (e *engine) onOpen() {
	if e.pairing != nil || e.session != nil {
		return
	}
	now := e.tr.nowMillis() / 1000
	pairing, err := wire.NewPairing(e.config.Rand, now)
	if err != nil {
		panic(noRandom)
	}
	pairing.ExpiryUnix = now + int64(e.timing.PairingTtl/time.Second)
	e.pairing = pairing
	w := &wait{kind: waitProposal, topic: pairing.Topic, id: e.client.newId(), deadline: pairing.ExpiryUnix * 1000}
	e.setWait(w)
	e.tr.addTopic(pairing.Topic)
	e.tr.logf("walletconnect: pairing %s proposed", pairing.Topic[:8])
	w.entry = e.publish(pairing.Topic, pairing.SymKey,
		wire.ProposeRequest(w.id, e.keys.Public, e.config.Metadata, e.config.NamespaceKey, e.config.Chain, e.config.Method),
		wire.TagSessionPropose, wire.TtlFiveMinutes, 0)
}

// onAcked hands the uri out when the proposal is at the relay (R20).
func (e *engine) onAcked(entry *publishEntry) {
	if w := e.wait; w != nil && w.kind == waitProposal && w.entry == entry {
		e.firstConnect = 0
		e.tr.logf("walletconnect: pairing %s ready", e.pairing.Topic[:8])
		e.client.emit(Event{Kind: EventPairingReady, PairingUri: e.pairing.Uri(), PairingExpiryMillis: e.pairing.ExpiryUnix * 1000})
	}
}

// onFirstWrite: a request counts as sent when it is written (R13).
func (e *engine) onFirstWrite(entry *publishEntry) {
	if w := e.wait; w != nil && w.kind == waitRequest && w.entry == entry {
		e.client.emit(Event{Kind: EventRequestSent, RequestId: w.id})
	}
}

// onGiveUp: what has a give-up is an answer or the delete, and nobody waits
// for those (design B.4).
func (e *engine) onGiveUp(*publishEntry) {}

func (e *engine) onConnected(connected bool) {
	e.client.emit(Event{Kind: EventConnected, Connected: connected})
}

func (e *engine) onFatal(err *Error) { e.end(err) }

// onTick counts the budgets of running time.
func (e *engine) onTick(_ int64, resumed bool) {
	if e.firstConnect > 0 { // R17
		if resumed {
			e.firstConnect = e.tr.ticks(e.timing.FirstConnect)
		} else if e.firstConnect--; e.firstConnect == 0 {
			e.end(&Error{Kind: ErrUnavailable, Detail: "the relay did not take the proposal in time"})
			return
		}
	}
	switch w := e.wait; {
	case w != nil && !w.marked:
		// R12: a deadline counts from the tick that sees it passed, and
		// then the mailbox is read
		if e.tr.nowMillis() >= w.deadline {
			w.marked, w.grace, w.seq = true, e.tr.ticks(e.timing.DeadlineGrace), e.tr.startRead()
		}
	case w != nil && resumed:
		w.grace = e.tr.ticks(e.timing.DeadlineGrace)
	case w != nil:
		if w.grace--; w.grace <= 0 {
			e.fail(ErrUnavailable, "the relay could not be reached after the deadline")
		}
	case e.settled && e.foreground: // R21
		if e.linger++; resumed {
			e.linger = 0
		} else if e.linger >= e.tr.ticks(e.timing.Linger) {
			e.end(nil)
		}
	}
}

// onRead: a wait whose deadline has passed ends with the second read that
// began after the loop saw it (R12).
func (e *engine) onRead(seq int64) {
	w := e.wait
	if w == nil || !w.marked || seq < w.seq {
		return
	}
	if w.reads++; w.reads < 2 {
		e.tr.startRead()
		return
	}
	e.fail(ErrExpired, "the wallet did not answer in time")
}

// onMessage takes a message of the wallet. What cannot be opened with the
// key of its topic, is no JSON-RPC object, or answers nothing that is pending
// on that topic is passed over (R10). The relay's tag is not looked at.
func (e *engine) onMessage(topic string, message string, _ int) {
	var key wire.Key
	onPairing := e.pairing != nil && topic == e.pairing.Topic
	switch {
	case onPairing:
		key = e.pairing.SymKey
	case e.session != nil && topic == e.session.topic:
		key = e.session.key
	default:
		return
	}
	plaintext, err := wire.Open(key, message)
	if err != nil {
		return
	}
	frame, err := wire.ParseFrame(plaintext)
	if err != nil {
		return
	}
	switch w := e.wait; {
	case frame.IsRequest() && onPairing:
		e.pairingRequest(frame)
	case frame.IsRequest():
		e.sessionRequest(frame)
	case w == nil || w.id == 0 || w.topic != topic || string(frame.Id) != string(wire.IdToken(w.id)):
	case w.kind == waitProposal:
		e.approved(frame)
	default:
		e.responded(frame)
	}
}

// kindOf is the class of an error a wallet answered with (design A.4). Only
// a request can have expired.
func kindOf(failure *wire.RpcError, request bool) ErrorKind {
	switch code := failure.Code; {
	case code == 4001, code >= 5000 && code <= 5003, rejectText.MatchString(failure.Message):
		return ErrRejected
	case code == 8000 && request:
		return ErrExpired
	case code >= 5100 && code <= 5104, code == 3001, code == 3005:
		return ErrUnsupported
	}
	return ErrWallet
}

// approved takes the answer to the proposal. With the wallet's key the
// session key is derived, and the session topic is held with its waiter
// before it is subscribed (R7).
func (e *engine) approved(frame *wire.Frame) {
	if frame.Error != nil {
		e.end(&Error{Kind: kindOf(frame.Error, false), Code: frame.Error.Code, Detail: "the wallet refused the proposal"})
		return
	}
	// a result that cannot be read leaves no key
	var result wire.ProposeResult
	json.Unmarshal(frame.Result, &result)
	responder, keyErr := wire.ParseKey(result.ResponderPublicKey)
	symKey, deriveErr := wire.DeriveSymKey(e.keys.Private, responder)
	if keyErr != nil || deriveErr != nil {
		e.end(&Error{Kind: ErrWallet, Code: wire.RpcCodeMalformed, Detail: "the approval is malformed"})
		return
	}
	e.session = &session{topic: wire.Topic(symKey), key: symKey, responder: result.ResponderPublicKey}
	e.setWait(&wait{kind: waitSettle, topic: e.session.topic, deadline: e.tr.nowMillis() + e.timing.SettleTtl.Milliseconds()})
	e.tr.addTopic(e.session.topic)
	e.tr.logf("walletconnect: approved, session %s", e.session.topic[:8])
}

// responded takes the answer to the request. A result that is neither a
// string nor an object with a signature is a result with no signature.
func (e *engine) responded(frame *wire.Frame) {
	ev := Event{Kind: EventRequestResult, RequestId: e.wait.id}
	switch {
	case frame.Error != nil:
		ev.Kind, ev.Err = EventRequestFailed, &Error{Kind: kindOf(frame.Error, true), Code: frame.Error.Code, Detail: "the wallet refused the request"}
	case frame.Result == nil:
		ev.Kind, ev.Err = EventRequestFailed, &Error{Kind: ErrWallet, Code: wire.RpcCodeMalformed, Detail: "the answer is malformed"}
	default:
		var object struct {
			Signature string `json:"signature"`
		}
		if json.Unmarshal(frame.Result, &ev.Signature) != nil && json.Unmarshal(frame.Result, &object) == nil {
			ev.Signature = object.Signature
		}
	}
	e.endRequest(ev)
}

// pairingRequest takes what the wallet asks on the pairing topic (R18).
func (e *engine) pairingRequest(frame *wire.Frame) {
	tag, ttl := wire.TagUnsupported, wire.TtlOneDay
	switch frame.Method {
	case methodSessionPropose:
		return // the proposal itself, echoed
	case methodPairingDelete:
		tag = wire.TagPairingDeleteResponse
	case methodPairingPing:
		tag, ttl = wire.TagPairingPingResponse, wire.TtlPing
	}
	e.publish(e.pairing.Topic, e.pairing.SymKey, wire.ResultFrame(frame.Id, true), tag, ttl, e.timing.WalletAnswerTtl)
	if frame.Method == methodPairingDelete && e.wait != nil && e.wait.kind == waitProposal {
		e.end(&Error{Kind: ErrRejected, Detail: "the wallet ended the pairing"})
	}
}

// sessionRequest takes what the wallet asks on the session topic (design
// B.4).
func (e *engine) sessionRequest(frame *wire.Frame) {
	s := e.session
	answer, tag, ttl := wire.ResultFrame(frame.Id, true), wire.TagUnsupported, wire.TtlOneDay
	switch known, ok := sessionAnswers[frame.Method]; {
	case frame.Method == methodSessionSettle:
		// taken once, while it is waited for; any other is not answered
		if e.wait != nil && e.wait.kind == waitSettle {
			e.settle(frame)
		}
		return
	case !e.settled || frame.Method == methodSessionRequest:
		return // nothing else counts before the settle, and only a wallet answers a request
	case frame.Method == methodSessionDelete:
		tag = wire.TagSessionDeleteResponse
	case ok:
		tag, ttl = known[0], known[1]
	default:
		answer = wire.ErrorFrame(frame.Id, codeUnsupportedMethod, "Unsupported method")
	}
	e.publish(s.topic, s.key, answer, tag, ttl, e.timing.WalletAnswerTtl)
	if frame.Method == methodSessionDelete {
		e.session = nil // the wallet has ended it: there is nothing to delete
		e.end(&Error{Kind: ErrDeleted, Detail: "the wallet ended the session"})
	}
}

// settle takes the wc_sessionSettle that is waited for. One that is refused
// is answered with the error, and the session the wallet now lists is
// deleted (design B.4).
func (e *engine) settle(frame *wire.Frame) {
	s := e.session
	var params wire.SettleParams
	kind, code, message := ErrWallet, codeSettlementFailed, "Session settlement is malformed"
	malformed := json.Unmarshal(frame.Params, &params) != nil
	if !malformed {
		kind, code, message = e.judge(&params)
	}
	if code != 0 {
		e.publish(s.topic, s.key, wire.ErrorFrame(frame.Id, code, message), wire.TagSessionSettleResponse, wire.TtlFiveMinutes, e.timing.WalletAnswerTtl)
		if malformed {
			code = wire.RpcCodeMalformed
		}
		e.end(&Error{Kind: kind, Code: code, Detail: "the session the wallet settled is not valid"})
		return
	}
	accounts := wire.ChainAccounts(params.Namespaces, e.config.NamespaceKey, e.config.Chain)
	e.tr.logf("walletconnect: session %s settled, %d accounts", s.topic[:8], len(accounts))
	e.publish(s.topic, s.key, wire.ResultFrame(frame.Id, true), wire.TagSessionSettleResponse, wire.TtlFiveMinutes, 0)
	// the pairing has done its work: nothing on its topic can be opened any more
	e.tr.removeTopic(e.pairing.Topic)
	e.pairing, e.settled, e.linger = nil, true, 0
	e.setWait(nil)
	e.client.emit(Event{Kind: EventSessionSettled, Accounts: accounts})
}

// judge says why a settle is refused: the kind for the owner, and the code
// and the text the wallet is answered with. The checks and their order are
// those of ur.io's client. No code: the settle is valid.
func (e *engine) judge(params *wire.SettleParams) (ErrorKind, int, string) {
	if params.Controller.PublicKey != e.session.responder {
		return ErrWallet, codeSettlementFailed, "Controller public key does not match the proposal response"
	}
	if failure := wire.ValidateNamespaces(e.config.NamespaceKey, e.config.Chain, e.config.Method, params.Namespaces); failure != nil {
		kind := ErrUnsupported
		if failure.Code == 5001 && failure.Message != "All chains must have at least one account" {
			kind = ErrNoAccount // no account at all, or one that is none
		}
		return kind, failure.Code, failure.Message
	}
	if expiry, ok := params.ExpiryUnix(); !ok || expiry <= e.tr.nowMillis()/1000 {
		return ErrWallet, codeSettlementFailed, "Session expiry is invalid"
	}
	return "", 0, ""
}
