//go:build !js && !ios_extension

package walletconnect

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/urnetwork/sdk/walletconnect/wire"
)

// the message ids kept to drop a second delivery (R10)
const seenLimit = 256

// transportHandler is what the transport tells its owner. Every call is made
// on the loop, and none from inside a call the owner makes to the transport:
// what such a call causes is told when it has returned, in the order it
// happened.
type transportHandler interface {
	// a socket opened; called before the subscribes of the sync are written, so topics added here are part of it
	onOpen()
	// a message on a held topic, after its push was acknowledged and after de-duplication (R10)
	onMessage(topic string, message string, tag int)
	// a mailbox read completed: every held topic has a subscribe result of this round and the quiet window passed
	onRead(seq int64)
	// Connected changed (R6: true = synced)
	onConnected(connected bool)
	// a queued publish was written to a socket for the first time (R13)
	onFirstWrite(entry *publishEntry)
	// the relay acknowledged a publish
	onAcked(entry *publishEntry)
	// a publish left the queue at its give-up, neither acknowledged nor cancelled
	onGiveUp(entry *publishEntry)
	// once per counted tick (one second of running time); resumed = a resume edge was handled since the last call
	onTick(runningSeconds int64, resumed bool)
	// the transport stopped for good: the first connect was refused, three relay errors, three read-limit closes
	onFatal(err *Error)
}

// publishEntry is one irn_publish from the moment it is queued until the
// relay acknowledged it, the owner cancelled it, or its give-up.
type publishEntry struct {
	topic string
	tag   int
	data  any // the engine's own reference

	id       string // of the one frame, which is written again as it is (R9)
	frame    []byte
	written  bool  // to any socket
	gen      int64 // of the socket it was last written to
	giveUp   int64 // seconds of running time, 0 for never
	giveUpAt int64 // the tick
}

// transport keeps a relay socket alive as design B.3 says (R1 to R16, R19),
// with a topic set and a publish queue. One goroutine, run, owns everything
// that is not marked otherwise. The methods from nowMillis on may be called
// only on that goroutine: from a handler callback or from a function passed
// to do.
type transport struct {
	ctx     context.Context
	config  *Config
	timing  *Timing
	handler transportHandler
	key     ed25519.PrivateKey // the relay knows the client by it: one for every dial

	// any goroutine
	mu       sync.Mutex
	commands []func()
	over     bool          // the loop ended: do drops
	wake     chan struct{} // there are commands
	events   chan event
	done     chan struct{} // closed when the loop ended
	epoch    atomic.Int64  // resume edges handled
	running  atomic.Int64  // ticks counted
	crash    atomic.Bool

	exit     bool     // the loop is to end
	lastNow  int64    // Config.Now at the iteration before (R2)
	resumed  bool     // a resume edge since the last onTick
	reported bool     // the Connected the handler knows
	tell     []func() // handler calls that wait for the end of the iteration

	foreground   bool
	backgroundAt int64 // the tick at which the background socket is closed
	parked       bool  // closed on purpose in the background (R3)
	stopped      bool  // onFatal was told
	closing      bool  // shutdown was called (R19)
	closeFlush   int64
	closeAt      int64 // the tick at which the shutdown waits no longer
	closeDialed  bool  // its one dial was made

	wanted bool
	topics []string
	queue  []*publishEntry
	seen   []string // message ids, the oldest first

	gen        int64 // of the dial or the socket of the moment
	socket     *socket
	cancelDial context.CancelFunc // not nil while a dial is in flight
	backoff    bool               // the wait before the next dial runs
	attempts   int                // failed in a row (R4)
	urlIndex   int
	identifier bool // the app identifier is presented (R15, R16)
	everSynced bool
	readSeq    int64 // of the last round started
	// in a row: the errors of the relay to irn_subscribe and to irn_publish
	// (R16), and the sockets lost to a frame above the read limit (R4)
	subscribeErrors, publishErrors, readLimits int
}

// newTransport makes a transport; config has its defaults. It makes the
// client key: a random source that fails leaves none, and then the relay
// refuses the first dial.
func newTransport(ctx context.Context, config *Config, handler transportHandler) *transport {
	t := &transport{
		ctx:        ctx,
		config:     config,
		timing:     config.Timing,
		handler:    handler,
		wake:       make(chan struct{}, 1),
		events:     make(chan event),
		done:       make(chan struct{}),
		foreground: true,
		identifier: config.IdentifierName != "" && config.IdentifierValue != "",
	}
	if seed, err := wire.NewKey(config.Rand); err == nil {
		t.key = wire.ClientKey(seed)
	}
	return t
}

// run is the loop. It returns when a shutdown completed, when ctx ended, or
// when a panic was recovered (crashed); no callback is made afterwards.
func (t *transport) run() {
	ticker := time.NewTicker(t.timing.Tick)
	defer func() {
		// R1: the value is not looked at, it may hold a secret
		if recover() != nil {
			t.crash.Store(true)
		}
		ticker.Stop()
		t.drop()
		t.mu.Lock()
		t.over, t.commands = true, nil
		t.mu.Unlock()
		close(t.done)
	}()
	t.lastNow = t.nowMillis()
	for !t.exit {
		var ev event
		var commands []func()
		select {
		case <-t.ctx.Done():
			return
		case <-t.wake:
			t.mu.Lock()
			commands, t.commands = t.commands, nil
			t.mu.Unlock()
		case ev = <-t.events:
		case <-ticker.C:
			ev.kind = evTick
		}
		// R2, before what woke the loop is looked at
		now := t.nowMillis()
		gap := now - t.lastNow
		t.lastNow = now
		if limit := t.timing.SuspendGap.Milliseconds(); gap > limit || gap < -limit {
			t.resume()
		}
		for _, command := range commands {
			if t.exit {
				return
			}
			command()
			t.advance()
		}
		t.handle(ev)
		t.advance()
	}
}

// do runs f on the loop, in call order. It never blocks, and f is dropped
// once the loop ended.
func (t *transport) do(f func()) {
	t.mu.Lock()
	if !t.over {
		t.commands = append(t.commands, f)
	}
	t.mu.Unlock()
	select {
	case t.wake <- struct{}{}:
	default:
	}
}

// crashed reports that run ended because a panic was recovered.
func (t *transport) crashed() bool { return t.crash.Load() }

// ResumeEpoch is the number of resume edges handled.
func (t *transport) ResumeEpoch() int64 { return t.epoch.Load() }

// RunningSeconds is the number of ticks counted.
func (t *transport) RunningSeconds() int64 { return t.running.Load() }

func (t *transport) nowMillis() int64 { return t.config.Now() }

func (t *transport) logf(format string, args ...any) {
	if t.config.Logf != nil {
		t.config.Logf(format, args...)
	}
}

// trace is one line of Config.Trace, which says what a line may hold. A topic
// is named by 8 characters and only when it is held: the topic of a push that
// is not held is a text the relay wrote.
func (t *transport) trace(format string, args ...any) {
	if t.config.Trace != nil {
		t.config.Trace(format, args...)
	}
}

// bit is a bool as a trace line has it.
func bit(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ticks is a running-time budget in ticks.
func (t *transport) ticks(d time.Duration) int64 { return int64(d / t.timing.Tick) }

// after runs f on the loop when d has passed, unless a resume edge was
// handled or the dial or the socket of now was let go meanwhile.
func (t *transport) after(d time.Duration, f func()) {
	epoch, gen := t.epoch.Load(), t.gen
	time.AfterFunc(d, func() {
		t.do(func() {
			if t.epoch.Load() == epoch && t.gen == gen {
				f()
			}
		})
	})
}

func (t *transport) handle(ev event) {
	switch {
	case ev.kind == evTick:
		t.tick()
	case ev.kind == evPanic:
		panic("walletconnect: a goroutine of the transport panicked")
	case ev.gen != t.gen:
		// of a dial or a socket that was let go
		if ev.ws != nil {
			ev.ws.Close()
		}
	case ev.kind == evDialed:
		t.dialed(ev)
	case ev.kind == evLost:
		t.lose(ev.err)
	case ev.kind == evPing:
		t.socket.idle = 0
	case ev.kind == evFrame:
		t.socket.idle = 0
		t.frame(t.socket, ev.text)
	}
}

// advance ends every iteration of the loop: the handler is told what
// happened, what may be written is written, and a socket is dialled or the
// loop ended when the state asks for it.
func (t *transport) advance() {
	for !t.exit {
		switch s := t.socket; {
		case s != nil && s.failed:
			t.lose(nil)
		case t.connected() != t.reported:
			t.reported = !t.reported
			t.handler.onConnected(t.reported)
		case len(t.tell) > 0:
			call := t.tell[0]
			t.tell = t.tell[1:]
			call()
		case !t.flush():
			t.connect()
			return
		}
	}
}

// connect ends the loop when a shutdown has nothing left to wait for (R19),
// and dials when a socket is needed and none is there or on its way (R4).
func (t *transport) connect() {
	if t.closing && (len(t.queue) == 0 || t.running.Load() >= t.closeAt) {
		t.hangUp("shutdown")
		t.exit = true
		return
	}
	if t.socket != nil || t.cancelDial != nil {
		return
	}
	if t.closing {
		if !t.closeDialed {
			t.closeDialed = true
			t.dial()
		}
		return
	}
	if t.backoff || !t.needed() {
		return
	}
	if t.attempts == 0 {
		t.dial()
		return
	}
	// attempt n comes min(base x 2^(n-1), max) after the one before, give or take the jitter
	wait := t.timing.BackoffMax
	if doublings := t.attempts - 1; doublings < 16 {
		wait = min(t.timing.BackoffBase<<doublings, wait)
	}
	t.backoff = true
	t.after(time.Duration(float64(wait)*(1+t.timing.BackoffJitter*(2*rand.Float64()-1))), func() {
		t.backoff = false
		if t.needed() {
			t.dial()
		}
	})
}

// needed reports that a socket is to be kept: a wait is pending or a publish
// is queued, and nothing says to stay closed.
func (t *transport) needed() bool {
	return (t.wanted || len(t.queue) > 0) && !t.parked && !t.stopped
}

// failedAttempt counts a dial that failed, or a socket that ended before it
// was healthy (R4). The next attempt goes to the other host (R5).
func (t *transport) failedAttempt() {
	t.attempts++
	t.urlIndex++
}

// lose lets go of a socket that ended or stopped answering (R4, R14). err is
// what its reader ended with, nil when the loop gives the socket up itself.
func (t *transport) lose(err error) {
	s := t.socket
	t.logf("walletconnect: socket %d lost after %d s", s.gen, s.age)
	// of a close frame the code alone, 0 with none: its reason is a text of the relay
	closed := &websocket.CloseError{}
	errors.As(err, &closed)
	t.trace("sock lost %d age=%ds code=%d", s.gen, s.age, closed.Code)
	t.drop()
	if t.readLimits++; !errors.Is(err, websocket.ErrReadLimit) {
		t.readLimits = 0
	}
	switch {
	case t.readLimits >= t.timing.ReadLimitCloses:
		t.fatal(ErrWallet, 0, "the relay sent frames above the read limit")
	case s.wasSynced && s.age >= t.ticks(t.timing.HealthySocket):
		t.attempts = 0
	default:
		t.failedAttempt()
	}
}

// relayError takes a JSON-RPC error of the relay to irn_subscribe or
// irn_publish: the call is made again on a new socket, and the third error in
// a row ends the transport (R16). The rows of the two calls are counted
// apart: a publish is made again behind a sync, whose subscribes succeed.
func (t *transport) relayError(row *int, code int) {
	if *row++; *row >= t.timing.RelayCallErrors {
		t.fatal(ErrUnavailable, code, "the relay answered its calls with an error")
		return
	}
	t.lose(nil)
}

// fatal stops the transport for good. A shutdown is not told: it is on its
// way out.
func (t *transport) fatal(kind ErrorKind, code int, detail string) {
	t.drop()
	if t.closing || t.stopped {
		return
	}
	t.stopped = true
	t.logf("walletconnect: stopped: %s, code %d", kind, code)
	t.trace("stopped %s code=%d", kind, code)
	t.tell = append(t.tell, func() { t.handler.onFatal(&Error{Kind: kind, Code: code, Detail: detail}) })
}

// resume handles a resume edge (R2).
func (t *transport) resume() {
	t.logf("walletconnect: resumed")
	t.epoch.Add(1)
	t.trace("resume %d", t.epoch.Load())
	t.resumed = true
	t.drop()
	t.attempts = 0
	t.parked = !t.foreground
	// every budget of running time starts again
	now := t.running.Load()
	t.closeAt = now + t.closeFlush
	for _, e := range t.queue {
		e.giveUpAt = now + e.giveUp
	}
}

// tick counts one second of running time and looks at every budget.
func (t *transport) tick() {
	if t.parked && !t.closing {
		return // R3: no budget runs while closed on purpose
	}
	now := t.running.Add(1)
	if !t.foreground && !t.parked && now >= t.backgroundAt {
		t.park()
	}
	t.queue = slices.DeleteFunc(t.queue, func(e *publishEntry) bool {
		gone := e.giveUp > 0 && now >= e.giveUpAt
		if gone {
			t.trace("give-up %v", e.data)
			t.tell = append(t.tell, func() { t.handler.onGiveUp(e) })
		}
		return gone
	})
	if s := t.socket; s != nil {
		s.age++
		s.idle++
		silent := s.idle >= t.ticks(t.timing.Idle) // R11c
		for _, c := range s.calls {
			silent = silent || now >= c.expires // R11a, R11b
		}
		switch {
		case silent:
			t.lose(nil)
		case t.wanted && s.synced && !s.settling:
			if s.rest++; s.rest >= t.ticks(t.timing.ProbeInterval) {
				t.startRound(s, t.timing.ProbeTimeout)
			}
		}
	}
	resumed := t.resumed
	t.resumed = false
	t.tell = append(t.tell, func() { t.handler.onTick(now, resumed) })
}

// frame takes one text frame of the socket.
func (t *transport) frame(s *socket, text []byte) {
	frame, err := wire.ParseFrame(text)
	if err != nil {
		return
	}
	id := string(frame.Id)
	switch c := s.calls[id]; {
	case frame.Method == wire.MethodSubscription:
		t.pushed(s, frame)
	case frame.IsRequest():
		// nothing else is asked of a client
	case c == nil:
		t.published(s, frame)
	case c.unsubscribe:
		delete(s.calls, id) // best effort, whatever the answer
	case frame.Error != nil:
		t.relayError(&t.subscribeErrors, frame.Error.Code)
	default:
		delete(s.calls, id)
		t.subscribeErrors = 0
		if slices.Contains(t.topics, c.topic) {
			var subscriptionId string
			json.Unmarshal(frame.Result, &subscriptionId)
			s.subscribed[c.topic] = subscriptionId
		}
		if s.waiting--; s.waiting == 0 {
			t.quiet(s)
		}
	}
}

// published takes the relay's answer to an irn_publish that was written to
// this socket; any other answer is passed over.
func (t *transport) published(s *socket, frame *wire.Frame) {
	i := slices.IndexFunc(t.queue, func(e *publishEntry) bool { return e.id == string(frame.Id) && e.gen == s.gen })
	switch {
	case i < 0:
	case frame.Error != nil:
		t.relayError(&t.publishErrors, frame.Error.Code)
	default:
		e := t.queue[i]
		t.queue = slices.Delete(t.queue, i, i+1)
		t.publishErrors = 0
		t.trace("ack %v", e.data)
		t.tell = append(t.tell, func() { t.handler.onAcked(e) })
	}
}

// pushed takes an irn_subscription (R10).
func (t *transport) pushed(s *socket, frame *wire.Frame) {
	// acknowledged at once, with the id as it came, before anything else
	t.write(s, wire.ResultFrame(frame.Id, true))
	if s.settling && s.waiting == 0 {
		t.quiet(s) // R6: a push starts the quiet window again
	}
	// what cannot be read of the params leaves its member empty: no push is
	// lost to a member that nothing here needs
	var params wire.SubscriptionParams
	json.Unmarshal(frame.Params, &params)
	if !slices.Contains(t.topics, params.Data.Topic) {
		t.trace("push tag=%d dropped not-held", params.Data.Tag)
		return // R7: dropped only when the topic is not held
	}
	topic := params.Data.Topic[:min(8, len(params.Data.Topic))]
	if id := wire.MessageId(params.Data.Message); !slices.Contains(t.seen, id) {
		if t.seen = append(t.seen, id); len(t.seen) > seenLimit {
			t.seen = t.seen[1:]
		}
		t.trace("push tag=%d topic=%s", params.Data.Tag, topic)
		t.tell = append(t.tell, func() { t.handler.onMessage(params.Data.Topic, params.Data.Message, params.Data.Tag) })
	} else {
		t.trace("push tag=%d topic=%s dropped duplicate", params.Data.Tag, topic)
	}
}

// newId is the id of a call to the relay, distinct from every id that waits
// for its answer.
func (t *transport) newId() int64 {
	id := wire.NewRelayId(t.nowMillis(), t.config.Rand)
	for t.pendingId(string(wire.IdToken(id))) {
		id++
	}
	return id
}

func (t *transport) pendingId(token string) bool {
	return t.socket != nil && t.socket.calls[token] != nil ||
		slices.ContainsFunc(t.queue, func(e *publishEntry) bool { return e.id == token })
}

// subscribe writes irn_subscribe for a topic.
func (t *transport) subscribe(s *socket, topic string, timeout time.Duration) {
	id := t.newId()
	s.calls[string(wire.IdToken(id))] = &call{topic: topic, expires: t.running.Load() + t.ticks(timeout)}
	s.waiting++
	s.settling = true
	t.write(s, wire.RequestFrame(id, wire.MethodSubscribe, wire.SubscribeParams{Topic: topic}))
}

// startRound reads the mailbox: irn_subscribe for every held topic, written
// back to back (R6). On a socket that is synced it is the probe too (R11a).
func (t *transport) startRound(s *socket, timeout time.Duration) {
	t.readSeq++
	s.round, s.again, s.settling = t.readSeq, false, true
	for _, topic := range t.topics {
		t.subscribe(s, topic, timeout)
	}
	if s.waiting == 0 {
		t.quiet(s) // no topic is held
	}
}

// quiet starts the wait that ends a round: Quiet with no further push (R6).
// The first sync of a client has nothing to wait for: nothing was published
// that could have been answered.
func (t *transport) quiet(s *socket) {
	s.quiet++
	if !t.everSynced {
		t.settled(s)
		return
	}
	window := s.quiet
	t.after(t.timing.Quiet, func() {
		if s.quiet == window && s.waiting == 0 {
			t.settled(s)
		}
	})
}

// settled ends a round, or the wait for the subscribe of a new topic: the
// socket is synced.
func (t *transport) settled(s *socket) {
	if round := s.round; round != 0 {
		t.tell = append(t.tell, func() { t.handler.onRead(round) })
	}
	if !s.wasSynced {
		t.logf("walletconnect: socket %d synced", s.gen)
		t.trace("sock synced %d", s.gen)
	}
	s.settling, s.round, s.rest = false, 0, 0
	s.synced, s.wasSynced, t.everSynced = true, true, true
	if s.again {
		t.startRound(s, t.timing.ProbeTimeout)
	}
}

// flush writes the queued publishes that may go out, in order and back to
// back (R6): one that was never written as soon as the socket is subscribed,
// one that an earlier socket was written only when this one is synced. A
// shutdown writes them all (R19). It reports whether it wrote.
func (t *transport) flush() bool {
	wrote := false
	for s := t.socket; s != nil; wrote = true {
		i := slices.IndexFunc(t.queue, func(e *publishEntry) bool { return e.gen != s.gen })
		if i < 0 {
			break
		}
		e := t.queue[i]
		if !t.closing && (len(s.subscribed) < len(t.topics) || e.written && !s.synced) {
			break
		}
		if !t.write(s, e.frame) {
			return true
		}
		if e.gen = s.gen; !e.written {
			e.written = true
			t.trace("write %v sock=%d", e.data, s.gen)
			t.tell = append(t.tell, func() { t.handler.onFirstWrite(e) })
		} else {
			t.trace("rewrite %v sock=%d", e.data, s.gen)
		}
	}
	return wrote
}

// addTopic holds a topic: registered at once (R7), and subscribed on the
// socket if one is open. Until that subscribe has its result and the quiet
// window passed, the socket is not synced.
func (t *transport) addTopic(topic string) {
	if slices.Contains(t.topics, topic) {
		return
	}
	t.topics = append(t.topics, topic)
	if s := t.socket; s != nil && !t.closing {
		s.synced = false
		t.subscribe(s, topic, t.timing.CallTimeout)
	}
}

// removeTopic lets go of a topic: irn_unsubscribe, best effort. Later pushes
// for it are dropped.
func (t *transport) removeTopic(topic string) {
	i := slices.Index(t.topics, topic)
	if i < 0 {
		return
	}
	t.topics = slices.Delete(t.topics, i, i+1)
	s := t.socket
	if s == nil {
		return
	}
	if subscriptionId, subscribed := s.subscribed[topic]; subscribed {
		delete(s.subscribed, topic)
		id := t.newId()
		s.calls[string(wire.IdToken(id))] = &call{unsubscribe: true, expires: t.running.Load() + t.ticks(t.timing.CallTimeout)}
		t.write(s, wire.RequestFrame(id, wire.MethodUnsubscribe, wire.UnsubscribeParams{Topic: topic, Id: subscriptionId}))
	}
}

// publish queues an irn_publish (R6, R9). message is the sealed envelope.
// giveUpSeconds is running time from now; 0 = never.
func (t *transport) publish(topic string, message string, tag int, ttl int, giveUpSeconds int64, data any) *publishEntry {
	id := t.newId()
	e := &publishEntry{
		topic:    topic,
		tag:      tag,
		data:     data,
		id:       string(wire.IdToken(id)),
		frame:    wire.RequestFrame(id, wire.MethodPublish, wire.PublishParams{Topic: topic, Message: message, Ttl: ttl, Tag: tag}),
		giveUp:   giveUpSeconds,
		giveUpAt: t.running.Load() + giveUpSeconds,
	}
	t.queue = append(t.queue, e)
	t.flush()
	return e
}

// cancelPublish takes an entry out of the queue: the peer answered it (R9).
func (t *transport) cancelPublish(entry *publishEntry) {
	t.queue = slices.DeleteFunc(t.queue, func(e *publishEntry) bool { return e == entry })
}

// setWanted says that a wait is pending: a socket is kept (R4). A queue that
// is not empty keeps one by itself.
func (t *transport) setWanted(wanted bool) { t.wanted = wanted }

// startRead starts a mailbox read now if the socket is synced; otherwise the
// next sync is the read. It returns the seq that onRead will report. A read
// in progress is followed by a new one.
func (t *transport) startRead() int64 {
	switch s := t.socket; {
	case s == nil || s.failed || t.closing:
	case s.settling:
		s.again = true
	default:
		t.startRound(s, t.timing.ProbeTimeout)
		return t.readSeq
	}
	return t.readSeq + 1
}

// park closes the socket on purpose, at the end of its time in the
// background (R3).
func (t *transport) park() {
	t.trace("parked after %ds", t.config.BackgroundSocketSeconds)
	t.parked = true
	t.hangUp("parked")
}

// setForeground is R3.
func (t *transport) setForeground(foreground bool) {
	switch s := t.socket; {
	case !foreground && t.foreground:
		t.trace("fg 0")
		t.foreground = false
		t.backgroundAt = t.running.Load() + int64(t.config.BackgroundSocketSeconds)
		if t.config.BackgroundSocketSeconds == 0 {
			t.park()
		}
	case foreground && !t.foreground:
		t.trace("fg 1")
		t.foreground = true
		t.resume()
	case foreground && s != nil && s.synced && !s.settling:
		// an inactive / active flicker: the socket is kept if it answers
		t.startRound(s, t.timing.ProbeTimeout)
	}
}

func (t *transport) connected() bool { return t.socket != nil && t.socket.synced }

// shutdown is R19: one dial attempt if something is queued and no socket is
// up; write what is queued; wait for acknowledgements up to flushSeconds of
// running time; close 1000; end run. An entry that must not be written again
// is cancelled before.
func (t *transport) shutdown(flushSeconds int64) {
	if !t.closing {
		t.closing, t.closeFlush, t.closeAt = true, flushSeconds, t.running.Load()+flushSeconds
		t.closeDialed = t.cancelDial != nil // a dial that is in flight is the one
	}
}
