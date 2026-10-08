//go:build !js && !ios_extension

package walletconnect

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/urnetwork/sdk/walletconnect/wire"
)

// Client is one connection to one wallet: it pairs, waits for the approval
// and the settle, sends one request at a time, and closes. What happens is
// told through Config.OnEvent, from one goroutine that is not the loop, one
// event at a time and in order; the client's methods may be called from
// inside it. Every method is safe to call from any goroutine and none waits.
type Client struct {
	config *Config
	tr     *transport
	engine *engine
	done   chan struct{}
	lastId atomic.Int64 // the last id of a message to the wallet

	// the events the owner was not told yet: no bound, so that the loop
	// never waits for a slow owner (R1)
	mu    sync.Mutex
	queue []Event
	wake  chan struct{}
}

// NewClient validates the config (project id, identifier name, namespace,
// chain, method) and starts the loop and the event goroutine. Nothing touches
// the network before Pair. The client ends with ctx.
func NewClient(ctx context.Context, config *Config) (*Client, error) {
	namespace, _, _ := strings.Cut(config.Chain, ":")
	switch {
	case config.ProjectId == "":
		return nil, errors.New("walletconnect: no project id")
	case config.IdentifierName != "" && config.IdentifierName != "bundleId" && config.IdentifierName != "packageName":
		return nil, errors.New("walletconnect: the identifier name is neither bundleId nor packageName")
	case !wire.IsCaip2(config.Chain) || config.NamespaceKey != namespace:
		return nil, errors.New("walletconnect: the chain is no CAIP-2 id of the namespace")
	case config.Method == "":
		return nil, errors.New("walletconnect: no method")
	case config.Timing != nil && config.Timing.Tick <= 0:
		return nil, errors.New("walletconnect: the timing has no tick")
	}
	config = config.withDefaults()
	keys, err := wire.NewKeyPair(config.Rand)
	if err != nil {
		return nil, err
	}
	c := &Client{config: config, done: make(chan struct{}), wake: make(chan struct{}, 1)}
	c.engine = &engine{client: c, config: config, timing: config.Timing, keys: keys, foreground: true}
	c.tr = newTransport(ctx, config, c.engine)
	c.engine.tr = c.tr
	go c.run()
	go c.deliver()
	return c, nil
}

// internalError is what the owner is told when a panic ended the client
// (R1).
func internalError() *Error { return &Error{Kind: ErrWallet, Detail: "internal error"} }

// run is the loop goroutine. EventClosed is the last event, and is queued
// when the loop has ended (R19): nothing runs on the engine any more.
func (c *Client) run() {
	c.tr.run()
	err := c.engine.closeErr
	if c.tr.crashed() {
		err = internalError()
	}
	c.emit(Event{Kind: EventClosed, Err: err})
}

// emit queues an event for the owner.
func (c *Client) emit(ev Event) {
	c.mu.Lock()
	c.queue = append(c.queue, ev)
	c.mu.Unlock()
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// deliver is the event goroutine; it ends with EventClosed. When the owner's
// callback panics the client is closed, and of what is queued the owner is
// told only the end, with the internal error (R1).
func (c *Client) deliver() {
	defer close(c.done)
	broken := false
	for range c.wake {
		c.mu.Lock()
		events := c.queue
		c.queue = nil
		c.mu.Unlock()
		for _, ev := range events {
			last := ev.Kind == EventClosed
			switch {
			case broken && last:
				ev.Err = internalError()
			case broken:
				continue
			}
			if c.call(ev) {
				broken = true
				c.Close()
			}
			if last {
				return
			}
		}
	}
}

// call tells the owner one event and reports whether that panicked. The
// value of the panic is not looked at: it may hold a secret.
func (c *Client) call(ev Event) (panicked bool) {
	defer func() { panicked = recover() != nil }()
	if c.config.OnEvent != nil {
		c.config.OnEvent(ev)
	}
	return false
}

// newId is the id of a message to the wallet: the time in milliseconds and
// three digits, as wire.NewPeerId has it, and above every id the client made
// before, so that no two are equal. SignMessage makes its id on the caller's
// goroutine, which is why the digits are not Config.Rand's: that is read on
// the loop only.
func (c *Client) newId() int64 {
	for {
		last := c.lastId.Load()
		id := max(wire.NewPeerId(c.config.Now(), nil), last+1)
		if c.lastId.CompareAndSwap(last, id) {
			return id
		}
	}
}

// Pair makes the pairing and proposes the session, once: EventPairingReady
// follows, or EventClosed.
func (c *Client) Pair() { c.tr.do(c.engine.pair) }

// SignMessage sends the one request, Config.Method on Config.Chain for an
// address and a message, on the settled session, and returns its id at once.
// One request at a time. Outcome: EventRequestSent, then EventRequestResult
// or EventRequestFailed (or EventClosed). deadlineMillis is the wall-clock
// deadline of the wait. It calls Config.Now on the caller's goroutine.
func (c *Client) SignMessage(address string, message string, deadlineMillis int64) int64 {
	id := c.newId()
	c.tr.do(func() { c.engine.request(id, address, message, deadlineMillis) })
	return id
}

// SetForeground tells the client that the app left the foreground or is in
// front again (R3). A client starts in the foreground.
func (c *Client) SetForeground(foreground bool) {
	c.tr.do(func() {
		c.engine.foreground = foreground
		c.tr.setForeground(foreground)
	})
}

// Close ends the client (R19); EventClosed with no error follows.
func (c *Client) Close() { c.tr.do(func() { c.engine.end(nil) }) }

// Done is closed when the loop and the event goroutine have ended.
func (c *Client) Done() <-chan struct{} { return c.done }

// ResumeEpoch is the number of resume edges handled (R2).
func (c *Client) ResumeEpoch() int64 { return c.tr.ResumeEpoch() }

// RunningSeconds is the running time of the client, in ticks counted.
func (c *Client) RunningSeconds() int64 { return c.tr.RunningSeconds() }
