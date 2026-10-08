//go:build !js && !ios_extension

package relaytest

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/urnetwork/sdk/walletconnect/wire"
)

// Message is one message as a connection is handed it: what was published,
// out of its irn_subscription.
type Message struct {
	Topic   string
	Message string
	Tag     int
}

// Conn is what the test wallet speaks; *Peer (in process) and the result of
// DialRelay (a real socket) implement it.
//
// Subscribe and Publish return when the relay has answered. Messages is the
// one channel of the connection, with every message it was handed, in order;
// it is closed when the connection is. A message was acknowledged to the
// relay when it was taken in, before anyone reads the channel. Close can be
// called more than once; a message that was not read is lost.
type Conn interface {
	Subscribe(topic string) error
	Publish(topic string, message string, tag int, ttl int) error
	Messages() <-chan Message
	Close()
}

var (
	_ Conn = (*Peer)(nil)
	_ Conn = (*socketConn)(nil)
)

var (
	errPeerClosed = errors.New("relaytest: the peer is closed")
	errPeerZombie = errors.New("relaytest: the peer is a zombie: the relay does not hear it")
	errConnClosed = errors.New("relaytest: the connection is closed")
)

// inbox is the queue behind the Messages channel of a connection. Taking a
// message in never waits for a reader.
type inbox struct {
	mu    sync.Mutex
	queue []Message
	wake  chan struct{}
	done  chan struct{}
	out   chan Message
	once  sync.Once
}

func newInbox() *inbox {
	return &inbox{
		wake: make(chan struct{}, 1),
		done: make(chan struct{}),
		out:  make(chan Message),
	}
}

// newClosedInbox is the inbox of a connection that never was: its channel is
// closed.
func newClosedInbox() *inbox {
	b := newInbox()
	b.close()
	close(b.out)
	return b
}

func (b *inbox) put(message Message) {
	b.mu.Lock()
	b.queue = append(b.queue, message)
	b.mu.Unlock()
	select {
	case b.wake <- struct{}{}:
	default:
	}
}

func (b *inbox) close() {
	b.once.Do(func() { close(b.done) })
}

// run hands the queue to whoever reads the channel, until the inbox is
// closed. It closes the channel when it ends.
func (b *inbox) run() {
	defer close(b.out)
	for {
		b.mu.Lock()
		var message Message
		have := len(b.queue) > 0
		if have {
			message = b.queue[0]
			b.queue = b.queue[1:]
		}
		b.mu.Unlock()
		if !have {
			select {
			case <-b.wake:
				continue
			case <-b.done:
				return
			}
		}
		select {
		case b.out <- message:
		case <-b.done:
			return
		}
	}
}

// Peer is a client of the relay that is in the process: no socket, no token,
// no frames. It follows the same mailbox rules as a socket client, and it
// acknowledges every push at once.
type Peer struct {
	relay *Relay
	ep    *endpoint
	inbox *inbox
	// guarded by the relay's lock
	closed bool
}

// Peer attaches an in-process client with the given client id: same mailbox
// rules as a socket client; it acknowledges every push at once.
//
// A second peer with a client id is that client coming back: it finds what
// was kept for the client id, after it subscribes. The peer of a closed
// relay is closed.
func (r *Relay) Peer(clientId string) *Peer {
	p := &Peer{relay: r}
	p.ep = &endpoint{clientId: clientId, peer: p, topics: map[string]bool{}}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		p.closed = true
		p.inbox = newClosedInbox()
		return p
	}
	p.inbox = newInbox()
	r.endpoints = append(r.endpoints, p.ep)
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		p.inbox.run()
	}()
	return p
}

// usable says why the peer cannot call the relay, nil when it can. The
// relay's lock is held.
func (p *Peer) usable() error {
	switch {
	case p.relay.closed:
		return errRelayClosed
	case p.closed:
		return errPeerClosed
	case p.ep.zombie:
		return errPeerZombie
	}
	return nil
}

// Subscribe makes the peer a subscriber of the topic. What the mailbox of its
// client id holds is handed to Messages.
func (p *Peer) Subscribe(topic string) error {
	r := p.relay
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := p.usable(); err != nil {
		return err
	}
	if topic == "" {
		return errors.New("relaytest: no topic")
	}
	r.pushAll(r.subscribe(p.ep, topic), p.ep)
	return nil
}

// Publish hands a message to the relay and returns when the relay answers:
// at once, or, when a recipient's socket does not acknowledge the push, when
// the relay has given up waiting for it.
func (p *Peer) Publish(topic string, message string, tag int, ttl int) error {
	r := p.relay
	r.mu.Lock()
	if err := p.usable(); err != nil {
		r.mu.Unlock()
		return err
	}
	if topic == "" {
		r.mu.Unlock()
		return errors.New("relaytest: no topic")
	}
	if refusal := ttlRefusal(ttl); refusal != "" {
		r.mu.Unlock()
		return errors.New("relaytest: the relay refused the publish: " + refusal)
	}
	answered := make(chan struct{})
	r.publish(p.ep, wire.PublishParams{Topic: topic, Message: message, Ttl: ttl, Tag: tag}, func() {
		// a relay that is closing answers nobody
		if !r.closed {
			close(answered)
		}
	})
	r.mu.Unlock()
	select {
	case <-answered:
		return nil
	case <-p.inbox.done:
	}
	// closed while the result was held; the relay has the message
	select {
	case <-answered:
		return nil
	default:
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errRelayClosed
	}
	return errPeerClosed
}

// Messages is the channel of what the peer was handed.
func (p *Peer) Messages() <-chan Message {
	return p.inbox.out
}

// Close detaches the peer. What is kept for its client id stays kept, for a
// later peer of that client id.
func (p *Peer) Close() {
	p.relay.mu.Lock()
	defer p.relay.mu.Unlock()
	p.relay.closePeer(p)
}

// closePeer is Close with the relay's lock held.
func (r *Relay) closePeer(p *Peer) {
	if p.closed {
		return
	}
	p.closed = true
	r.removeEndpoint(p.ep)
	p.inbox.close()
}

// The socket client

const (
	// the time for the dial and the upgrade
	socketDialTimeout = 10 * time.Second
	// A publish can be held 6 or 12 seconds behind a recipient that does not
	// acknowledge, so a call is given more than that.
	socketCallTimeout = 15 * time.Second
	socketWriteWait   = 5 * time.Second
	socketReadLimit   = 1 << 20
)

// DialRelay is a minimal real-socket client for the opt-in live test: header
// auth, acknowledges every push, no reconnect.
//
// relayUrl is the relay's url, "wss://relay.walletconnect.com". The client
// key is the key of seed, as it is given: a caller that wants a fresh
// client id passes a random seed. ctx bounds the dial and the upgrade, not
// the life of the connection.
func DialRelay(ctx context.Context, relayUrl string, projectId string, seed wire.Key) (Conn, error) {
	dialer := &websocket.Dialer{
		TLSClientConfig:  &tls.Config{MinVersion: tls.VersionTLS12},
		HandshakeTimeout: socketDialTimeout,
	}
	return dialRelay(ctx, dialer, relayUrl, projectId, seed)
}

// dialRelay is DialRelay with the dialer given, which is how a test runs the
// socket client against a Relay.
func dialRelay(ctx context.Context, dialer *websocket.Dialer, relayUrl string, projectId string, seed wire.Key) (Conn, error) {
	nonce, err := wire.NewKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	// the audience is the url without a query, and the token goes in a
	// header: it is never part of a url
	audience, _, hasQuery := strings.Cut(relayUrl, "?")
	token := wire.RelayAuthToken(wire.ClientKey(seed), audience, time.Now().Unix(), nonce)
	separator := "?"
	if hasQuery {
		separator = "&"
	}
	target := relayUrl + separator + "projectId=" + url.QueryEscape(projectId)
	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)

	ws, response, err := dialer.DialContext(ctx, target, header)
	if err != nil {
		if errors.Is(err, websocket.ErrBadHandshake) && response != nil {
			body, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
			return nil, fmt.Errorf("relaytest: the relay refused the connection: %d %s", response.StatusCode, body)
		}
		return nil, fmt.Errorf("relaytest: dial: %w", err)
	}
	ws.SetReadLimit(socketReadLimit)
	c := &socketConn{
		ws:      ws,
		inbox:   newInbox(),
		pending: map[string]chan *wire.Frame{},
	}
	go c.inbox.run()
	go c.read()
	return c, nil
}

// socketConn is a Conn on a websocket.
type socketConn struct {
	ws    *websocket.Conn
	inbox *inbox

	// one frame is written at a time: calls come from any goroutine, the
	// acknowledgements from the reader
	writeMu sync.Mutex

	mu sync.Mutex
	// the calls that wait for their answer, by id
	pending map[string]chan *wire.Frame
	closed  bool
}

// read is the reader of the socket: it acknowledges every push at once, with
// the id as it came, and hands every answer to the call that waits for it.
func (c *socketConn) read() {
	defer c.end()
	for {
		messageType, text, err := c.ws.ReadMessage()
		if err != nil {
			return
		}
		if messageType != websocket.TextMessage {
			continue
		}
		frame, err := wire.ParseFrame(text)
		if err != nil {
			continue
		}
		if !frame.IsRequest() {
			c.mu.Lock()
			waiting := c.pending[string(frame.Id)]
			delete(c.pending, string(frame.Id))
			c.mu.Unlock()
			if waiting != nil {
				waiting <- frame
			}
			continue
		}
		if frame.Method != wire.MethodSubscription {
			continue
		}
		if c.write(wire.ResultFrame(frame.Id, true)) != nil {
			return
		}
		var params wire.SubscriptionParams
		if json.Unmarshal(frame.Params, &params) != nil {
			continue
		}
		c.inbox.put(Message{Topic: params.Data.Topic, Message: params.Data.Message, Tag: params.Data.Tag})
	}
}

func (c *socketConn) write(text []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.ws.SetWriteDeadline(time.Now().Add(socketWriteWait))
	return c.ws.WriteMessage(websocket.TextMessage, text)
}

// end closes the connection for good. Calls that wait fail by it.
func (c *socketConn) end() {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	c.inbox.close()
	c.ws.Close()
}

// call makes one call to the relay and waits for its answer.
func (c *socketConn) call(method string, params any) error {
	id := wire.NewRelayId(time.Now().UnixMilli(), rand.Reader)
	answer := make(chan *wire.Frame, 1)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errConnClosed
	}
	// two ids of one millisecond can be equal
	token := string(wire.IdToken(id))
	for c.pending[token] != nil {
		id++
		token = string(wire.IdToken(id))
	}
	c.pending[token] = answer
	c.mu.Unlock()
	forget := func() {
		c.mu.Lock()
		delete(c.pending, token)
		c.mu.Unlock()
	}

	if err := c.write(wire.RequestFrame(id, method, params)); err != nil {
		forget()
		return fmt.Errorf("relaytest: %s: %w", method, err)
	}
	timeout := time.NewTimer(socketCallTimeout)
	defer timeout.Stop()
	select {
	case frame := <-answer:
		if frame.Error != nil {
			return fmt.Errorf("relaytest: %s: the relay answered %d %s", method, frame.Error.Code, frame.Error.Message)
		}
		return nil
	case <-c.inbox.done:
		forget()
		return errConnClosed
	case <-timeout.C:
		forget()
		return fmt.Errorf("relaytest: %s: no answer in %v", method, socketCallTimeout)
	}
}

func (c *socketConn) Subscribe(topic string) error {
	return c.call(wire.MethodSubscribe, wire.SubscribeParams{Topic: topic})
}

func (c *socketConn) Publish(topic string, message string, tag int, ttl int) error {
	return c.call(wire.MethodPublish, wire.PublishParams{Topic: topic, Message: message, Ttl: ttl, Tag: tag})
}

func (c *socketConn) Messages() <-chan Message {
	return c.inbox.out
}

// Close sends a close frame with 1000 and closes the socket.
func (c *socketConn) Close() {
	c.mu.Lock()
	closed := c.closed
	c.closed = true
	c.mu.Unlock()
	if closed {
		return
	}
	c.ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
	c.inbox.close()
	c.ws.Close()
}
