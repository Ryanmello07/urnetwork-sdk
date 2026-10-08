//go:build !js && !ios_extension

// Package relaytest is a WalletConnect relay for tests. It runs in the
// process, is reached over in-memory connections, and behaves the way the
// hosted relay was measured to behave where the specification leaves the
// behaviour open. A client that was only tested against a relay that hands
// every message to every subscriber at once has not been tested, so what
// follows is how this relay always behaves, not a set of faults to switch
// on:
//
//   - A message belongs to one client id. When it is published it is assigned
//     to every other client id the relay knows as a subscriber of the topic,
//     also one that unsubscribed or has no socket at that moment. With none,
//     it waits for the first other client id that subscribes. It is never
//     handed to its publisher, and never to a client id it was not assigned
//     to.
//   - A message is pushed to a connection that is subscribed to its topic. It
//     leaves the mailbox only by the acknowledgement of a push: the result
//     true with the id of the push, digit for digit, on the socket the push
//     went to, within 6 seconds (SetAckHold). One that was not acknowledged
//     is pushed again whenever the same client id sends irn_subscribe for the
//     topic, on the same socket or on a new one, and at no other time.
//     Nothing is pushed on a new socket before it subscribes.
//   - The publisher's result is held while the push of its message waits for
//     its acknowledgement. When none comes the relay tries another connection
//     of the same client id, the oldest first, and then answers. A recipient
//     with no subscribed connection holds nothing up, and one whose
//     connection ends is waited for no longer.
//   - A message string that is published again is merged into the copy that
//     is still in a mailbox: nothing is stored and nothing is pushed. Once
//     that copy was acknowledged the same string is a new message.
//   - A message is gone when its ttl has passed, and a ttl under 30 seconds
//     or over 30 days is refused.
//   - The subscription id of a client id and a topic is always the same.
//   - irn_subscribe is answered a moment after it arrives. Subscribes written
//     back to back are answered together, and then stored messages come on
//     either side of the result of their topic: those of the first topic
//     before any result, the results last call first, then the stored
//     messages of the other topics. One subscribe by itself gets its result
//     first.
//   - Every socket is pinged every 30 seconds and closed with 4010 when the
//     ping before was not answered.
//   - The upgrade is refused with the statuses and the bodies of the hosted
//     relay for a missing or unknown project id, a missing or unacceptable
//     token, and an origin, bundle id or package name that is not allowed. A
//     client that presents none of the three is accepted.
//
// On top of that a test can make the relay misbehave (the fault controls,
// from SetOffline to SendOversized) and read what it saw (Handshakes, Dials,
// ClientIds, OpenSockets, Published, Frames).
//
// A client reaches the relay through DialTLS, which is the value for the
// client's dial hook, or as a Peer, which is in the process and speaks no
// websocket. DialRelay is a small socket client for the hosted relay, so that
// what is written against a Peer can run against the real thing.
//
// Everything works on the clock of a testing/synctest bubble: a relay that is
// made, used and closed inside one bubble leaves no goroutine and no timer
// behind, and its waits take no real time. It works on the real clock too.
// Two clocks are in use. RelayOptions.Now dates the messages and what is
// recorded, and is the time a token is judged by. The relay's own waits (the
// 6 seconds, the pings, the answer to a subscribe) run on the clock of the
// time package, which in a bubble is the bubble's.
//
// The frames of a socket are taken by a goroutine of that socket. So the call
// of a Peer, a fault control or a look at what the relay saw is not ordered
// against a frame a socket client has just written: a test in a bubble calls
// synctest.Wait in between. What the relay records of a dial is there when
// the dial returns.
//
// The package is for tests and is not part of what an app links.
package relaytest

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"

	"github.com/urnetwork/sdk/walletconnect/wire"
)

const (
	// The hosted relay waited 6.0 to 6.1 seconds for the acknowledgement of
	// a push before it answered the publisher, and 12 seconds once.
	defaultAckHold = 6 * time.Second

	// The hosted relay pinged every connection every 30 seconds. A
	// connection that had stopped answering was closed with 4010 between 46
	// and 66 seconds later.
	pingInterval = 30 * time.Second

	// The hosted relay answered a subscribe in 20 to 300 milliseconds. The
	// number does not matter here, only that the answer takes time: every
	// subscribe a client writes back to back is there before the first one
	// is answered.
	subscribeLatency = 20 * time.Millisecond

	// A client that does not read what it is sent is let go.
	writeTimeout = 5 * time.Second

	// The hosted relay refused a token whose iat was more than 120 seconds
	// ahead of its clock.
	tokenLeewaySeconds = 120
	// A relay token is about 430 characters. One of thousands is not looked
	// at.
	maxTokenLength = 4096

	// The hosted relay took a ttl of 30 seconds to 30 days.
	minTtlSeconds = 30
	maxTtlSeconds = 2592000

	closeLoadBalancing       = 4010
	closeLoadBalancingReason = "Disconnecting for load balancing reasons"

	// The push ids of the hosted relay were 15 digit numbers.
	firstPushId = int64(458_600_000_000_000)

	// JSON-RPC's own codes, for a call the relay cannot read
	rpcMethodNotFound = -32601
	rpcInvalidParams  = -32602
	// the code of the hosted relay's refusal of a ttl
	rpcRefused = -32000
)

// the payload of a ping: nine bytes, as the hosted relay's
var pingPayload = []byte("relaytest")

var errRelayClosed = errors.New("relaytest: the relay is closed")

// RelayOptions says whom the relay lets in and how it numbers its pushes. The
// zero value lets in a client of the project "test-project" that presents
// nothing else, and numbers as the hosted relay did. FirstPushId is for a
// test of ids that no float64 holds, such as one of 19 digits.
type RelayOptions struct {
	ProjectIds   []string         // accepted project ids; default {"test-project"}
	Origins      []string         // allowed Origin header values; default none
	BundleIds    []string         // allowed bundleId query values; default none
	PackageNames []string         // allowed packageName query values; default none
	Audiences    []string         // accepted aud; default the two urls of the hosted relay
	Now          func() time.Time // default time.Now (bubble time inside synctest)
	FirstPushId  int64            // id of the first push, each later one the next number; default 15 digits
}

// Relay is the relay. Every method is safe to call from any goroutine.
type Relay struct {
	options RelayOptions

	mu sync.Mutex
	// the goroutines of the relay: one for each connection it serves, one
	// writer for each socket, one pump for each peer
	wg     sync.WaitGroup
	closed bool
	timers map[*time.Timer]struct{}

	// what was seen
	dials       int
	handshakes  []Handshake
	clientIds   []string
	socketCount map[string]int // sockets opened so far, by client id
	published   []Published
	frames      []clientFrame

	// connections
	pending   map[net.Conn]struct{}      // accepted, the upgrade not answered yet
	hung      map[chan struct{}]struct{} // dials that are kept waiting
	endpoints []*endpoint                // open in the relay's eyes, the oldest first
	writing   map[*socket]struct{}       // sockets whose writer runs

	// mailboxes
	topics     map[string]*topic
	pushes     map[string]*push // waiting for an acknowledgement, by push id
	nextPushId int64

	// faults
	offline               bool
	hangDials             int
	refusals              int
	refusalStatus         int
	refusalBody           string
	closeAfterUpgrade     int
	closeAfterUpgradeCode int
	loseAck               map[string]bool
	ackHold               time.Duration
	duplicate             map[string]bool
	failures              map[string]*failure
}

// endpoint is one connection of a client id: a socket or a peer.
type endpoint struct {
	clientId string
	socket   *socket
	peer     *Peer
	// nothing gets through to it or from it, and the relay does not know
	zombie bool
	// the topics it subscribed to on this connection
	topics map[string]bool
}

// socket is a websocket on one of the relay's in-memory connections. Its
// reader is the goroutine that served the upgrade, its writer another one,
// and everything but the two connections is guarded by the relay's lock.
type socket struct {
	ep      *endpoint
	ordinal int
	netConn net.Conn
	ws      *websocket.Conn

	// no longer a connection of its client in the relay's eyes
	detached bool
	// the connection ended underneath a zombie, which the relay cannot know
	dead bool

	// what is to be written, in order
	out     []outItem
	wake    chan struct{}
	done    chan struct{}
	stopped bool

	// subscribes that are not answered yet
	batch      []*wire.Frame
	batchTimer *time.Timer

	pingTimer       *time.Timer
	pingOutstanding bool
}

type outItem struct {
	kind   int
	data   []byte
	code   int
	reason string
}

const (
	itemText = iota
	itemPing
	itemPong
	itemClose
)

// topic is what the relay keeps of one topic.
type topic struct {
	// the client ids that subscribed, in order. A client id stays here when
	// it unsubscribes or leaves: messages are still kept for it.
	known []string
	// the mailbox of each of them, in the order of publishing
	boxes map[string][]*entry
	// published while no other client id was known: for the first one that
	// subscribes
	unassigned []*entry
}

// entry is a message in a mailbox.
type entry struct {
	topic       string
	message     string
	tag         int
	publisher   string
	recipient   string
	unassigned  bool // it waits for the first other client id, and has no recipient yet
	publishedAt time.Time
	expiresAt   time.Time
	consumed    bool
	// the pushes of it that wait for an acknowledgement
	pushes map[*push]struct{}
	// the delivery its publish started, while the publisher is not answered
	round *round
}

// round is the delivery of a new message to one recipient.
type round struct {
	tried map[*endpoint]bool
	// tells the publish that this recipient is done with
	done func()
}

// push is one irn_subscription that waits for its acknowledgement.
type push struct {
	token string // the id as it is written
	entry *entry
	to    *endpoint
	timer *time.Timer
	// its end moves the delivery of a new message on
	inRound bool
}

type failure struct {
	n       int
	code    int
	message string
}

type clientFrame struct {
	clientId string
	frame    RecordedFrame
}

// NewRelay makes a relay. It starts nothing: the relay's goroutines and
// timers belong to its connections.
func NewRelay(options RelayOptions) *Relay {
	if len(options.ProjectIds) == 0 {
		options.ProjectIds = []string{"test-project"}
	}
	if len(options.Audiences) == 0 {
		options.Audiences = []string{"wss://relay.walletconnect.com", "wss://relay.walletconnect.org"}
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.FirstPushId == 0 {
		options.FirstPushId = firstPushId
	}
	// the caller keeps its slices
	options.ProjectIds = slices.Clone(options.ProjectIds)
	options.Origins = slices.Clone(options.Origins)
	options.BundleIds = slices.Clone(options.BundleIds)
	options.PackageNames = slices.Clone(options.PackageNames)
	options.Audiences = slices.Clone(options.Audiences)
	return &Relay{
		options:     options,
		timers:      map[*time.Timer]struct{}{},
		socketCount: map[string]int{},
		pending:     map[net.Conn]struct{}{},
		hung:        map[chan struct{}]struct{}{},
		writing:     map[*socket]struct{}{},
		topics:      map[string]*topic{},
		pushes:      map[string]*push{},
		nextPushId:  options.FirstPushId,
		loseAck:     map[string]bool{},
		ackHold:     defaultAckHold,
		duplicate:   map[string]bool{},
		failures:    map[string]*failure{},
	}
}

// Close ends the relay: every connection is closed with no close frame,
// every peer is closed, a dial that hangs fails, and what is asked of the
// relay afterwards fails or does nothing. It returns when the relay's
// goroutines have ended. It can be called more than once.
func (r *Relay) Close() {
	r.mu.Lock()
	if !r.closed {
		r.closed = true
		for conn := range r.pending {
			conn.Close()
		}
		for released := range r.hung {
			close(released)
		}
		clear(r.hung)
		for _, ep := range slices.Clone(r.endpoints) {
			if ep.socket != nil {
				r.dropSocket(ep.socket)
			} else {
				r.closePeer(ep.peer)
			}
		}
		// a socket that was being closed with a close frame
		for s := range r.writing {
			s.netConn.Close()
			s.stop()
		}
	}
	r.mu.Unlock()
	r.wg.Wait()
}

// DialTLS is the value for walletconnect.Config.DialTLS: one end of a
// net.Pipe whose other end this relay serves. The network and the address
// are not looked at; the host the client meant is in the request it sends.
func (r *Relay) DialTLS(ctx context.Context, network string, address string) (net.Conn, error) {
	r.mu.Lock()
	r.dials++
	switch {
	case r.closed:
		r.mu.Unlock()
		return nil, errRelayClosed
	case ctx.Err() != nil:
		r.mu.Unlock()
		return nil, ctx.Err()
	case r.offline:
		r.mu.Unlock()
		return nil, &net.OpError{Op: "dial", Net: network, Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	case r.hangDials > 0:
		r.hangDials--
		released := make(chan struct{})
		r.hung[released] = struct{}{}
		r.mu.Unlock()
		select {
		case <-ctx.Done():
			r.mu.Lock()
			delete(r.hung, released)
			r.mu.Unlock()
			return nil, ctx.Err()
		case <-released:
			return nil, errRelayClosed
		}
	}
	client, server := net.Pipe()
	r.pending[server] = struct{}{}
	r.wg.Add(1)
	r.mu.Unlock()
	go r.serve(server)
	return client, nil
}

// serve answers the upgrade request of one connection and, when it is
// accepted, reads the socket until it ends.
func (r *Relay) serve(conn net.Conn) {
	defer r.wg.Done()
	s := r.upgrade(conn)
	if s == nil {
		return
	}
	for {
		messageType, text, err := s.ws.ReadMessage()
		if err != nil {
			break
		}
		if messageType == websocket.TextMessage {
			r.handleText(s, text)
		}
	}
	r.ended(s)
}

// The upgrade

// verdict is the relay's answer to an upgrade request.
type verdict struct {
	status      int
	body        string
	contentType string
	// the token's iss, "" when no token verified
	clientId string
}

// authorize decides an upgrade request. The statuses and the texts are the
// hosted relay's. The order of the checks is this relay's own, except that
// the hosted relay too turns a request that is no upgrade away before it
// asks for a project id. A token that cannot be read at all is answered like
// one whose signature does not verify.
func (r *Relay) authorize(request *http.Request) verdict {
	query := request.URL.Query()
	token := bearerToken(request, query)
	var claims *wire.RelayClaims
	if token != "" && len(token) <= maxTokenLength {
		if verified, err := wire.VerifyToken(token); err == nil {
			claims = verified
		}
	}
	v := verdict{contentType: "application/json"}
	if claims != nil {
		v.clientId = claims.Iss
	}
	refuse := func(status int, message string) verdict {
		v.status = status
		v.body = string(wire.MarshalCompact(struct {
			Error string `json:"error"`
		}{message}))
		return v
	}
	now := r.options.Now().Unix()
	projectId := query.Get("projectId")
	switch {
	case !websocket.IsWebSocketUpgrade(request):
		v.status = http.StatusBadRequest
		v.body = "Connection header did not include 'upgrade'"
		v.contentType = "text/plain"
		return v
	case projectId == "":
		return refuse(http.StatusBadRequest, "Project ID is missing")
	case !slices.Contains(r.options.ProjectIds, projectId):
		return refuse(http.StatusForbidden, "Project not found")
	case token == "":
		return refuse(http.StatusUnauthorized, "JWT is missing")
	case claims == nil:
		return refuse(http.StatusUnauthorized, "JWT validation error: Invalid signature")
	case !slices.Contains(r.options.Audiences, claims.Aud):
		return refuse(http.StatusUnauthorized, "JWT validation error: Invalid audience")
	case claims.Iat > now+tokenLeewaySeconds:
		return refuse(http.StatusUnauthorized, "JWT validation error: JWT Token is not yet valid: basic.iat: "+
			strconv.FormatInt(claims.Iat, 10)+", now + time_leeway: "+strconv.FormatInt(now+tokenLeewaySeconds, 10)+
			", time_leeway: "+strconv.Itoa(tokenLeewaySeconds))
	case claims.Exp <= now:
		return refuse(http.StatusUnauthorized, "JWT validation error: JWT Token is expired: Some("+strconv.FormatInt(claims.Exp, 10)+")")
	case !r.allowed(request, query):
		return refuse(http.StatusForbidden, "Unauthorized: origin not allowed")
	}
	v.status = http.StatusSwitchingProtocols
	return v
}

// bearerToken is the token of a request: the Authorization header, or the
// auth parameter a browser uses because it cannot set a header.
func bearerToken(request *http.Request, query url.Values) string {
	if token, found := strings.CutPrefix(request.Header.Get("Authorization"), "Bearer "); found && token != "" {
		return token
	}
	return query.Get("auth")
}

// allowed applies the three lists. The first thing a client presents decides
// alone: an Origin header before a bundleId, a bundleId before a packageName.
// Each list is its own: a bundle id is no package name and no origin. A
// client that presents nothing is let in, as the hosted relay lets it in.
func (r *Relay) allowed(request *http.Request, query url.Values) bool {
	if origins, sent := request.Header["Origin"]; sent {
		return len(origins) > 0 && slices.Contains(r.options.Origins, origins[0])
	}
	if query.Has("bundleId") {
		// the hosted relay took a bundle id in capitals
		bundleId := query.Get("bundleId")
		return slices.ContainsFunc(r.options.BundleIds, func(allowed string) bool {
			return strings.EqualFold(allowed, bundleId)
		})
	}
	if query.Has("packageName") {
		return slices.Contains(r.options.PackageNames, query.Get("packageName"))
	}
	return true
}

// upgrade reads the request of a new connection and answers it. The
// handshake is recorded, and an accepted socket is one of its client's,
// before the answer is written: when the client's dial returns, what the
// relay reports is the state after it.
func (r *Relay) upgrade(conn net.Conn) *socket {
	reader := bufio.NewReader(conn)
	request, err := http.ReadRequest(reader)
	if err != nil {
		r.forget(conn)
		return nil
	}
	v := r.authorize(request)

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		conn.Close()
		return nil
	}
	if r.refusals > 0 {
		r.refusals--
		v.status, v.body, v.contentType = r.refusalStatus, r.refusalBody, "application/json"
	}
	if v.clientId != "" && !slices.Contains(r.clientIds, v.clientId) {
		r.clientIds = append(r.clientIds, v.clientId)
	}
	record := len(r.handshakes)
	r.handshakes = append(r.handshakes, Handshake{
		Host:     request.Host,
		Query:    request.URL.Query(),
		Header:   request.Header.Clone(),
		Status:   v.status,
		Body:     v.body,
		ClientId: v.clientId,
	})
	if v.status != http.StatusSwitchingProtocols {
		r.mu.Unlock()
		writeResponse(conn, v.status, v.contentType, v.body)
		r.forget(conn)
		return nil
	}
	r.socketCount[v.clientId]++
	s := &socket{
		ordinal: r.socketCount[v.clientId],
		netConn: conn,
		wake:    make(chan struct{}, 1),
		done:    make(chan struct{}),
	}
	s.ep = &endpoint{clientId: v.clientId, socket: s, topics: map[string]bool{}}
	r.endpoints = append(r.endpoints, s.ep)
	closeAtOnce := r.closeAfterUpgrade > 0
	closeCode := r.closeAfterUpgradeCode
	if closeAtOnce {
		r.closeAfterUpgrade--
	}
	r.mu.Unlock()

	writer := &upgradeWriter{conn: conn, reader: reader, header: http.Header{}}
	upgrader := websocket.Upgrader{
		// the origin was looked at above
		CheckOrigin: func(*http.Request) bool { return true },
	}
	ws, err := upgrader.Upgrade(writer, request, nil)

	r.mu.Lock()
	defer r.mu.Unlock()
	// The connection stayed in pending while the answer was written, so that
	// Close could end the wait for a client that does not read it. Nothing
	// else would: a socket that was closed with a close frame meanwhile is
	// no socket of its client any more, and has no writer yet.
	delete(r.pending, conn)
	if err != nil {
		// an upgrade request that is no websocket handshake after all: the
		// upgrader's refusal is the answer, and there was no socket
		if writer.status != 0 {
			r.handshakes[record].Status = writer.status
			r.handshakes[record].Body = string(writer.body)
		}
		if r.socketCount[v.clientId] == s.ordinal {
			r.socketCount[v.clientId]--
		}
		r.detach(s)
		if writer.status != 0 && !writer.hijacked && !r.closed {
			// not under the lock: the client reads when it likes, and
			// Close ends the wait for it
			r.pending[conn] = struct{}{}
			r.mu.Unlock()
			writeResponse(conn, writer.status, writer.header.Get("Content-Type"), string(writer.body))
			r.mu.Lock()
			delete(r.pending, conn)
		}
		conn.Close()
		return nil
	}
	if s.stopped || r.closed {
		// dropped, or the relay closed, while the answer was written
		conn.Close()
		return nil
	}
	s.ws = ws
	ws.SetPingHandler(func(data string) error {
		r.mu.Lock()
		defer r.mu.Unlock()
		if !s.detached && !s.ep.zombie {
			s.queue(outItem{kind: itemPong, data: []byte(data)})
		}
		return nil
	})
	ws.SetPongHandler(func(string) error {
		r.mu.Lock()
		defer r.mu.Unlock()
		if !s.ep.zombie {
			s.pingOutstanding = false
		}
		return nil
	})
	ws.SetCloseHandler(func(code int, text string) error {
		r.mu.Lock()
		defer r.mu.Unlock()
		if s.detached {
			return nil
		}
		r.record(s, true, closeText(code, text))
		if !s.ep.zombie {
			// the close frame is answered with one of the same code
			r.closeSocket(s, code, "")
		}
		return nil
	})
	// A test can have closed the socket with a close frame already: its dial
	// returned when the answer was read. Then the writer has that frame to
	// write and nothing else is left to do.
	if !s.detached {
		s.pingTimer = r.after(pingInterval, func() { r.pingTick(s) })
		if closeAtOnce {
			reason := ""
			if closeCode == closeLoadBalancing {
				reason = closeLoadBalancingReason
			}
			r.closeSocket(s, closeCode, reason)
		}
	}
	r.writing[s] = struct{}{}
	r.wg.Add(1)
	go r.write(s)
	return s
}

// forget closes a connection that did not become a socket.
func (r *Relay) forget(conn net.Conn) {
	r.mu.Lock()
	delete(r.pending, conn)
	r.mu.Unlock()
	conn.Close()
}

// writeResponse answers an upgrade request with a status and a body in place
// of the upgrade.
func writeResponse(conn net.Conn, status int, contentType string, body string) {
	response := &http.Response{
		StatusCode:    status,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {contentType}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Close:         true,
	}
	buffered := bufio.NewWriter(conn)
	response.Write(buffered)
	buffered.Flush()
}

// upgradeWriter is the response writer the websocket upgrader wants: one
// that gives up its connection. There is no http.Server behind it: the
// connection is one end of a pipe, and the request was read from it by hand.
type upgradeWriter struct {
	conn     net.Conn
	reader   *bufio.Reader
	header   http.Header
	hijacked bool
	// what the upgrader answers when it refuses
	status int
	body   []byte
}

func (w *upgradeWriter) Header() http.Header {
	return w.header
}

func (w *upgradeWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}

func (w *upgradeWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	w.body = append(w.body, b...)
	return len(b), nil
}

func (w *upgradeWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.hijacked = true
	return w.conn, bufio.NewReadWriter(w.reader, bufio.NewWriter(w.conn)), nil
}

// Sockets

// queue adds to what the socket's writer writes. The relay's lock is held.
func (s *socket) queue(item outItem) {
	s.out = append(s.out, item)
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// stop ends the socket's writer without letting it write what is queued. The
// relay's lock is held.
func (s *socket) stop() {
	if !s.stopped {
		s.stopped = true
		close(s.done)
	}
}

// write is the socket's writer. Nothing else writes to the socket, so that
// no lock is held while a client takes its time to read.
func (r *Relay) write(s *socket) {
	defer r.wg.Done()
	defer func() {
		s.netConn.Close()
		r.mu.Lock()
		delete(r.writing, s)
		r.mu.Unlock()
	}()
	for {
		r.mu.Lock()
		var item outItem
		have := len(s.out) > 0
		if have {
			item = s.out[0]
			s.out = s.out[1:]
		}
		r.mu.Unlock()
		if !have {
			select {
			case <-s.wake:
				continue
			case <-s.done:
				return
			}
		}
		deadline := time.Now().Add(writeTimeout)
		var err error
		switch item.kind {
		case itemText:
			s.ws.SetWriteDeadline(deadline)
			err = s.ws.WriteMessage(websocket.TextMessage, item.data)
		case itemPing:
			err = s.ws.WriteControl(websocket.PingMessage, item.data, deadline)
		case itemPong:
			err = s.ws.WriteControl(websocket.PongMessage, item.data, deadline)
		case itemClose:
			s.ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(item.code, item.reason), deadline)
			return
		}
		// the deadline's timer is not left to run
		s.netConn.SetWriteDeadline(time.Time{})
		if err != nil {
			return
		}
	}
}

// send writes a text frame to a socket and records it. A zombie is sent
// nothing.
//
// The relay's lock is held here, and in every unexported method from here
// on that does not take it itself (ended and handleText do: they are called
// by a socket's reader).
func (r *Relay) send(s *socket, text []byte) {
	if s.detached || s.ep.zombie {
		return
	}
	r.record(s, false, string(text))
	s.queue(outItem{kind: itemText, data: text})
}

func (r *Relay) record(s *socket, toRelay bool, text string) {
	r.frames = append(r.frames, clientFrame{
		clientId: s.ep.clientId,
		frame:    RecordedFrame{Socket: s.ordinal, ToRelay: toRelay, Text: text, At: r.options.Now()},
	})
}

// closeText is how a close frame is recorded: it has no text of its own.
func closeText(code int, reason string) string {
	text := "close " + strconv.Itoa(code)
	if reason != "" {
		text += " " + reason
	}
	return text
}

// detach takes a socket out of the relay's view: it is no connection of its
// client any more, its timers are stopped, and the pushes that wait for it
// are over.
func (r *Relay) detach(s *socket) {
	if s.detached {
		return
	}
	s.detached = true
	r.stop(s.batchTimer)
	r.stop(s.pingTimer)
	s.batchTimer, s.pingTimer, s.batch = nil, nil, nil
	r.removeEndpoint(s.ep)
}

// removeEndpoint ends a connection in the relay's eyes. A push that waited
// for its acknowledgement waits no longer: the delivery moves on, and the
// message stays in the mailbox.
func (r *Relay) removeEndpoint(ep *endpoint) {
	r.endpoints = slices.DeleteFunc(r.endpoints, func(other *endpoint) bool { return other == ep })
	var waiting []*push
	for _, p := range r.pushes {
		if p.to == ep {
			waiting = append(waiting, p)
		}
	}
	// in the order they were made
	slices.SortFunc(waiting, func(a *push, b *push) int {
		return strings.Compare(a.token, b.token)
	})
	for _, p := range waiting {
		r.stop(p.timer)
		r.expire(p)
	}
}

// closeSocket closes a socket with a close frame, behind what is queued for
// it. A zombie gets no frame.
func (r *Relay) closeSocket(s *socket, code int, reason string) {
	if s.detached {
		return
	}
	if s.ep.zombie || s.dead {
		r.dropSocket(s)
		return
	}
	r.record(s, false, closeText(code, reason))
	r.detach(s)
	s.queue(outItem{kind: itemClose, code: code, reason: reason})
}

// dropSocket closes a socket's connection with no close frame.
func (r *Relay) dropSocket(s *socket) {
	if s.detached {
		return
	}
	r.detach(s)
	s.netConn.Close()
	s.stop()
}

// ended is called when the reader of a socket stops: the client closed its
// end, or the relay did.
func (r *Relay) ended(s *socket) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.detached {
		// the relay closed it; the writer finishes by itself
		return
	}
	if s.ep.zombie {
		// the relay hears nothing of a zombie, its end included
		s.dead = true
		return
	}
	r.dropSocket(s)
}

// pingTick pings a socket, or closes it when the ping before was not
// answered.
func (r *Relay) pingTick(s *socket) {
	s.pingTimer = nil
	if s.detached {
		return
	}
	if s.pingOutstanding {
		r.closeSocket(s, closeLoadBalancing, closeLoadBalancingReason)
		return
	}
	s.pingOutstanding = true
	if !s.ep.zombie {
		s.queue(outItem{kind: itemPing, data: pingPayload})
	}
	s.pingTimer = r.after(pingInterval, func() { r.pingTick(s) })
}

// after runs f under the relay's lock when d has passed, unless the timer
// was stopped meanwhile: a timer belongs to a socket or to a push, and is
// stopped with it. The relay's lock is held by the caller, which is what
// makes the timer known before it can fire.
func (r *Relay) after(d time.Duration, f func()) *time.Timer {
	var timer *time.Timer
	timer = time.AfterFunc(d, func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if _, live := r.timers[timer]; !live {
			return
		}
		delete(r.timers, timer)
		f()
	})
	r.timers[timer] = struct{}{}
	return timer
}

func (r *Relay) stop(timer *time.Timer) {
	if timer != nil {
		timer.Stop()
		delete(r.timers, timer)
	}
}

// Calls

// handleText takes one text frame of a socket: a call, or the answer to a
// push.
func (r *Relay) handleText(s *socket, text []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.detached {
		return
	}
	r.record(s, true, string(text))
	if s.ep.zombie {
		return
	}
	frame, err := wire.ParseFrame(text)
	if err != nil {
		return
	}
	if !frame.IsRequest() {
		// an acknowledgement is the result true, with the id of the push as
		// it was written
		if frame.Error == nil && string(frame.Result) == "true" {
			r.acknowledge(s.ep, string(frame.Id))
		}
		return
	}
	if frame.Method == wire.MethodSubscribe {
		s.batch = append(s.batch, frame)
		if s.batchTimer == nil {
			s.batchTimer = r.after(subscribeLatency, func() {
				s.batchTimer = nil
				r.answerSubscribes(s)
			})
		}
		return
	}
	// another call ends the wait for more subscribes: the calls of a socket
	// take effect in the order they were written
	r.answerSubscribes(s)
	switch frame.Method {
	case wire.MethodPublish:
		r.callPublish(s, frame)
	case wire.MethodUnsubscribe:
		r.callUnsubscribe(s, frame)
	default:
		r.send(s, wire.ErrorFrame(frame.Id, rpcMethodNotFound, "Method not found"))
	}
}

// answerSubscribes answers the subscribes of a socket that wait. One gets its
// result and then what its mailbox holds. Of several, the stored messages of
// the first topic are written before any result, the results last call
// first, and then the stored messages of the other topics: with two
// subscribes written back to back the hosted relay was seen to push before
// the result of the topic, and to answer the second subscribe first.
func (r *Relay) answerSubscribes(s *socket) {
	r.stop(s.batchTimer)
	s.batchTimer = nil
	calls := s.batch
	s.batch = nil
	if len(calls) == 0 {
		return
	}
	answers := make([][]byte, len(calls))
	stored := make([][]*entry, len(calls))
	for i, call := range calls {
		answers[i], stored[i] = r.callSubscribe(s, call)
	}
	if len(calls) == 1 {
		r.send(s, answers[0])
		r.pushAll(stored[0], s.ep)
		return
	}
	r.pushAll(stored[0], s.ep)
	for i := len(answers) - 1; i >= 0; i-- {
		r.send(s, answers[i])
	}
	for _, entries := range stored[1:] {
		r.pushAll(entries, s.ep)
	}
}

func (r *Relay) callSubscribe(s *socket, call *wire.Frame) ([]byte, []*entry) {
	var params wire.SubscribeParams
	if err := json.Unmarshal(call.Params, &params); err != nil || params.Topic == "" {
		return wire.ErrorFrame(call.Id, rpcInvalidParams, "Invalid params"), nil
	}
	if failure := r.takeFailure(wire.MethodSubscribe); failure != nil {
		return wire.ErrorFrame(call.Id, failure.code, failure.message), nil
	}
	stored := r.subscribe(s.ep, params.Topic)
	return wire.ResultFrame(call.Id, subscriptionId(s.ep.clientId, params.Topic)), stored
}

func (r *Relay) callUnsubscribe(s *socket, call *wire.Frame) {
	var params wire.UnsubscribeParams
	if err := json.Unmarshal(call.Params, &params); err != nil || params.Topic == "" {
		r.send(s, wire.ErrorFrame(call.Id, rpcInvalidParams, "Invalid params"))
		return
	}
	if failure := r.takeFailure(wire.MethodUnsubscribe); failure != nil {
		r.send(s, wire.ErrorFrame(call.Id, failure.code, failure.message))
		return
	}
	// this connection is pushed nothing more of the topic. The client id
	// stays known to the topic, and its mailbox stays.
	delete(s.ep.topics, params.Topic)
	r.send(s, wire.ResultFrame(call.Id, true))
}

func (r *Relay) callPublish(s *socket, call *wire.Frame) {
	var params wire.PublishParams
	if err := json.Unmarshal(call.Params, &params); err != nil || params.Topic == "" {
		r.send(s, wire.ErrorFrame(call.Id, rpcInvalidParams, "Invalid params"))
		return
	}
	if failure := r.takeFailure(wire.MethodPublish); failure != nil {
		r.send(s, wire.ErrorFrame(call.Id, failure.code, failure.message))
		return
	}
	if refusal := ttlRefusal(params.Ttl); refusal != "" {
		r.send(s, wire.ErrorFrame(call.Id, rpcRefused, refusal))
		return
	}
	answer := func() { r.send(s, wire.ResultFrame(call.Id, true)) }
	for _, clientId := range []string{s.ep.clientId, ""} {
		if r.loseAck[clientId] {
			delete(r.loseAck, clientId)
			answer = func() {}
			break
		}
	}
	r.publish(s.ep, params, answer)
}

// ttlRefusal is the hosted relay's refusal of a ttl, "" for one it takes.
func ttlRefusal(ttl int) string {
	switch {
	case ttl < minTtlSeconds:
		return "Message: TtlTooShort"
	case ttl > maxTtlSeconds:
		return "Message: TtlTooLong"
	}
	return ""
}

func (r *Relay) takeFailure(method string) *failure {
	f := r.failures[method]
	if f == nil {
		return nil
	}
	f.n--
	if f.n <= 0 {
		delete(r.failures, method)
	}
	return f
}

// subscriptionId is the same for a client id and a topic whenever it is
// asked for, and 64 hex characters like the hosted relay's.
func subscriptionId(clientId string, topic string) string {
	sum := sha256.Sum256([]byte(clientId + "\n" + topic))
	return hex.EncodeToString(sum[:])
}

// Mailboxes

func (r *Relay) topicOf(name string) *topic {
	t := r.topics[name]
	if t == nil {
		t = &topic{boxes: map[string][]*entry{}}
		r.topics[name] = t
	}
	return t
}

// box is the mailbox of a client id on a topic, without what has expired.
func (r *Relay) box(t *topic, recipient string, now time.Time) []*entry {
	kept, gone := unexpired(t.boxes[recipient], now)
	if len(gone) > 0 {
		t.boxes[recipient] = kept
		for _, e := range gone {
			r.consume(e)
		}
	}
	return kept
}

// unassigned is what waits on a topic for the first other client id,
// without what has expired.
func (r *Relay) unassigned(t *topic, now time.Time) []*entry {
	kept, gone := unexpired(t.unassigned, now)
	if len(gone) > 0 {
		t.unassigned = kept
		for _, e := range gone {
			r.consume(e)
		}
	}
	return kept
}

// unexpired splits entries into those that still live at now and those whose
// ttl has passed. With nothing expired the entries are returned as they are.
func unexpired(entries []*entry, now time.Time) (kept []*entry, gone []*entry) {
	expired := func(e *entry) bool { return !now.Before(e.expiresAt) }
	if !slices.ContainsFunc(entries, expired) {
		return entries, nil
	}
	for _, e := range entries {
		if expired(e) {
			gone = append(gone, e)
		} else {
			kept = append(kept, e)
		}
	}
	return kept, gone
}

// subscribe makes a connection a subscriber of a topic and returns what the
// mailbox of its client id holds, the oldest first, for the caller to push.
func (r *Relay) subscribe(ep *endpoint, name string) []*entry {
	now := r.options.Now()
	t := r.topicOf(name)
	if !slices.Contains(t.known, ep.clientId) {
		t.known = append(t.known, ep.clientId)
	}
	ep.topics[name] = true
	// what waited for the first other client id is this client's now. What
	// this client published itself goes on waiting.
	var waiting []*entry
	for _, e := range r.unassigned(t, now) {
		if e.publisher == ep.clientId {
			waiting = append(waiting, e)
			continue
		}
		e.recipient, e.unassigned = ep.clientId, false
		t.boxes[ep.clientId] = append(t.boxes[ep.clientId], e)
	}
	t.unassigned = waiting
	return slices.Clone(r.box(t, ep.clientId, now))
}

// publish takes a message from a connection. answer is called once, when the
// relay answers the publisher: at once, or when the pushes of the message
// are acknowledged or given up.
func (r *Relay) publish(from *endpoint, params wire.PublishParams, answer func()) {
	now := r.options.Now()
	r.published = append(r.published, Published{
		ClientId: from.clientId,
		Topic:    params.Topic,
		Message:  params.Message,
		Tag:      params.Tag,
		Ttl:      params.Ttl,
		At:       now,
	})
	t := r.topicOf(params.Topic)
	fresh := func() *entry {
		return &entry{
			topic:       params.Topic,
			message:     params.Message,
			tag:         params.Tag,
			publisher:   from.clientId,
			publishedAt: now,
			expiresAt:   now.Add(time.Duration(params.Ttl) * time.Second),
			pushes:      map[*push]struct{}{},
		}
	}
	same := func(e *entry) bool { return e.message == params.Message }

	var recipients []string
	for _, clientId := range t.known {
		if clientId != from.clientId {
			recipients = append(recipients, clientId)
		}
	}
	if len(recipients) == 0 {
		// nobody else is known: for the first other client id that
		// subscribes
		waiting := r.unassigned(t, now)
		if !slices.ContainsFunc(waiting, func(e *entry) bool { return same(e) && e.publisher == from.clientId }) {
			e := fresh()
			e.unassigned = true
			t.unassigned = append(waiting, e)
		}
		answer()
		return
	}
	// the publisher is answered when every recipient is done with
	open := 1
	done := func() {
		open--
		if open == 0 {
			answer()
		}
	}
	for _, recipient := range recipients {
		box := r.box(t, recipient, now)
		if slices.ContainsFunc(box, same) {
			// merged into the copy that is still there
			continue
		}
		e := fresh()
		e.recipient = recipient
		t.boxes[recipient] = append(box, e)
		open++
		e.round = &round{tried: map[*endpoint]bool{}, done: done}
		r.deliver(e)
	}
	done()
}

// deliver pushes a new message to the next connection of its recipient that
// is subscribed to the topic and was not tried, the oldest first. With none
// left the delivery is over: the publisher is answered, and the message
// waits in the mailbox for the recipient's next subscribe.
func (r *Relay) deliver(e *entry) {
	current := e.round
	for _, ep := range r.endpoints {
		if ep.clientId == e.recipient && ep.topics[e.topic] && !current.tried[ep] {
			current.tried[ep] = true
			r.push(e, ep, true)
			return
		}
	}
	e.round = nil
	current.done()
}

// pushAll pushes what a mailbox held when its client subscribed.
func (r *Relay) pushAll(entries []*entry, to *endpoint) {
	for _, e := range entries {
		r.push(e, to, false)
	}
}

// push hands a message to one connection. A peer takes it and acknowledges
// at once. A socket is written an irn_subscription and has the hold to
// acknowledge it. A zombie, socket or peer, gets nothing, and the relay
// waits for it all the same.
func (r *Relay) push(e *entry, to *endpoint, inRound bool) {
	if e.consumed {
		return
	}
	if to.peer != nil && !to.zombie {
		to.peer.inbox.put(Message{Topic: e.topic, Message: e.message, Tag: e.tag})
		r.consume(e)
		return
	}
	copies := 1
	if to.socket != nil && r.duplicate[e.topic] {
		delete(r.duplicate, e.topic)
		copies = 2
	}
	for i := range copies {
		id := r.nextPushId
		r.nextPushId++
		p := &push{
			token:   strconv.FormatInt(id, 10),
			entry:   e,
			to:      to,
			inRound: inRound && i == 0,
		}
		r.pushes[p.token] = p
		e.pushes[p] = struct{}{}
		p.timer = r.after(r.ackHold, func() { r.expire(p) })
		if to.socket != nil {
			r.send(to.socket, wire.RequestFrame(id, wire.MethodSubscription, wire.SubscriptionParams{
				Id: subscriptionId(to.clientId, e.topic),
				Data: wire.SubscriptionData{
					Topic:       e.topic,
					Message:     e.message,
					PublishedAt: e.publishedAt.Unix(),
					Tag:         e.tag,
				},
			}))
		}
	}
}

// expire ends the wait for the acknowledgement of one push. One that comes
// later does not count: the message stays in the mailbox.
func (r *Relay) expire(p *push) {
	delete(r.pushes, p.token)
	delete(p.entry.pushes, p)
	if p.inRound && p.entry.round != nil {
		r.deliver(p.entry)
	}
}

// acknowledge takes the answer to a push from the connection it went to.
func (r *Relay) acknowledge(from *endpoint, token string) {
	p := r.pushes[token]
	if p == nil || p.to != from {
		return
	}
	r.consume(p.entry)
}

// consume takes a message out of its mailbox: it was acknowledged, or its
// ttl has passed.
func (r *Relay) consume(e *entry) {
	if e.consumed {
		return
	}
	e.consumed = true
	for p := range e.pushes {
		r.stop(p.timer)
		delete(r.pushes, p.token)
	}
	e.pushes = nil
	t := r.topics[e.topic]
	same := func(other *entry) bool { return other == e }
	if e.unassigned {
		t.unassigned = slices.DeleteFunc(t.unassigned, same)
	} else {
		t.boxes[e.recipient] = slices.DeleteFunc(t.boxes[e.recipient], same)
	}
	if current := e.round; current != nil {
		e.round = nil
		current.done()
	}
}

// Observation

// Handshake is one upgrade request and the relay's answer to it.
type Handshake struct {
	Host     string
	Query    url.Values
	Header   http.Header
	Status   int    // 101 or the refusal
	Body     string // the refusal's body
	ClientId string // the token's iss ("" when the token did not verify)
}

// Handshakes are the upgrade requests the relay answered, in order. A dial
// that was refused or left hanging sent none.
func (r *Relay) Handshakes() []Handshake {
	r.mu.Lock()
	defer r.mu.Unlock()
	handshakes := slices.Clone(r.handshakes)
	for i := range handshakes {
		handshakes[i].Query = url.Values(http.Header(handshakes[i].Query).Clone())
		handshakes[i].Header = handshakes[i].Header.Clone()
	}
	return handshakes
}

// Dials is how often DialTLS was called, whatever became of the dial.
func (r *Relay) Dials() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dials
}

// ClientIds are the socket clients seen, in order of first handshake: the
// client id of every upgrade request with a token that verified, accepted or
// not.
func (r *Relay) ClientIds() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.clientIds)
}

// OpenSockets is the number of sockets of a client that are open in the
// relay's eyes, of every socket client for "". A zombie counts until the
// relay closes it, also when the client has let go of it.
func (r *Relay) OpenSockets(clientId string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	open := 0
	for _, ep := range r.endpoints {
		if ep.socket != nil && (clientId == "" || ep.clientId == clientId) {
			open++
		}
	}
	return open
}

// Published is one irn_publish the relay took, of a socket client or of a
// peer.
type Published struct {
	ClientId string
	Topic    string
	Message  string
	Tag      int
	Ttl      int
	At       time.Time
}

// Published are the publishes the relay took, in order: also one whose
// result was lost, and one that was merged. A publish that was answered with
// an error is not among them.
func (r *Relay) Published() []Published {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.published)
}

// RecordedFrame is one frame of a socket.
//
// A close frame is recorded with the text "close", its code and, when it has
// one, its reason: "close 1000", "close 4010 Disconnecting for load
// balancing reasons". A connection that ended with no close frame leaves
// nothing. Pings and pongs are not recorded.
type RecordedFrame struct {
	Socket  int // ordinal of the socket of this client
	ToRelay bool
	Text    string
	At      time.Time
}

// Frames are the frames of a client's sockets, of every socket client for
// "", in the order the relay took and gave them. Socket is 1 for the first
// socket the client opened, 2 for the second.
//
// A frame of the client is recorded when it is read, also one that a zombie
// swallows: it is what the client wrote. A frame of the relay is recorded
// when it is handed to the socket, which is before the client has read it;
// what a zombie is not sent is not recorded.
func (r *Relay) Frames(clientId string) []RecordedFrame {
	r.mu.Lock()
	defer r.mu.Unlock()
	var frames []RecordedFrame
	for _, recorded := range r.frames {
		if clientId == "" || recorded.clientId == clientId {
			frames = append(frames, recorded.frame)
		}
	}
	return frames
}

// Faults. A clientId "" means every socket client. Only SetZombie also takes
// the client id of a peer.

// sockets are the open sockets a fault is meant for.
func (r *Relay) sockets(clientId string) []*socket {
	var sockets []*socket
	for _, ep := range r.endpoints {
		if ep.socket != nil && (clientId == "" || ep.clientId == clientId) {
			sockets = append(sockets, ep.socket)
		}
	}
	return sockets
}

// SetOffline makes dials fail at once (connection refused). The sockets that
// are open stay open.
func (r *Relay) SetOffline(offline bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.offline = offline
}

// HangDials makes the next n dials never complete until their context ends.
func (r *Relay) HangDials(n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hangDials = n
}

// RefuseHandshakes makes the next n upgrades get this status and body,
// whatever the request.
func (r *Relay) RefuseHandshakes(n int, status int, body string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refusals, r.refusalStatus, r.refusalBody = n, status, body
}

// CloseAfterUpgrade makes the next n sockets be closed with this code right
// after the upgrade. With 4010 the close frame has the hosted relay's reason.
func (r *Relay) CloseAfterUpgrade(n int, code int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closeAfterUpgrade, r.closeAfterUpgradeCode = n, code
}

// Drop closes the connections with no close frame.
func (r *Relay) Drop(clientId string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.sockets(clientId) {
		r.dropSocket(s)
	}
}

// CloseSockets closes the sockets with a close frame, behind what the relay
// had to write to them. They are no sockets of their client from this call
// on.
func (r *Relay) CloseSockets(clientId string, code int, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.sockets(clientId) {
		r.closeSocket(s, code, reason)
	}
}

// SetZombie makes the connections a client has now swallow frames in both
// directions and keeps them: what the client writes has no effect and no
// answer, what the relay writes does not arrive, and the relay goes on
// believing in the connection, also when the client lets go of it. A
// connection the client opens afterwards is healthy.
//
// With false the connections work again. What was swallowed is lost, and a
// connection the client had let go of is closed.
//
// The relay's pings go on counting. A zombie is sent none and its pongs are
// not heard, so the relay itself drops it, with no close frame, at the second
// ping tick after it was made one: 30 to 60 seconds later. And a socket that
// works again after a tick passed while it was a zombie is closed with 4010
// at its next tick: the ping it did not answer was never sent to it.
//
// The client id of a peer makes that peer silent: it is handed nothing, and
// its calls fail. "" is every socket client and no peer.
func (r *Relay) SetZombie(clientId string, zombie bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, ep := range slices.Clone(r.endpoints) {
		meant := ep.clientId == clientId
		if clientId == "" {
			meant = ep.socket != nil
		}
		if !meant {
			continue
		}
		ep.zombie = zombie
		if !zombie && ep.socket != nil && ep.socket.dead {
			r.dropSocket(ep.socket)
		}
	}
}

// LoseNextPublishAck makes the relay accept the next irn_publish of the
// client and never answer it.
func (r *Relay) LoseNextPublishAck(clientId string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.loseAck[clientId] = true
}

// SetAckHold sets how long the publisher's result is held behind an
// unacknowledged push; default 6 s. It is also how long a push can be
// acknowledged. It counts for pushes made from now on; 0 is the default
// again.
func (r *Relay) SetAckHold(d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if d <= 0 {
		d = defaultAckHold
	}
	r.ackHold = d
}

// DuplicateNextPush makes the relay write the next push of the topic to a
// socket twice, with two ids. Either acknowledgement takes the message. A
// push to a peer is not the one.
func (r *Relay) DuplicateNextPush(topic string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.duplicate[topic] = true
}

// FailCalls makes the relay answer the next n calls of method by a socket
// client with this json-rpc error. Such a call has no effect. A second call
// for the same method replaces the first.
func (r *Relay) FailCalls(method string, n int, code int, message string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n <= 0 {
		delete(r.failures, method)
		return
	}
	r.failures[method] = &failure{n: n, code: code, message: message}
}

// SendOversized writes one text frame of this size, which is no json, to
// the sockets.
func (r *Relay) SendOversized(clientId string, bytes int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	text := []byte(strings.Repeat("x", max(bytes, 0)))
	for _, s := range r.sockets(clientId) {
		r.send(s, text)
	}
}
