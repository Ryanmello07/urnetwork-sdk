//go:build !js && !ios_extension

package walletconnect

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"github.com/urnetwork/sdk/walletconnect/wire"
)

// what the hosted relay says in the body of a 403 (design B.3 R16)
const (
	refusedOrigin  = "origin not allowed"
	refusedProject = "Project not found"
)

// event is what a dial or a reader goroutine hands to the loop. gen is the
// generation of the dial or the socket it belongs to: the loop passes over
// what is not of the current one.
type event struct {
	kind int
	gen  int64
	ws   *websocket.Conn // evDialed: the socket, nil when the dial failed
	// evDialed: the status of a refused upgrade and up to 1 KiB of its body
	status int
	body   string
	text   []byte // evFrame
	err    error  // evLost
}

const (
	evNone = iota
	evTick
	evDialed
	evFrame
	evPing
	evLost
	evPanic // a goroutine of the transport panicked
)

// socket is the loop's view of one websocket. Budgets are in ticks.
type socket struct {
	ws  *websocket.Conn
	gen int64

	failed bool  // a write failed: the loop lets go of it at the end of the iteration
	age    int64 // since it opened
	idle   int64 // since anything arrived (R11c)
	rest   int64 // since its last round ended (R11a)

	// irn_subscribe and irn_unsubscribe that wait for their answer, by id
	calls map[string]*call
	// the held topics that have a subscribe result on this socket, with
	// their subscription ids
	subscribed map[string]string
	waiting    int   // subscribe results that are not in
	settling   bool  // a round, or the subscribe of a new topic, is not over
	round      int64 // the seq of the round in progress, 0 for none
	again      bool  // a read was asked for during this one
	quiet      int64 // counts the quiet windows: the end of an older one is passed over
	synced     bool  // R6: Connected
	wasSynced  bool  // R4: it synced once
}

type call struct {
	topic       string
	unsubscribe bool
	expires     int64 // the tick at which the socket is replaced for it (R11)
}

// dial starts one attempt (R5, R15) and returns at once: the outcome comes as
// an evDialed.
func (t *transport) dial() {
	t.gen++
	t.backoff = false
	gen := t.gen
	relayUrl := t.config.RelayUrls[t.urlIndex%len(t.config.RelayUrls)]
	target := relayUrl + "?projectId=" + url.QueryEscape(t.config.ProjectId)
	if t.identifier {
		target += "&" + t.config.IdentifierName + "=" + url.QueryEscape(t.config.IdentifierValue)
	}
	// The nonce only tells connections apart, the relay does not look at
	// it: a source that fails gives zeros. With no key the token is empty
	// and the relay refuses the client.
	nonce, _ := wire.NewKey(t.config.Rand)
	header := http.Header{}
	header.Set("Authorization", "Bearer "+wire.RelayAuthToken(t.key, relayUrl, t.nowMillis()/1000, nonce))
	dialer := &websocket.Dialer{
		NetDialContext:    t.config.NetDial,
		NetDialTLSContext: t.config.DialTLS,
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
		HandshakeTimeout:  t.timing.DialTimeout,
	}
	ctx, cancel := context.WithTimeout(t.ctx, t.timing.DialTimeout)
	t.cancelDial = cancel
	t.logf("walletconnect: dial %d to %s", gen, relayUrl)
	// the host alone: what is dialled has the project id and the app in it
	if parsed, err := url.Parse(relayUrl); err == nil {
		t.trace("sock dial %d %s", gen, parsed.Host)
	}
	go func() {
		defer cancel()
		defer t.contain()
		ws, response, err := dialer.DialContext(ctx, target, header)
		ev := event{kind: evDialed, gen: gen, ws: ws}
		if errors.Is(err, websocket.ErrBadHandshake) && response != nil {
			body, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
			ev.status, ev.body = response.StatusCode, string(body)
		}
		if !t.post(ev) && ws != nil {
			ws.Close()
		}
	}()
}

// dialed takes the outcome of the dial.
func (t *transport) dialed(ev event) {
	t.cancelDial = nil
	if ev.ws == nil {
		t.logf("walletconnect: dial %d failed, status %d", ev.gen, ev.status)
		t.trace("sock dial-failed %d status=%d", ev.gen, ev.status)
		origin := ev.status == http.StatusForbidden && strings.Contains(ev.body, refusedOrigin)
		switch {
		case origin && t.identifier:
			// R16: nothing is presented from here on, and this was no attempt
			t.identifier = false
		case !t.everSynced && (ev.status == http.StatusBadRequest || ev.status == http.StatusUnauthorized ||
			origin || ev.status == http.StatusForbidden && strings.Contains(ev.body, refusedProject)):
			t.fatal(ErrUnavailable, ev.status, "the relay refused the connection")
		default:
			t.failedAttempt()
		}
		return
	}
	s := &socket{ws: ev.ws, gen: ev.gen, calls: map[string]*call{}, subscribed: map[string]string{}}
	t.trace("sock open %d", s.gen)
	defer func() {
		if t.socket != s {
			s.ws.Close()
		}
	}()
	if !t.closing {
		// the socket is not the transport's yet: a topic the handler adds
		// now is subscribed by the sync, and by nothing before it
		t.handler.onOpen()
	}
	if t.gen != s.gen {
		return // the handler had the transport let go of it
	}
	t.socket = s
	go t.read(s.ws, s.gen)
	if !t.closing {
		t.startRound(s, t.timing.CallTimeout)
	}
}

// read is the reader goroutine of one socket.
func (t *transport) read(ws *websocket.Conn, gen int64) {
	defer t.contain()
	ws.SetReadLimit(t.timing.ReadLimit)
	// gorilla's own handler would answer without the loop seeing the ping (R11c)
	ws.SetPingHandler(func(data string) error {
		ws.WriteControl(websocket.PongMessage, []byte(data), time.Now().Add(t.timing.WriteTimeout))
		t.post(event{kind: evPing, gen: gen})
		return nil
	})
	for {
		_, text, err := ws.ReadMessage()
		if err != nil {
			// a frame above the limit is websocket.ErrReadLimit
			t.post(event{kind: evLost, gen: gen, err: err})
			return
		}
		if !t.post(event{kind: evFrame, gen: gen, text: text}) {
			return
		}
	}
}

// post hands an event to the loop. It is false when the loop has ended.
func (t *transport) post(ev event) bool {
	select {
	case t.events <- ev:
		return true
	case <-t.done:
		return false
	}
}

// contain is deferred by the goroutines of a dial and of a reader: their
// panic ends the transport and not the process (R1). The loop has its own.
// The value is not looked at: it may hold a secret.
func (t *transport) contain() {
	if recover() != nil {
		t.post(event{kind: evPanic})
	}
}

// write writes one text frame. After a failure the socket is written no
// more, and the loop lets go of it when the iteration ends.
func (t *transport) write(s *socket, text []byte) bool {
	if !s.failed {
		s.ws.SetWriteDeadline(time.Now().Add(t.timing.WriteTimeout))
		s.failed = s.ws.WriteMessage(websocket.TextMessage, text) != nil
	}
	return !s.failed
}

// hangUp sends the close frame 1000 and lets go of the socket (R3, R19). why
// is a word for the trace.
func (t *transport) hangUp(why string) {
	if s := t.socket; s != nil && !s.failed {
		t.trace("sock close %d code=1000 %s", s.gen, why)
		s.ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			time.Now().Add(t.timing.WriteTimeout))
	}
	t.drop()
}

// drop lets go of the dial in flight and of the socket, with no close frame.
// What they still deliver is of an older generation.
func (t *transport) drop() {
	t.gen++
	t.backoff = false
	if t.cancelDial != nil {
		t.cancelDial()
		t.cancelDial = nil
	}
	if s := t.socket; s != nil {
		t.socket = nil
		s.ws.Close()
	}
}
