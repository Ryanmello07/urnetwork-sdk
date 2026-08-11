package sdk

import (
	"context"
	"errors"
	"fmt"
	mathrand "math/rand"
	"net/http"
	"sync/atomic"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"

	"github.com/urnetwork/connect"
)

// minRefreshTimeout is the floor on the scheduled refresh interval, and it is
// the load-bearing half of the schedule.
//
// The refresh point used to be a FIXED lead subtracted from the token's `exp`
// (14 days, calibrated to a 30-day server lifetime). The server later shortened
// its lifetime to 24h, which made the lead exceed the token's entire life, so
// every computed timeout was ~13 days in the PAST. A non-positive timeout means
// no sleep, and since a successful refresh yields another 24h token, success
// re-armed the same condition: an unbounded refresh loop at ~30ms per pass, 593
// refreshes in one observed 22-minute session.
//
// The half-life schedule below is the correctness fix; this floor is what makes
// the failure mode non-catastrophic the NEXT time the server changes its
// lifetime, or a clock is skewed, or an `exp` is malformed. Any interval derived
// from a server-controlled value needs a floor, or it is one config change away
// from a hot loop.
const minRefreshTimeout = 5 * time.Minute

// noExpirationRefreshTimeout is the fallback when the stored jwt has no usable
// `exp` -- including when it is empty or unparseable.
const noExpirationRefreshTimeout = 7 * 24 * time.Hour

// jwtRefreshTimeout is the delay until the next SCHEDULED refresh of `byJwt`.
//
// Pure and total by design: it is the entire schedule, so it can be pinned
// against real tokens without a network, a clock, or a running device. It never
// returns less than minRefreshTimeout -- callers that want an immediate refresh
// (the first pass, or an explicit RefreshToken request) override it deliberately.
func jwtRefreshTimeout(byJwt string, now time.Time) time.Duration {
	var issuedTime time.Time
	var expirationTime time.Time

	if claims, err := parseJwtClaims(byJwt); err == nil {
		if iat, ok := claims["iat"].(float64); ok {
			issuedTime = time.Unix(int64(iat), 0)
		}
		if exp, ok := claims["exp"].(float64); ok {
			expirationTime = time.Unix(int64(exp), 0)
		}
	}

	var refreshTimeout time.Duration
	if expirationTime.IsZero() {
		// no expiration, or none we can read (including an empty jwt): refresh at
		// an arbitrary long interval
		refreshTimeout = noExpirationRefreshTimeout
	} else {
		// Refresh at the token's HALF-LIFE, derived from the token itself.
		//
		// The server's token lifetime is not a constant this sdk can hardcode: it
		// was 30 days, then became 24h, and the hardcoded 14-day lead this
		// replaces silently became a hot loop when it did (see minRefreshTimeout).
		// A half-life is correct for whatever lifetime the server chooses, and it
		// is the cadence the server documents for sdk clients.
		//
		// Prefer `iat` so the half-life is of the token's REAL lifetime rather than
		// of whatever happens to remain right now -- halving the remainder on every
		// pass would make the interval collapse geometrically toward the floor.
		// Fall back to now when `iat` is absent or nonsensical.
		lifetimeStart := issuedTime
		if lifetimeStart.IsZero() || !lifetimeStart.Before(expirationTime) {
			lifetimeStart = now
		}
		refreshTime := lifetimeStart.Add(expirationTime.Sub(lifetimeStart) / 2)
		refreshTimeout = refreshTime.Sub(now)
	}

	// A token already past its half-life -- a device resumed after being offline,
	// a skewed clock, a server that shortened its lifetime again -- is refreshed
	// after the floor rather than in a tight loop.
	if refreshTimeout < minRefreshTimeout {
		refreshTimeout = minRefreshTimeout
	}
	return refreshTimeout
}

// parseJwtClaims reads a jwt's claims WITHOUT verifying it. The sdk only ever
// reads claims from tokens the server already handed it; verification is the
// server's job on the next call.
func parseJwtClaims(jwt string) (gojwt.MapClaims, error) {
	if jwt == "" {
		return nil, errors.New("Empty jwt.")
	}
	token, _, err := gojwt.NewParser().ParseUnverified(jwt, gojwt.MapClaims{})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(gojwt.MapClaims)
	if !ok {
		return nil, errors.New("Unexpected claims type.")
	}
	return claims, nil
}

type deviceTokenManager struct {
	ctx              context.Context
	cancel           context.CancelFunc
	log              connect.Logger
	api              *Api
	refreshMonitor   *connect.Monitor
	onTokenRefreshed func(newToken string)
	logout           func() error

	// refreshPending makes a refresh request LEVEL-triggered instead of edge-triggered.
	//
	// The monitor is a pure edge: NotifyAll closes the current channel and swaps in a
	// fresh one. The run loop captures that channel at the TOP of each iteration — so a
	// RefreshToken() landing while the loop is inside the /auth/refresh http call closes
	// a channel nobody is listening to any more. The request is silently DROPPED, and
	// the next scheduled refresh is ~16 days away.
	//
	// That is a real failure, not a theoretical one: an app asking for a refresh right
	// after an upgrade (to pick up the new `pro` claim) would simply never get one, and
	// nothing would say so. The flag survives across iterations, so a request made at any
	// moment is honored on the next pass.
	refreshPending atomic.Bool
}

func newDeviceTokenManager(
	ctx context.Context,
	log connect.Logger,
	api *Api,
	onTokenRefreshed func(newToken string),
	logout func() error,
) *deviceTokenManager {
	cancelCtx, cancel := context.WithCancel(ctx)

	manager := &deviceTokenManager{
		ctx:              cancelCtx,
		cancel:           cancel,
		log:              log,
		api:              api,
		refreshMonitor:   connect.NewMonitor(),
		onTokenRefreshed: onTokenRefreshed,
		logout:           logout,
	}

	go connect.HandleError(manager.run)

	return manager
}

func (self *deviceTokenManager) run() {
	// the first refresh runs immediately: an app start with a stored jwt
	// must find out right away when the jwt's client no longer exists on the
	// server (see refreshToken), instead of silently running against a dead
	// client until the scheduled refresh window
	first := true
	for {
		// Capture the notify channel BEFORE reading refreshPending, and use it for
		// exactly ONE wait (the inner retry loop re-captures its own). Subscribe
		// then check, never the reverse: a RefreshToken landing between the check
		// and the capture would close a channel we had not taken yet, and we would
		// sleep the full interval with the request still pending.
		//
		// `Monitor.NotifyAll` CLOSES the current channel and swaps in a fresh one,
		// so a captured channel that outlives its wait is a permanently-ready
		// select arm -- a zero-backoff spin for the rest of the iteration.
		refreshNotify := self.refreshMonitor.NotifyChannel()

		byJwt := self.api.GetByJwt()
		if self.log.V(1).Enabled() {
			if claims, err := parseJwtClaims(byJwt); err == nil {
				self.log.Infof("[dtm]JWT claims: %+v", claims)
			}
		}

		refreshTimeout := jwtRefreshTimeout(byJwt, time.Now())

		if first {
			// the first refresh runs immediately: an app start with a stored jwt
			// must find out right away when the jwt's client no longer exists on
			// the server (see refreshToken)
			first = false
			refreshTimeout = 0
		} else if self.refreshPending.Load() {
			// A refresh was requested while we were busy (or while computing the
			// timeout above), so the monitor's edge went to a channel we are no
			// longer listening to. Honor the request instead of sleeping.
			refreshTimeout = 0
		}

		if 0 < refreshTimeout {
			self.log.Infof(
				"[dtm]waiting %.2fs to refresh the jwt",
				float64(refreshTimeout/time.Millisecond)/1000.0,
			)
			select {
			case <-self.ctx.Done():
				return
			case <-refreshNotify:
			case <-time.After(refreshTimeout):
			}
		} else {
			// The wait above is the ONLY place the outer loop observed
			// cancellation, and it is skipped whenever the timeout is
			// non-positive. A closed device therefore kept re-entering
			// refreshToken forever: 297 attempts in 497ms against a cancelled
			// ClientStrategy in one observed teardown. Cancellation must be
			// observed on this path too, and it must not depend on the schedule
			// above being correct.
			select {
			case <-self.ctx.Done():
				return
			default:
			}
		}

		// Consume the request BEFORE doing the work, not after. A RefreshToken() that
		// lands *during* the refresh below must set the flag again and be serviced by the
		// next iteration — clearing it afterwards would swallow exactly that request.
		self.refreshPending.Store(false)

		loggedOut := false
		canceled := false
		func() {
			for {
				self.log.Infof("[dtm]refreshing the jwt now")
				var err error
				loggedOut, err = self.refreshToken()
				if err == nil {
					return
				}

				randomTimeout := time.Duration(mathrand.Int63n(int64(15 * time.Minute)))

				self.log.Infof(
					"[dtm]jwt refresh failed. Will retry in %.2fs. err = %s",
					float64(randomTimeout/time.Millisecond)/1000.0,
					err,
				)

				// re-capture per wait: see the note at the outer capture. A
				// NotifyAll during this iteration would otherwise leave the arm
				// below permanently ready and defeat the backoff entirely.
				retryNotify := self.refreshMonitor.NotifyChannel()

				select {
				case <-self.ctx.Done():
					canceled = true
					return
				case <-retryNotify:
				case <-time.After(randomTimeout):
				}
			}
		}()
		if canceled {
			// This `return` USED TO BE the closure's, which exited only the
			// closure -- `loggedOut` was false, so the check below did not stop
			// the loop and the outer `for` immediately re-entered the refresh.
			// That is how a correctly-computed backoff ("Will retry in 128.69s")
			// was observed being discarded in the same millisecond, 297 times.
			// Cancellation has to stop run(), not just the retry.
			return
		}
		if loggedOut {
			// the local auth state is cleared; there is nothing left to
			// refresh. Without stopping here, an already-expired stored jwt
			// would hot loop refresh->logout.
			return
		}
	}
}

// refreshToken refreshes the jwt once. `loggedOut` is true when the api
// confirmed the credential is invalid (an error result such as "client no
// longer exists", or a 401) and the logout callback ran; `err` is a transient
// failure the caller should retry.
//
// The logout decision is deliberately conservative: only a confirmed api
// response that rejects the jwt logs out. Transport failures (offline
// network), timeouts, and non-401 statuses (5xx outages, proxy/waf blocks)
// retry forever without touching the auth state. Non-2xx responses surface as
// a typed `connect.HttpStatusError` from the http layer, so an outage page
// body can never be mistaken for a refresh result.
func (self *deviceTokenManager) refreshToken() (loggedOut bool, returnErr error) {
	// bound the request to the manager ctx so a closed device does not leave
	// the refresh (and its dialer evals) running to their own timeouts
	result, err := self.api.refreshJwtSyncWithContext(self.ctx)

	if err != nil {
		// a 401 over the api connection is the auth layer rejecting the jwt
		// itself (expired or unparseable): confirmed invalid
		var statusErr *connect.HttpStatusError
		if errors.As(err, &statusErr) && statusErr.StatusCode == http.StatusUnauthorized {
			self.log.Errorf("[dtm]jwt rejected by the api (%d): logging out", statusErr.StatusCode)

			self.logout()
			loggedOut = true
			return
		}

		/*
		 *  potentially API failed, try again
		 */

		self.log.Errorf("[dtm]failed to refresh JWT: %v", err)

		returnErr = err
		return
	}

	if result.Error != nil {
		/**
		 * not a API error, but a token refresh error
		 * for example, client no longer exists
		 */

		self.log.Errorf("[dtm]failed to refresh JWT: %v", result.Error.Message)

		self.logout()
		loggedOut = true
		return
	}

	// guard against api logic errors that could mess up the client state
	if result.ByJwt == "" {
		returnErr = fmt.Errorf("Failed to refresh JWT: empty JWT returned")
		return
	}

	self.log.Infof("[dtm]successfully refreshed JWT")

	self.onTokenRefreshed(result.ByJwt)

	return
}

// refreshes the token immediately
func (self *deviceTokenManager) RefreshToken() {
	// Record the request FIRST. The notify below is only a wake-up; the flag is what
	// makes the request survive being made while the loop is busy refreshing.
	self.refreshPending.Store(true)
	self.refreshMonitor.NotifyAll()
}

func (self *deviceTokenManager) Close() {
	self.cancel()
}
