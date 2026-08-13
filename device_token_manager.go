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

// minRefreshTimeout is the floor on a DERIVED refresh interval.
//
// The half-life schedule below is the correctness fix for the hot loop; this
// floor is what keeps the failure mode non-catastrophic the next time the
// server changes its token lifetime, or a clock is skewed, or an `exp` is
// malformed. A non-positive interval means no sleep, and a successful refresh
// re-arms the same condition, so an interval derived from a server-controlled
// value needs a floor or it is one config change away from a hot loop -- 593
// refreshes in one observed 22-minute session, at ~30ms per pass.
//
// This bounds only the derived schedule. A deliberate immediate refresh (the
// first pass after Start, or an explicit RefreshToken) sets refreshPending and
// bypasses this entirely.
const minRefreshTimeout = 5 * time.Minute

// apiTokenManager is owned by Api, rather than by DeviceLocal/DeviceRemote.
// Api is the single owner of the mutable bearer token, so headless users such
// as the subnet miner and validator get exactly the same scheduling, retry,
// rotation, and rejection behavior as the apps without constructing a device.
type apiTokenManager struct {
	ctx    context.Context
	cancel context.CancelFunc
	api    *Api

	refreshMonitor *connect.Monitor
	active         atomic.Bool
	refreshPending atomic.Bool
}

func newApiTokenManager(ctx context.Context, api *Api) *apiTokenManager {
	cancelCtx, cancel := context.WithCancel(ctx)
	manager := &apiTokenManager{
		ctx:            cancelCtx,
		cancel:         cancel,
		api:            api,
		refreshMonitor: connect.NewMonitor(),
	}
	go connect.HandleError(manager.run)
	return manager
}

// jwtCanRefresh is intentionally an unverified parse. It is only a local
// scheduling predicate; /auth/refresh performs the authoritative signature,
// claims, active-client, and network-ownership checks.
func jwtCanRefresh(byJwt string) bool {
	claims := gojwt.MapClaims{}
	if _, _, err := gojwt.NewParser().ParseUnverified(byJwt, claims); err != nil {
		return false
	}
	clientId, clientOk := claims["client_id"].(string)
	deviceId, deviceOk := claims["device_id"].(string)
	return clientOk && clientId != "" && deviceOk && deviceId != ""
}

func jwtExpiration(byJwt string) time.Time {
	claims := gojwt.MapClaims{}
	if _, _, err := gojwt.NewParser().ParseUnverified(byJwt, claims); err != nil {
		return time.Time{}
	}
	expiration, err := claims.GetExpirationTime()
	if err != nil || expiration == nil {
		return time.Time{}
	}
	return expiration.Time
}

func stopApiTokenTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

func (self *apiTokenManager) Start() {
	if self.active.CompareAndSwap(false, true) {
		self.RefreshToken()
	}
}

func (self *apiTokenManager) TokenChanged() {
	if self.active.Load() {
		self.RefreshToken()
		return
	}
	// Wake the dormant loop as well. This matters when a network JWT is
	// replaced with a client JWT immediately before Start.
	self.refreshMonitor.NotifyAll()
}

// apiTokenRefreshTimeout is the delay until the next SCHEDULED refresh of byJwt.
//
// Extracted from run() rather than left inline so the schedule can be pinned
// against real tokens without a network, a clock, or a running manager -- the
// hot loop this floor guards against was a property of the arithmetic alone,
// and a test that has to stand up an http server to observe it is a test that
// will not be written. It never returns less than minRefreshTimeout; callers
// wanting an immediate refresh set refreshPending and skip it entirely.
func apiTokenRefreshTimeout(byJwt string, now time.Time) time.Duration {
	var refreshTimeout time.Duration
	if expirationTime := jwtExpiration(byJwt); expirationTime.IsZero() {
		// A refreshable legacy token without exp should not become
		// permanent. Revalidate it on a conservative weekly cadence.
		refreshTimeout = 7 * 24 * time.Hour
	} else {
		// Rotate at half-life. This adapts automatically as the server
		// shortens token lifetimes, without creating an immediate-refresh
		// loop when the lifetime is less than the old 14-day lead time.
		issuedAt := jwtIssuedAt(byJwt)
		refreshAt := expirationTime.Add(-12 * time.Hour)
		if !issuedAt.IsZero() && issuedAt.Before(expirationTime) {
			refreshAt = issuedAt.Add(expirationTime.Sub(issuedAt) / 2)
		}
		refreshTimeout = refreshAt.Sub(now)
	}

	// A token already past its refresh point -- a device resumed after being
	// offline, a skewed clock, a server that shortened its lifetime again, or
	// an `iat`-less token whose lifetime is shorter than the 12h lead above --
	// is refreshed after the floor rather than in a tight loop.
	if refreshTimeout < minRefreshTimeout {
		refreshTimeout = minRefreshTimeout
	}
	return refreshTimeout
}

func (self *apiTokenManager) run() {
	for {
		refreshNotify := self.refreshMonitor.NotifyChannel()
		byJwt := self.api.GetByJwt()

		if !self.active.Load() || !jwtCanRefresh(byJwt) {
			select {
			case <-self.ctx.Done():
				return
			case <-refreshNotify:
				continue
			}
		}

		refreshTimeout := time.Duration(0)
		if !self.refreshPending.Load() {
			refreshTimeout = apiTokenRefreshTimeout(byJwt, time.Now())
		}

		if 0 < refreshTimeout {
			self.api.logger().Infof(
				"[api-token]waiting %.2fs to refresh the jwt",
				float64(refreshTimeout/time.Millisecond)/1000.0,
			)
			timer := time.NewTimer(refreshTimeout)
			select {
			case <-self.ctx.Done():
				stopApiTokenTimer(timer)
				return
			case <-refreshNotify:
				stopApiTokenTimer(timer)
				continue
			case <-timer.C:
			}
		}

		// Cancellation has to be observed on the ZERO-timeout path too.
		//
		// That path is legitimately reachable -- the immediate first refresh
		// after Start, and every explicit RefreshToken, both set refreshPending
		// and skip the timer above -- so the guarantee cannot depend on the
		// computed timeout being positive. It is also reachable on a CLOSED
		// manager: the guard at the top of the loop selects over ctx.Done() and
		// refreshNotify, and when Start races Close both are ready, so Go picks
		// between them at random. Roughly half the time the loop falls through
		// here with a cancelled context and, without this check, issues the
		// request anyway.
		select {
		case <-self.ctx.Done():
			return
		default:
		}

		// Consume before the request. A manual request or new JWT installed
		// while this HTTP call is in flight sets the flag again and is handled
		// on the next outer iteration.
		self.refreshPending.Store(false)
		byJwt = self.api.GetByJwt()
		if !jwtCanRefresh(byJwt) {
			continue
		}

		for {
			self.api.logger().Infof("[api-token]refreshing the jwt now")
			loggedOut, stale, err := self.refreshToken(byJwt)
			if loggedOut || stale || err == nil {
				break
			}

			// A request arriving during the failed HTTP call must not sleep
			// behind retry jitter. Return to the outer loop immediately.
			if self.refreshPending.Load() {
				break
			}

			randomTimeout := time.Duration(mathrand.Int63n(int64(15 * time.Minute)))
			self.api.logger().Infof(
				"[api-token]jwt refresh failed. Will retry in %.2fs. err = %s",
				float64(randomTimeout/time.Millisecond)/1000.0,
				err,
			)

			retryNotify := self.refreshMonitor.NotifyChannel()
			timer := time.NewTimer(randomTimeout)
			select {
			case <-self.ctx.Done():
				stopApiTokenTimer(timer)
				return
			case <-retryNotify:
				stopApiTokenTimer(timer)
				// The token or refresh request changed; recalculate from the
				// API's current state rather than retrying the captured JWT.
				break
			case <-timer.C:
				continue
			}
			break
		}
	}
}

func jwtIssuedAt(byJwt string) time.Time {
	claims := gojwt.MapClaims{}
	if _, _, err := gojwt.NewParser().ParseUnverified(byJwt, claims); err != nil {
		return time.Time{}
	}
	issuedAt, err := claims.GetIssuedAt()
	if err != nil || issuedAt == nil {
		return time.Time{}
	}
	return issuedAt.Time
}

// refreshToken refreshes one captured JWT. loggedOut means that exact token
// was authoritatively rejected and cleared. stale means a concurrent login or
// token replacement won the compare-and-set, so this result was discarded.
func (self *apiTokenManager) refreshToken(byJwt string) (loggedOut bool, stale bool, returnErr error) {
	result, err := self.api.refreshJwtSyncWithContextAndJwt(self.ctx, byJwt)
	if err != nil {
		var statusErr *connect.HttpStatusError
		if errors.As(err, &statusErr) && statusErr.StatusCode == http.StatusUnauthorized {
			self.api.logger().Errorf("[api-token]jwt rejected by the api (%d): logging out", statusErr.StatusCode)
			if self.api.rejectByJwt(byJwt) {
				loggedOut = true
			} else {
				stale = true
			}
			return
		}

		self.api.logger().Errorf("[api-token]failed to refresh JWT: %v", err)
		returnErr = err
		return
	}

	if result.Error != nil {
		self.api.logger().Errorf("[api-token]failed to refresh JWT: %v", result.Error.Message)
		if self.api.rejectByJwt(byJwt) {
			loggedOut = true
		} else {
			stale = true
		}
		return
	}

	if result.ByJwt == "" {
		returnErr = fmt.Errorf("failed to refresh JWT: empty JWT returned")
		return
	}

	if !self.api.setRefreshedByJwt(byJwt, result.ByJwt) {
		stale = true
		return
	}
	self.api.logger().Infof("[api-token]successfully refreshed JWT")
	return
}

// RefreshToken records a level-triggered immediate refresh request.
func (self *apiTokenManager) RefreshToken() {
	self.refreshPending.Store(true)
	self.refreshMonitor.NotifyAll()
}

func (self *apiTokenManager) Close() {
	self.cancel()
}
