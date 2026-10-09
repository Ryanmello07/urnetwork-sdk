//go:build !js && !ios_extension

package walletconnect

import "time"

// Timing holds every wait of a client. The values marked "running" are
// budgets of running time: they are counted in ticks of the loop, so a
// process that was suspended has not used them up, and they start again when
// it resumes. Only the three marked "wall clock" are compared with Config.Now.
type Timing struct {
	Tick            time.Duration // 1 s
	SuspendGap      time.Duration // 3 s: a larger wall-clock gap between two loop iterations is a resume edge (R2)
	DialTimeout     time.Duration // 8 s (R5)
	WriteTimeout    time.Duration // 5 s (R1)
	BackoffBase     time.Duration // 250 ms (R4)
	BackoffMax      time.Duration // 5 s (R4)
	BackoffJitter   float64       // 0.2 (R4)
	HealthySocket   time.Duration // 10 s running (R4)
	Quiet           time.Duration // 500 ms (R6)
	CallTimeout     time.Duration // 15 s running (R11b)
	ProbeInterval   time.Duration // 15 s running (R11a)
	ProbeTimeout    time.Duration // 5 s running (R11a)
	Idle            time.Duration // 45 s running (R11c)
	FirstConnect    time.Duration // 20 s running (R17)
	DeadlineGrace   time.Duration // 20 s running (R12)
	PairingTtl      time.Duration // 300 s wall clock
	SettleTtl       time.Duration // 300 s wall clock
	WalletAnswerTtl time.Duration // 30 s running: give-up of an answer to a wallet-initiated request (B.4)
	Linger          time.Duration // 120 s foreground running (R21)
	CloseFlush      time.Duration // 3 s running (R19)
	ReadLimit       int64         // 1 << 20 (R5)
	ReadLimitCloses int           // 3 (R4)
	RelayCallErrors int           // 3 (R16)
}

// DefaultTiming is the timing of design B.3; the rule of each value is named
// beside its field.
func DefaultTiming() *Timing {
	return &Timing{
		Tick:            time.Second,
		SuspendGap:      3 * time.Second,
		DialTimeout:     8 * time.Second,
		WriteTimeout:    5 * time.Second,
		BackoffBase:     250 * time.Millisecond,
		BackoffMax:      5 * time.Second,
		BackoffJitter:   0.2,
		HealthySocket:   10 * time.Second,
		Quiet:           500 * time.Millisecond,
		CallTimeout:     15 * time.Second,
		ProbeInterval:   15 * time.Second,
		ProbeTimeout:    5 * time.Second,
		Idle:            45 * time.Second,
		FirstConnect:    20 * time.Second,
		DeadlineGrace:   20 * time.Second,
		PairingTtl:      300 * time.Second,
		SettleTtl:       300 * time.Second,
		WalletAnswerTtl: 30 * time.Second,
		Linger:          120 * time.Second,
		CloseFlush:      3 * time.Second,
		ReadLimit:       1 << 20,
		ReadLimitCloses: 3,
		RelayCallErrors: 3,
	}
}
