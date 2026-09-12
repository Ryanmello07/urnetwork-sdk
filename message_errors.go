package sdk

import (
	"errors"
)

// The typed refusals the messaging client's durable stream store owns.
//
// Every one of them is a section 5.9 G7 fatal error: a value a caller matches with errors.Is,
// never a bool, never a log line, and -- this is the whole reason the file exists -- never
// (0, nil). Contract clause 4 of connect/messagegroup.StreamIndexReserver makes an unseen
// stream an error-free zero, and a sender ratchet resumes at HighWater + 1. So every condition
// that is NOT "this stream was never seen" and is answered as a zero anyway restarts the
// ladder at index 1 under a class key that has not moved, which spec A section 5.6 calls
//
//	a total break of both AEADs for that record.
//
// The errors below are the conditions that must never take that exit.
var (
	// ErrStreamKeyWidth is a group id or a sender handle offered to the store at a width
	// connect/messagegroup.StreamKey cannot hold, or a count of key parameters that is not
	// the count that type declares. Section 8.2 spells the two parameters []byte and states
	// no length rule; StreamKey's fields are fixed-width arrays and are total over their
	// domain. The flattening between the two is the only place a 17-octet group id can
	// become a panic or a silent truncation, and a truncation collides two streams onto one
	// row -- which hands the second stream indices the first has already used. The refusal
	// names which parameter it refused and what width it had.
	ErrStreamKeyWidth = errors.New("stream key width")

	// ErrStreamKeySpace is a row written under a key derivation this build does not produce.
	//
	// THIS IS LEDGER ITEM 170's MECHANISM. Ruling A1 removed the retention-class byte from
	// StreamKey, and StreamKey's field set IS the identity a reserver keys a row on. A store
	// holding rows under the older, three-field derivation answers HighWater 0 for an A1 key
	// -- silently, because clause 4 makes "never seen" an error-free zero -- and the ladder
	// restarts at 1. The store therefore versions its whole key space by a tag derived from
	// StreamKey's own field set and REFUSES any row bearing a different one, rather than
	// migrating rows that, on the day this shipped, did not exist anywhere.
	//
	// The refusal is deliberately coarse: one foreign-tagged row refuses every key in the
	// directory, because a directory written by another build tells this build nothing about
	// which of its keys that build had already spent.
	ErrStreamKeySpace = errors.New("stream key space")

	// ErrStreamStoreState is state the store found and cannot answer from: an entry in the
	// row directory that is not a row under any tag, a row whose records are damaged in a
	// way an interrupted append cannot produce, an unreadable row directory, or a store that
	// has been closed.
	//
	// It is explicitly NOT the answer for a torn tail. A trailing record that does not verify
	// is the ORDINARY outcome of a crash mid-append; refusing it would leave a row no later
	// process could open, on exactly the path the durability exists to survive. See
	// classifyStreamRow for the three cases and the discriminator between them.
	ErrStreamStoreState = errors.New("stream store state")
)
