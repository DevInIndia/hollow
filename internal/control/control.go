// Package control carries what a running server knows to a process that wants
// to watch it.
//
// The transport is a loopback TCP listener speaking length-prefixed JSON. Not a
// Unix domain socket, which does not exist on Windows, and not HTTP, which would
// bring a server, a router and a set of status-code decisions to a problem that
// is one request and a stream of records. The framing is four octets of length
// and then a JSON object, which is the same shape as DNS over TCP two packages
// over, for the same reason: a reader has to know where a message ends before it
// can parse one.
//
// The types on the wire are defined here rather than reused from internal/stats.
// That package deliberately knows nothing about DNS, so its events carry a query
// type as a bare uint16 and its durations as time.Duration, which JSON renders
// as a count of nanoseconds. Rendering both on this side of the socket is what
// lets a consumer be a dashboard and nothing else: it never imports internal/wire
// and never divides by a thousand.
package control

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// DefaultAddr is where the control socket listens when one is asked for.
//
// One above the DNS default of 15353, so an operator who remembers one number
// remembers both. Not 5354, which is adjacent to the mDNS range that made 5353
// unusable.
const DefaultAddr = "127.0.0.1:15354"

// maxFrame bounds a single frame in either direction.
//
// A length prefix is a promise about an allocation, and a reader that believes
// one is a reader that can be told to allocate four gigabytes by four octets.
// The largest frame this protocol produces is a snapshot carrying three lists of
// ten, which is a few kilobytes.
const maxFrame = 1 << 20

// Commands a client may send.
const (
	CommandSnapshot = "snapshot"
	CommandWatch    = "watch"
)

// Kinds a server may send.
const (
	KindSnapshot = "snapshot"
	KindEvent    = "event"
	KindError    = "error"
)

// Request is the single frame a client sends after connecting.
type Request struct {
	Command string `json:"command"`

	// IntervalMS is how often a watch resends the snapshot. Zero takes the
	// default, and anything below the floor is raised to it, because a client
	// asking for a snapshot every millisecond is asking the server to sort three
	// top-N lists a thousand times a second on its behalf.
	IntervalMS int `json:"interval_ms,omitempty"`
}

// Frame is what the server sends. Exactly one of the three bodies is set, and
// Kind says which, so a reader dispatches on one field rather than guessing from
// which pointer is non-nil.
type Frame struct {
	Kind     string    `json:"kind"`
	Snapshot *Snapshot `json:"snapshot,omitempty"`
	Event    *Event    `json:"event,omitempty"`
	Error    string    `json:"error,omitempty"`
}

// Snapshot is a point-in-time view of the server.
//
// Durations are milliseconds. A time.Duration marshals as an integer count of
// nanoseconds, which is correct, unreadable in a terminal, and a trap for
// anything on the other end that is not Go.
type Snapshot struct {
	UptimeMS       int64   `json:"uptime_ms"`
	QueriesTotal   uint64  `json:"queries_total"`
	QueriesBlocked uint64  `json:"queries_blocked"`
	CacheHits      uint64  `json:"cache_hits"`
	CacheMisses    uint64  `json:"cache_misses"`
	CacheEntries   int     `json:"cache_entries"`
	StaleServed    uint64  `json:"stale_served"`
	UpstreamErrors uint64  `json:"upstream_errors"`
	LatencyP50MS   float64 `json:"latency_p50_ms"`
	LatencyP99MS   float64 `json:"latency_p99_ms"`
	TopClients     []Item  `json:"top_clients"`
	TopDomains     []Item  `json:"top_domains"`
	TopBlocked     []Item  `json:"top_blocked"`
	EventsDropped  uint64  `json:"events_dropped"`
	NamesDropped   uint64  `json:"names_dropped"`
}

// Item is one row of a top-N list.
type Item struct {
	Name  string `json:"name"`
	Count uint64 `json:"count"`
}

// Event is one answered query.
type Event struct {
	At         time.Time `json:"at"`
	Client     string    `json:"client"`
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	Rcode      string    `json:"rcode"`
	Blocked    bool      `json:"blocked"`
	CacheHit   bool      `json:"cache_hit"`
	Stale      bool      `json:"stale"`
	DurationMS float64   `json:"duration_ms"`
}

// errFrameTooLarge is returned rather than allocating what a prefix asks for.
var errFrameTooLarge = errors.New("control: frame too large")

// writeFrame writes v as one length-prefixed JSON frame.
//
// The prefix and the body go out in a single Write. Two writes would be legal
// and would also let a reader that assumes one segment per frame work in testing
// and fail under load, which is the worst kind of correct.
func writeFrame(w io.Writer, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("control: encoding a frame: %w", err)
	}
	if len(body) > maxFrame {
		return errFrameTooLarge
	}
	buf := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(buf, uint32(len(body)))
	copy(buf[4:], body)
	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("control: writing a frame: %w", err)
	}
	return nil
}

// readFrame reads one length-prefixed JSON frame into v.
//
// The length is checked before the buffer is made, which is the whole reason
// this is a function and not four lines at each call site: every one of the
// three places that reads a frame would otherwise have to remember.
func readFrame(r io.Reader, v any) error {
	var prefix [4]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		// io.EOF passes through unwrapped, because a clean hangup between frames
		// is how a connection normally ends and callers test for it with
		// errors.Is rather than by reading a message.
		if errors.Is(err, io.EOF) {
			return err
		}
		return fmt.Errorf("control: reading a frame length: %w", err)
	}
	n := binary.BigEndian.Uint32(prefix[:])
	if n == 0 || n > maxFrame {
		return fmt.Errorf("%w: %d octets", errFrameTooLarge, n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		// A prefix that arrived followed by a short body is a truncated frame,
		// not a clean end, so io.EOF is translated here rather than passed on.
		return fmt.Errorf("control: reading a %d octet frame: %w", n, err)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("control: decoding a frame: %w", err)
	}
	return nil
}
