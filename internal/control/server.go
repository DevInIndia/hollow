package control

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DevInIndia/hollow/internal/stats"
	"github.com/DevInIndia/hollow/internal/wire"
)

// Defaults for a watch. The floor exists because the interval is a client's
// instruction to do work on the server: a snapshot sorts three top-N lists and
// copies a reservoir, and a client asking for one every millisecond is asking
// this server to spend its time being watched.
const (
	DefaultInterval = 500 * time.Millisecond
	minInterval     = 100 * time.Millisecond
)

// maxConns bounds attached watchers.
//
// Loopback only, so this is not a defence against an attacker so much as against
// a script in a loop that forgets to close. Eight is more dashboards than anyone
// has screens for.
const maxConns = 8

// requestTimeout bounds how long a connection may sit having said nothing. A
// client that connects and then goes quiet is holding a slot.
const requestTimeout = 5 * time.Second

// writeTimeout bounds one frame. A watcher that has stopped reading fills the
// socket buffer and then this fires, which is what closes it rather than letting
// it accumulate.
const writeTimeout = 5 * time.Second

// refuseTimeout bounds the refusal of a connection past the cap, and maxRequest
// bounds what is drained from it. See refuse.
const (
	refuseTimeout = 250 * time.Millisecond
	maxRequest    = 4096
)

// Server answers control connections for one collector.
type Server struct {
	// Collector is what the answers are read from. Required.
	Collector *stats.Collector

	// Log receives connection-level problems. Nil takes the default logger,
	// which is what internal/server does with the same field.
	Log *slog.Logger

	// served counts connections that got as far as a valid request, which is
	// what the shutdown line reports. A count of accepts would include the port
	// scan that connected and said nothing.
	served atomic.Uint64
}

func (s *Server) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// Served reports how many clients made a valid request.
func (s *Server) Served() uint64 { return s.served.Load() }

// Listen binds addr for control connections.
//
// Separate from Serve so that the caller can bind before it starts announcing
// itself, and fail loudly. A control socket that could not bind is not a
// degraded server, it is a server the operator asked for and did not get.
func Listen(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("control: binding %s: %w", addr, err)
	}
	return ln, nil
}

// Serve answers connections until ctx is cancelled, then closes the listener and
// waits for the work already accepted to finish.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	if s.Collector == nil {
		return errors.New("control: no collector")
	}

	// The listener does not notice a cancelled context; closing it is what ends
	// the Accept below. Live connections are ended by their own context check,
	// since each one is either parked in a read with a deadline or ticking.
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	slots := make(chan struct{}, maxConns)
	var wg sync.WaitGroup

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				break
			}
			wg.Wait()
			return fmt.Errorf("control: accepting: %w", err)
		}

		select {
		case slots <- struct{}{}:
		default:
			// Told rather than dropped. Unlike a DNS client, whoever is on the
			// other end of this is a person at a terminal, and "too many
			// watchers" is a thing they can act on.
			refuse(conn)
			continue
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			defer conn.Close()
			s.handle(ctx, conn)
		}()
	}

	wg.Wait()
	return nil
}

// refuse tells a client it is past the cap and closes.
//
// The drain is the part that is not obvious and is not optional. The client has
// already sent its request, so those octets are sitting unread in the receive
// buffer, and closing a TCP socket with unread data queued sends a reset rather
// than a FIN. The reset discards whatever this end had already written, so the
// client would see a connection error instead of the explanation it was sent.
// Reading the request first turns the close back into a FIN.
//
// It runs on the accept loop rather than a goroutine, under a deadline short
// enough that it cannot become a way to stall accepts. When every slot is taken
// there is nothing useful to accept anyway.
func refuse(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(refuseTimeout))
	writeFrame(conn, Frame{Kind: KindError, Error: "too many control connections"})
	io.CopyN(io.Discard, conn, maxRequest)
}

// handle reads one request and answers it.
func (s *Server) handle(ctx context.Context, conn net.Conn) {
	conn.SetReadDeadline(time.Now().Add(requestTimeout))
	var req Request
	if err := readFrame(conn, &req); err != nil {
		if ctx.Err() == nil {
			s.log().Debug("reading a control request", "from", conn.RemoteAddr().String(), "err", err)
		}
		return
	}
	// The request is the last thing read on this connection. Clearing the
	// deadline stops a watch from being cut off five seconds in by a read that
	// is never going to happen.
	conn.SetReadDeadline(time.Time{})

	switch req.Command {
	case CommandSnapshot:
		s.served.Add(1)
		s.send(conn, Frame{Kind: KindSnapshot, Snapshot: snapshotOf(s.Collector)})
	case CommandWatch:
		s.served.Add(1)
		s.watch(ctx, conn, req)
	default:
		s.send(conn, Frame{Kind: KindError, Error: fmt.Sprintf("unknown command %q", req.Command)})
	}
}

// send writes one frame under a deadline, reporting whether the connection is
// still usable.
func (s *Server) send(conn net.Conn, f Frame) bool {
	conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if err := writeFrame(conn, f); err != nil {
		s.log().Debug("writing a control frame", "to", conn.RemoteAddr().String(), "err", err)
		return false
	}
	return true
}

// watch streams events as they happen and a fresh snapshot on a timer.
//
// One connection carries both rather than the client polling for snapshots and
// holding a second connection for events. The subscription is taken before the
// first snapshot is sent, so a query answered between the two appears in the
// stream rather than in neither.
func (s *Server) watch(ctx context.Context, conn net.Conn, req Request) {
	interval := time.Duration(req.IntervalMS) * time.Millisecond
	switch {
	case interval == 0:
		interval = DefaultInterval
	case interval < minInterval:
		interval = minInterval
	}

	events, cancel := s.Collector.Subscribe()
	defer cancel()

	if !s.send(conn, Frame{Kind: KindSnapshot, Snapshot: snapshotOf(s.Collector)}) {
		return
	}

	tick := time.NewTicker(interval)
	defer tick.Stop()

	// A watcher never sends anything after its request, so the only way to learn
	// that it has gone is to write to it. Reading in parallel would notice the
	// hangup sooner and would be a second goroutine per connection to notice
	// something the next tick notices anyway.
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if !s.send(conn, Frame{Kind: KindSnapshot, Snapshot: snapshotOf(s.Collector)}) {
				return
			}
		case e, ok := <-events:
			if !ok {
				return
			}
			ev := eventOf(e)
			if !s.send(conn, Frame{Kind: KindEvent, Event: &ev}) {
				return
			}
		}
	}
}

// snapshotOf renders a collector snapshot for the wire.
func snapshotOf(c *stats.Collector) *Snapshot {
	s := c.Snapshot()
	out := &Snapshot{
		UptimeMS:       s.Uptime.Milliseconds(),
		QueriesTotal:   s.QueriesTotal,
		QueriesBlocked: s.QueriesBlocked,
		CacheHits:      s.CacheHits,
		CacheMisses:    s.CacheMisses,
		CacheEntries:   s.CacheEntries,
		StaleServed:    s.StaleServed,
		UpstreamErrors: s.UpstreamErrors,
		LatencyP50MS:   millis(s.LatencyP50),
		LatencyP99MS:   millis(s.LatencyP99),
		TopClients:     items(s.TopClients),
		TopDomains:     items(s.TopDomains),
		TopBlocked:     items(s.TopBlocked),
		EventsDropped:  s.EventsDropped,
		NamesDropped:   s.NamesDropped,
	}
	return out
}

// items converts a top-N list, always to a non-nil slice.
//
// A nil slice marshals as null, and null is a third case every consumer would
// have to handle to say the same thing an empty list already says.
func items(in []stats.CountedItem) []Item {
	out := make([]Item, 0, len(in))
	for _, it := range in {
		out = append(out, Item{Name: it.Name, Count: it.Count})
	}
	return out
}

// eventOf renders one query outcome for the wire, with the DNS vocabulary
// resolved here so that nothing downstream needs it.
func eventOf(e stats.Event) Event {
	out := Event{
		At:         e.At,
		Name:       e.Name,
		Type:       wire.Type(e.Type).String(),
		Rcode:      wire.RcodeName(e.Rcode),
		Blocked:    e.Blocked,
		CacheHit:   e.CacheHit,
		Stale:      e.Stale,
		DurationMS: millis(e.Duration),
	}
	if e.Client.IsValid() {
		out.Client = e.Client.String()
	}
	return out
}

// millis keeps a fraction, because a p50 of 400 microseconds is a number worth
// seeing and integer milliseconds would render it as zero.
func millis(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}
