package control

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DevInIndia/hollow/internal/stats"
	"github.com/DevInIndia/hollow/internal/wire"
)

// serve starts a control server on loopback and returns its address. Everything
// is torn down when the test ends.
func serve(t *testing.T, col *stats.Collector) (string, *Server) {
	t.Helper()

	ln, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	s := &Server{Collector: col, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := s.Serve(ctx, ln); err != nil {
			t.Errorf("Serve() error = %v", err)
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return ln.Addr().String(), s
}

func TestFetchReturnsWhatTheCollectorCounted(t *testing.T) {
	col := stats.New()
	col.CacheEntries = func() int { return 7 }
	col.Record(stats.Event{
		Client:   netip.MustParseAddr("192.0.2.9"),
		Name:     "example.com.",
		Type:     uint16(wire.TypeAAAA),
		Rcode:    wire.RcodeNXDomain,
		Duration: 1500 * time.Microsecond,
	})
	addr, _ := serve(t, col)

	snap, err := Fetch(t.Context(), addr)
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if snap.QueriesTotal != 1 {
		t.Errorf("QueriesTotal = %d, want 1", snap.QueriesTotal)
	}
	if snap.CacheEntries != 7 {
		t.Errorf("CacheEntries = %d, want 7", snap.CacheEntries)
	}
	// The gauge that cannot be accumulated from events has to survive the wire
	// like everything else, and a p50 under a millisecond has to arrive as a
	// fraction rather than as zero.
	if snap.LatencyP50MS <= 0 || snap.LatencyP50MS >= 2 {
		t.Errorf("LatencyP50MS = %v, want the 1.5 ms that was recorded", snap.LatencyP50MS)
	}
	if len(snap.TopDomains) != 1 || snap.TopDomains[0].Name != "example.com." {
		t.Errorf("TopDomains = %+v", snap.TopDomains)
	}
}

// A top-N list nobody has filled yet must arrive as an empty list, not as null,
// or every consumer grows a nil check to say what an empty list already says.
func TestSnapshotListsAreNeverNull(t *testing.T) {
	addr, _ := serve(t, stats.New())

	snap, err := Fetch(t.Context(), addr)
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	for name, list := range map[string][]Item{
		"TopClients": snap.TopClients,
		"TopDomains": snap.TopDomains,
		"TopBlocked": snap.TopBlocked,
	} {
		if list == nil {
			t.Errorf("%s is nil, want an empty list", name)
		}
	}
}

// The DNS vocabulary is resolved on the server side, so that nothing downstream
// of the socket has to import internal/wire to render a row.
func TestWatchRendersTypeAndRcodeAsNames(t *testing.T) {
	col := stats.New()
	addr, _ := serve(t, col)

	w, err := Dial(t.Context(), addr, minInterval)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer w.Close()

	// The first frame is always the snapshot, and the subscription is taken
	// before it is sent, so an event recorded now cannot fall between the two.
	if f := <-w.Frames(); f.Kind != KindSnapshot {
		t.Fatalf("first frame = %q, want %q", f.Kind, KindSnapshot)
	}
	col.Record(stats.Event{
		Client:  netip.MustParseAddr("192.0.2.4"),
		Name:    "ads.example.",
		Type:    uint16(wire.TypeMX),
		Rcode:   wire.RcodeNXDomain,
		Blocked: true,
	})

	deadline := time.After(5 * time.Second)
	for {
		select {
		case f, ok := <-w.Frames():
			if !ok {
				t.Fatalf("the stream ended before the event arrived: %v", w.Err())
			}
			if f.Kind != KindEvent {
				continue
			}
			if f.Event.Type != "MX" || f.Event.Rcode != "NXDOMAIN" {
				t.Errorf("event = %+v, want MX and NXDOMAIN spelled out", f.Event)
			}
			if f.Event.Client != "192.0.2.4" || !f.Event.Blocked {
				t.Errorf("event = %+v", f.Event)
			}
			return
		case <-deadline:
			t.Fatal("no event frame arrived")
		}
	}
}

// A watch keeps sending snapshots on its own, which is what the dashboard's
// counters are built from. Without this the stream would be silent on an idle
// server and the uptime would freeze.
func TestWatchKeepsSendingSnapshots(t *testing.T) {
	addr, _ := serve(t, stats.New())

	w, err := Dial(t.Context(), addr, minInterval)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer w.Close()

	deadline := time.After(5 * time.Second)
	for seen := 0; seen < 2; {
		select {
		case f, ok := <-w.Frames():
			if !ok {
				t.Fatalf("the stream ended after %d snapshots: %v", seen, w.Err())
			}
			if f.Kind == KindSnapshot {
				seen++
			}
		case <-deadline:
			t.Fatal("a second snapshot never arrived")
		}
	}
}

// The claim the whole stats package is arranged around: watching the server
// cannot slow it down. A watcher that connects and never reads must not stop
// Record from returning.
func TestAWatcherThatNeverReadsDoesNotBlockTheQueryPath(t *testing.T) {
	col := stats.New()
	addr, _ := serve(t, col)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer conn.Close()
	if err := writeFrame(conn, Request{Command: CommandWatch}); err != nil {
		t.Fatalf("writeFrame() error = %v", err)
	}
	// Wait until the server has actually subscribed, so the events below are
	// offered to a subscriber rather than to nobody.
	for range 100 {
		if col.Subscribers() > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Far more than the subscriber buffer, so the send has to be dropping
		// rather than merely fitting.
		for range 10_000 {
			col.Record(stats.Event{Name: "example.com.", Type: uint16(wire.TypeA)})
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Record blocked on a watcher that stopped reading")
	}
	if col.Snapshot().EventsDropped == 0 {
		t.Error("nothing was recorded as dropped, so the events were not offered to the watcher")
	}
}

func TestServerRejectsAnUnknownCommand(t *testing.T) {
	addr, _ := serve(t, stats.New())

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer conn.Close()
	if err := writeFrame(conn, Request{Command: "drop-tables"}); err != nil {
		t.Fatalf("writeFrame() error = %v", err)
	}
	var f Frame
	if err := readFrame(conn, &f); err != nil {
		t.Fatalf("readFrame() error = %v", err)
	}
	if f.Kind != KindError || !strings.Contains(f.Error, "drop-tables") {
		t.Errorf("frame = %+v, want an error naming the command", f)
	}
}

// Fetch is what hollow stats runs, and the first thing a user does is run it
// against a server started without --control.
func TestFetchSaysWhenNothingIsListening(t *testing.T) {
	// Bound and closed, so the port is real and certainly free.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	if _, err := Fetch(t.Context(), addr); !errors.Is(err, ErrNoServer) {
		t.Errorf("Fetch() error = %v, want ErrNoServer", err)
	}
}

// A length prefix is a promise about an allocation, and the only safe response
// to a four-gigabyte promise is to refuse it.
func TestReadFrameRefusesAnAbsurdLength(t *testing.T) {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint32(1<<30))
	buf.WriteString("{}")

	var f Frame
	err := readFrame(&buf, &f)
	if !errors.Is(err, errFrameTooLarge) {
		t.Errorf("readFrame() error = %v, want errFrameTooLarge", err)
	}
}

func TestReadFrameRejectsMalformedInput(t *testing.T) {
	frame := func(body string) []byte {
		out := make([]byte, 4+len(body))
		binary.BigEndian.PutUint32(out, uint32(len(body)))
		copy(out[4:], body)
		return out
	}
	tests := map[string][]byte{
		"a truncated prefix":  {0, 0},
		"a zero length":       {0, 0, 0, 0},
		"a body that is cut":  append(frame(`{"kind":"snapshot"}`)[:6], 'x'),
		"a body that is junk": frame(`not json`),
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			var f Frame
			if err := readFrame(bytes.NewReader(in), &f); err == nil {
				t.Error("readFrame() accepted it")
			}
		})
	}
}

// An empty read is a clean hangup rather than a fault, and callers tell the two
// apart with errors.Is. Wrapping io.EOF here would make every one of them wrong.
func TestReadFrameReportsACleanHangupAsEOF(t *testing.T) {
	var f Frame
	if err := readFrame(bytes.NewReader(nil), &f); !errors.Is(err, io.EOF) {
		t.Errorf("readFrame() error = %v, want io.EOF", err)
	}
}

func TestFrameRoundTripsEveryField(t *testing.T) {
	want := Frame{Kind: KindEvent, Event: &Event{
		At:         time.Now().UTC().Truncate(time.Second),
		Client:     "192.0.2.1",
		Name:       "example.com.",
		Type:       "A",
		Rcode:      "NOERROR",
		CacheHit:   true,
		DurationMS: 0.25,
	}}

	var buf bytes.Buffer
	if err := writeFrame(&buf, want); err != nil {
		t.Fatalf("writeFrame() error = %v", err)
	}
	var got Frame
	if err := readFrame(&buf, &got); err != nil {
		t.Fatalf("readFrame() error = %v", err)
	}
	if got.Kind != want.Kind || *got.Event != *want.Event {
		t.Errorf("round trip: got %+v, want %+v", *got.Event, *want.Event)
	}
}

// Over the cap a client is told rather than dropped, because whoever is on the
// other end of this socket is a person at a terminal.
func TestServerRefusesPastTheConnectionCap(t *testing.T) {
	addr, _ := serve(t, stats.New())

	var open []*Watcher
	defer func() {
		for _, w := range open {
			w.Close()
		}
	}()
	for range maxConns {
		w, err := Dial(t.Context(), addr, 0)
		if err != nil {
			t.Fatalf("Dial() error = %v", err)
		}
		open = append(open, w)
		// Wait for the first frame, so the connection is certainly established
		// and holding its slot before the next one is opened.
		if f, ok := <-w.Frames(); !ok || f.Kind != KindSnapshot {
			t.Fatalf("watcher did not start: %+v", f)
		}
	}

	if _, err := Fetch(t.Context(), addr); err == nil || !strings.Contains(err.Error(), "too many") {
		t.Errorf("the connection past the cap got error %v, want one saying too many", err)
	}
}

// Shutdown has to end open watches, or the process hangs waiting for a dashboard
// somebody left running in another terminal.
func TestShutdownEndsAnOpenWatch(t *testing.T) {
	ln, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	s := &Server{Collector: stats.New(), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.Serve(ctx, ln); err != nil {
			t.Errorf("Serve() error = %v", err)
		}
	}()

	w, err := Dial(context.Background(), ln.Addr().String(), 0)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer w.Close()
	<-w.Frames()

	cancel()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return with a watch still attached")
	}
	if s.Served() != 1 {
		t.Errorf("Served() = %d, want 1", s.Served())
	}
}

func TestServeNeedsACollector(t *testing.T) {
	ln, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()
	if err := (&Server{}).Serve(t.Context(), ln); err == nil {
		t.Error("Serve() with no collector returned nil")
	}
}
