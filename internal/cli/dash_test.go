package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DevInIndia/hollow/internal/control"
	"github.com/DevInIndia/hollow/internal/stats"
	"github.com/DevInIndia/hollow/internal/tui"
)

// safeBuffer is a bytes.Buffer the drawing goroutine and the test can both
// touch. The dashboard draws from a loop this test is watching from outside.
type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// controlOn starts a control socket on a fixed address so it can be stopped and
// started again under the same dashboard, which is what a reconnect needs.
func controlOn(t *testing.T, addr string, col *stats.Collector) (string, func()) {
	t.Helper()

	ln, err := control.Listen(addr)
	if err != nil {
		t.Fatalf("control.Listen(%q) error = %v", addr, err)
	}
	s := &control.Server{Collector: col, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Serve(ctx, ln)
	}()
	stopped := false
	return ln.Addr().String(), func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		<-done
	}
}

// waitFor polls until cond holds, so a test never sleeps for a fixed duration
// hoping something happened.
func waitFor(t *testing.T, why string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", why)
}

// The whole loop against a real server: attach, draw what it says, and keep
// drawing as it answers.
func TestWatchDrawsWhatTheServerReports(t *testing.T) {
	col := stats.New()
	col.Record(stats.Event{Name: "example.com.", Type: 1, Duration: time.Millisecond})
	addr, stop := controlOn(t, "127.0.0.1:0", col)
	defer stop()

	var out safeBuffer
	frame := &tui.Frame{Target: addr, Charset: tui.ASCII}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		watch(ctx, frame, addr, 50*time.Millisecond, func() { frame.Render(&out, 100, 24) })
	}()

	waitFor(t, "the first frame carrying the query", func() bool {
		return strings.Contains(out.String(), "example.com.")
	})
	cancel()
	<-done

	if strings.Contains(out.String(), "\x1b") {
		t.Error("a plain render carried an escape sequence")
	}
}

// Losing the server is a banner over the last known state, and then a
// reconnect. It will happen: somebody stops the server with the dashboard open.
func TestWatchShowsABannerAndReconnects(t *testing.T) {
	// A fixed port, because the server has to come back on the same address the
	// dashboard is holding. Bound and released first so the port is known free.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	addr := probe.Addr().String()
	probe.Close()

	col := stats.New()
	col.Record(stats.Event{Name: "first.example.", Type: 1})
	_, stop := controlOn(t, addr, col)

	var out safeBuffer
	frame := &tui.Frame{Target: addr, Charset: tui.ASCII}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		watch(ctx, frame, addr, 50*time.Millisecond, func() { frame.Render(&out, 100, 24) })
	}()

	waitFor(t, "the dashboard to attach", func() bool {
		return strings.Contains(out.String(), "first.example.")
	})

	stop()
	waitFor(t, "the disconnect banner", func() bool {
		return strings.Contains(out.String(), "reconnecting")
	})

	// The point of the banner: the numbers are still there behind it, because
	// the moment the server stops is when its last state is worth reading.
	tail := lastFrame(out.String())
	if !strings.Contains(tail, "first.example.") {
		t.Errorf("the last known state was cleared behind the banner:\n%s", tail)
	}

	// The server comes back on the same address, and the dashboard finds it
	// without being restarted.
	col2 := stats.New()
	col2.Record(stats.Event{Name: "second.example.", Type: 1})
	_, stop2 := controlOn(t, addr, col2)
	defer stop2()

	waitFor(t, "the reconnect", func() bool {
		return strings.Contains(out.String(), "second.example.")
	})
	cancel()
	<-done
}

// lastFrame returns the most recently appended frame, which in plain mode is
// everything after the last top border.
func lastFrame(s string) string {
	if i := strings.LastIndex(s, "+- hollow"); i >= 0 {
		return s[i:]
	}
	return s
}

// A dashboard started before its server must wait rather than exit, since the
// obvious order to type the two commands in is the wrong way round.
func TestWatchWaitsForAServerThatIsNotThereYet(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	addr := probe.Addr().String()
	probe.Close()

	var out safeBuffer
	frame := &tui.Frame{Target: addr, Charset: tui.ASCII}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		watch(ctx, frame, addr, 50*time.Millisecond, func() { frame.Render(&out, 100, 24) })
	}()

	waitFor(t, "the banner naming the flag", func() bool {
		return strings.Contains(out.String(), "--control")
	})

	col := stats.New()
	col.Record(stats.Event{Name: "late.example.", Type: 1})
	_, stop := controlOn(t, addr, col)
	defer stop()

	waitFor(t, "the dashboard to attach once the server starts", func() bool {
		return strings.Contains(out.String(), "late.example.")
	})
	cancel()
	<-done
}

// Cancelling the context ends the loop promptly, whatever it was doing. That is
// the Ctrl-C path, and a dashboard that does not return leaves the terminal in
// the alternate screen.
func TestWatchStopsWhenTheContextEnds(t *testing.T) {
	addr, stop := controlOn(t, "127.0.0.1:0", stats.New())
	defer stop()

	frame := &tui.Frame{Target: addr, Charset: tui.ASCII}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		watch(ctx, frame, addr, 50*time.Millisecond, func() { frame.Render(io.Discard, 100, 24) })
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("watch did not return after its context was cancelled")
	}
}

// A dashboard that is never going to reach a server still exits on Ctrl-C
// rather than sitting in a backoff that ignores it.
func TestWatchStopsDuringABackoff(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	addr := probe.Addr().String()
	probe.Close()

	frame := &tui.Frame{Target: addr, Charset: tui.ASCII}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		watch(ctx, frame, addr, 50*time.Millisecond, func() { frame.Render(io.Discard, 100, 24) })
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("watch did not return while waiting to retry")
	}
}

func TestBannerNamesTheAddressAndTheFix(t *testing.T) {
	const addr = "127.0.0.1:15354"
	if got := banner(addr, control.ErrNoServer); !strings.Contains(got, "--control") {
		t.Errorf("banner() = %q, want the flag that fixes it", got)
	}
	if got := banner(addr, nil); !strings.Contains(got, addr) || !strings.Contains(got, "reconnecting") {
		t.Errorf("banner() = %q", got)
	}
	if got := banner(addr, errors.New("broken pipe")); !strings.Contains(got, "broken pipe") {
		t.Errorf("banner() = %q, want the reason", got)
	}
}

func TestDashRejectsBadArguments(t *testing.T) {
	tests := map[string][]string{
		"unrecognised flag":           {"--nope"},
		"a positional":                {"example.com"},
		"an interval that is not one": {"--interval", "soon"},
		"a negative interval":         {"--interval", "-1s"},
		"a zero interval":             {"--interval", "0"},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr strings.Builder
			if got := Dash(args, &stdout, &stderr); got != ExitFailure {
				t.Errorf("Dash() = %d, want %d", got, ExitFailure)
			}
			if stderr.Len() == 0 {
				t.Error("a failed dash explained nothing on stderr")
			}
		})
	}
}
