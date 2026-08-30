package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/DevInIndia/hollow/internal/control"
	"github.com/DevInIndia/hollow/internal/tui"
)

// Reconnect backoff. A dashboard whose server has gone is going to be sitting
// there for as long as it takes somebody to start it again, so the retry starts
// fast enough to feel instant on a restart and then backs off rather than
// hammering a socket that is not there.
const (
	minBackoff = 500 * time.Millisecond
	maxBackoff = 5 * time.Second
)

// Dash runs the dash verb and returns the process exit code.
//
// A separate process from serve rather than a flag on it, which is three things
// at once: the server stays headless and scriptable, the dashboard attaches to
// and detaches from a server that keeps running, and the demo is a server in one
// pane and this in another.
func Dash(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("hollow dash", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		target   = fs.String("target", control.DefaultAddr, "control socket of the server to watch")
		interval = fs.Duration("interval", control.DefaultInterval, "how often to redraw, and how often to ask for a snapshot")
		width    = fs.Int("width", 0, "frame width; default is $COLUMNS, then 100")
		height   = fs.Int("height", 0, "frame height; default is $LINES, then 30")
		ascii    = fs.Bool("ascii", false, "draw with ASCII instead of box-drawing characters")
		plain    = fs.Bool("plain", false, "append a frame per interval instead of redrawing in place, and write no escape sequences")
	)
	fs.Usage = func() {
		fmt.Fprint(stderr, "usage: hollow dash [flags]\n\nflags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return ExitFailure
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return ExitFailure
	}
	if *interval <= 0 {
		fmt.Fprintf(stderr, "hollow: --interval %v, want a positive duration\n", *interval)
		return ExitFailure
	}

	// Installed before the screen is taken, and released after it is given back.
	// The defers below run last in, first out, so Restore happens while the
	// handler is still installed: a second Ctrl-C arriving during shutdown would
	// otherwise take the default disposition and kill the process between the
	// last frame and the sequence that puts the terminal right.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	mode := tui.Detect(stdout, *ascii, *plain)
	w, h := tui.Size(*width, *height)
	frame := &tui.Frame{Target: *target, Charset: mode.Charset, Colour: mode.Colour}

	var screen *tui.Screen
	if mode.Fullscreen {
		screen = tui.Enter(stdout)
	}
	// Restore is safe on a nil screen, which is what plain mode holds, so the
	// deferred call needs no condition around it and cannot be reached by only
	// one of the two exits.
	defer screen.Restore()

	draw := func() {
		if mode.Fullscreen {
			frame.Paint(stdout, w, h)
			return
		}
		frame.Render(stdout, w, h)
	}

	watch(ctx, frame, *target, *interval, draw)
	return ExitOK
}

// watch keeps a dashboard attached to a server for as long as the context lives,
// reconnecting when the server goes away.
//
// Losing the server is a banner and not an exit. It will happen: somebody will
// stop the server with the dashboard still open, probably by accident, and a
// tool that quits at that moment has to be started again by hand for no reason.
// The last known state stays on screen behind the banner, because the moment the
// server stops is exactly when its final numbers are worth reading.
func watch(ctx context.Context, frame *tui.Frame, target string, interval time.Duration, draw func()) {
	backoff := minBackoff
	for ctx.Err() == nil {
		w, err := control.Dial(ctx, target, interval)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			frame.Banner = banner(target, err)
			draw()
			if !sleep(ctx, backoff) {
				return
			}
			backoff = min(backoff*2, maxBackoff)
			continue
		}

		frame.Banner = ""
		backoff = minBackoff

		// The counters start again from nothing. A server that restarted has an
		// uptime that went backwards, and a rate computed across that boundary
		// would put a spike on the sparkline describing something that never
		// happened.
		frame.Reset()

		err = stream(ctx, w, frame, interval, draw)
		w.Close()
		if ctx.Err() != nil {
			return
		}

		frame.Banner = banner(target, err)
		draw()
		if !sleep(ctx, backoff) {
			return
		}
		backoff = min(backoff*2, maxBackoff)
	}
}

// stream reads one connection until it ends, redrawing on a timer.
//
// The redraw is on its own ticker rather than one per frame received, which is
// the difference between a dashboard and a dashboard that becomes the load. A
// busy server sends an event per answered query, and repainting the screen a
// thousand times a second would spend more time drawing than the server spends
// resolving.
func stream(ctx context.Context, w *control.Watcher, frame *tui.Frame, interval time.Duration, draw func()) error {
	tick := time.NewTicker(interval)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			draw()
		case f, ok := <-w.Frames():
			if !ok {
				return w.Err()
			}
			switch f.Kind {
			case control.KindSnapshot:
				if f.Snapshot != nil {
					frame.Observe(f.Snapshot)
				}
			case control.KindEvent:
				if f.Event != nil {
					frame.Add(*f.Event)
				}
			case control.KindError:
				return errors.New(f.Error)
			}
		}
	}
}

// banner is the one line a disconnected dashboard shows.
//
// It names the address, because somebody watching two servers needs to know
// which one went, and it names the fix for the case that is not a crash but a
// server started without the flag.
func banner(target string, err error) string {
	if errors.Is(err, control.ErrNoServer) {
		return fmt.Sprintf("no server on %s: start it with --control %s, reconnecting", target, target)
	}
	if err == nil {
		return fmt.Sprintf("%s closed the connection, reconnecting", target)
	}
	return fmt.Sprintf("%s: %v, reconnecting", target, err)
}

// sleep waits, reporting false if the context ended first.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
