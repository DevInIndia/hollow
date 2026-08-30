package control

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"time"
)

// dialTimeout bounds the connect. Loopback either answers at once or is not
// there, so a long wait here only delays the message that says so.
const dialTimeout = 3 * time.Second

// ErrNoServer reports that nothing is listening on the control address.
//
// A distinct error because it is the one every user will hit first, and because
// "connection refused" on its own does not tell them that the server they are
// running needs a flag it did not need yesterday. The message is written where
// the user sees it, not here, since only the caller knows which verb they typed.
var ErrNoServer = errors.New("control: nothing is listening")

// Fetch asks for one snapshot and returns it.
func Fetch(ctx context.Context, addr string) (*Snapshot, error) {
	conn, err := dial(ctx, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	if err := writeFrame(conn, Request{Command: CommandSnapshot}); err != nil {
		return nil, err
	}
	var f Frame
	if err := readFrame(conn, &f); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("control: the server closed without answering")
		}
		return nil, err
	}
	switch f.Kind {
	case KindSnapshot:
		if f.Snapshot == nil {
			return nil, errors.New("control: the server sent a snapshot frame with no snapshot")
		}
		return f.Snapshot, nil
	case KindError:
		return nil, fmt.Errorf("control: the server refused: %s", f.Error)
	}
	return nil, fmt.Errorf("control: unexpected frame %q", f.Kind)
}

// Watcher is an open stream of frames from a server.
//
// Frames arrive on a channel, which is closed when the stream ends for any
// reason; the error is available from Err afterwards. A channel rather than a
// callback because the caller is a redraw loop that already has a select in it,
// and a callback would run the rendering on this package's goroutine.
type Watcher struct {
	frames chan Frame
	err    error
	conn   net.Conn
}

// Dial opens a watch on addr. The caller reads Frames until it closes, then
// checks Err.
func Dial(ctx context.Context, addr string, interval time.Duration) (*Watcher, error) {
	conn, err := dial(ctx, addr)
	if err != nil {
		return nil, err
	}
	if err := writeFrame(conn, Request{Command: CommandWatch, IntervalMS: int(interval.Milliseconds())}); err != nil {
		conn.Close()
		return nil, err
	}

	w := &Watcher{frames: make(chan Frame, 64), conn: conn}
	go w.read(ctx)
	return w, nil
}

// Frames is the stream. It is closed when the watch ends, for any reason.
func (w *Watcher) Frames() <-chan Frame { return w.frames }

// Err reports why the stream ended. It is valid only after Frames is closed, and
// is nil when the caller's context ended it.
func (w *Watcher) Err() error { return w.err }

// Close ends the watch. Safe to call after the stream has already ended.
func (w *Watcher) Close() error { return w.conn.Close() }

func (w *Watcher) read(ctx context.Context) {
	defer close(w.frames)

	// Closing the connection is what unblocks the read below. A context check
	// between frames would not, because between frames is exactly where this
	// goroutine parks for as long as the server stays quiet.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			w.conn.Close()
		case <-done:
		}
	}()

	for {
		var f Frame
		if err := readFrame(w.conn, &f); err != nil {
			if ctx.Err() == nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				w.err = err
			}
			return
		}
		select {
		case w.frames <- f:
		case <-ctx.Done():
			return
		}
	}
}

// dial connects, translating a refusal into ErrNoServer.
func dial(ctx context.Context, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		// syscall.ECONNREFUSED rather than matching on the message, which is
		// worded differently on Windows and translated on a localised system.
		if errors.Is(err, syscall.ECONNREFUSED) {
			return nil, fmt.Errorf("%w on %s", ErrNoServer, addr)
		}
		return nil, fmt.Errorf("control: connecting to %s: %w", addr, err)
	}
	return conn, nil
}
