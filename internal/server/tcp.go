package server

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// serveTCP accepts connections and runs one goroutine per connection.
//
// A goroutine each is affordable here in a way it is not on UDP, because a
// connection is something the client had to establish and something we can
// count, time out and close. The cap is what keeps that true.
func (s *Server) serveTCP(ctx context.Context, ln net.Listener) error {
	// A slot per permitted connection. Taken on accept, returned when the
	// handler goroutine ends.
	slots := make(chan struct{}, s.maxConns())

	var conns connSet
	var wg sync.WaitGroup

	// Connections parked in a read do not notice a cancelled context, and the
	// listener closing does nothing to sockets already accepted. Closing them
	// is what ends their reads.
	go func() {
		<-ctx.Done()
		conns.closeAll()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				break
			}
			wg.Wait()
			return fmt.Errorf("server: accepting tcp: %w", err)
		}

		select {
		case slots <- struct{}{}:
		default:
			// Over the cap. Closed at once rather than held open unserved, so
			// the client sees the connection go and retries, instead of waiting
			// out its own timeout against a server that was never going to
			// answer.
			conn.Close()
			s.log().Warn("tcp connection refused, at the cap",
				"from", conn.RemoteAddr().String(), "max", s.maxConns())
			continue
		}

		if !conns.add(conn) {
			// Shutdown began between the accept and here.
			conn.Close()
			<-slots
			continue
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			defer conns.remove(conn)
			s.handleConn(ctx, conn)
		}()
	}

	wg.Wait()
	return nil
}

// handleConn answers queries on one connection until it goes idle, errors, or
// the server shuts down.
func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	for {
		// RFC 7766 expects a connection to carry more than one query, so the
		// wait between them is an idle timeout rather than a read timeout: a
		// client holding a connection open for its next lookup is behaving
		// correctly and should not be cut off at the same deadline that bounds
		// a message arriving in pieces.
		conn.SetReadDeadline(time.Now().Add(s.idleTimeout()))
		var prefix [2]byte
		if _, err := io.ReadFull(conn, prefix[:]); err != nil {
			// io.EOF is the client hanging up, which is how most connections
			// end and is not worth a line in the log.
			if !errors.Is(err, io.EOF) && ctx.Err() == nil {
				s.log().Debug("reading a tcp length prefix",
					"from", conn.RemoteAddr().String(), "err", err)
			}
			return
		}

		// Once the length is known the rest is committed and the tighter
		// deadline applies. A client that sends a prefix and then stalls is
		// holding a connection against the cap, which is the cheapest denial of
		// service there is on a stream protocol.
		conn.SetReadDeadline(time.Now().Add(s.timeout()))
		body := make([]byte, binary.BigEndian.Uint16(prefix[:]))
		if _, err := io.ReadFull(conn, body); err != nil {
			if ctx.Err() == nil {
				s.log().Debug("reading a tcp message",
					"from", conn.RemoteAddr().String(), "want", len(body), "err", err)
			}
			return
		}

		reply := s.answerTCP(ctx, body)
		if reply == nil {
			// Nothing to say to this one. The connection stays open, since the
			// next query on it may be perfectly good.
			continue
		}

		conn.SetWriteDeadline(time.Now().Add(s.timeout()))
		if _, err := conn.Write(reply); err != nil {
			s.log().Debug("writing a tcp reply",
				"to", conn.RemoteAddr().String(), "err", err)
			return
		}
	}
}

func (s *Server) answerTCP(ctx context.Context, body []byte) []byte {
	qctx, cancel := s.queryContext(ctx)
	defer cancel()

	reply := s.answer(qctx, body, true)
	if reply == nil {
		return nil
	}

	// The two-octet length goes out in the same write as the message it
	// describes. Two writes would be legal and would also let a reader that
	// assumes one segment per message fail in a way that looks like our bug.
	framed := make([]byte, 2+len(reply))
	binary.BigEndian.PutUint16(framed, uint16(len(reply)))
	copy(framed[2:], reply)
	return framed
}

// connSet tracks live connections so shutdown can close them.
//
// It exists because there is no other way to wake a goroutine parked in a read.
// A deadline would work only if one were always pending, and an idle connection
// has nothing to time out against.
type connSet struct {
	mu     sync.Mutex
	closed bool
	conns  map[net.Conn]struct{}
}

// add registers conn, reporting false if the set is already closed, in which
// case the caller owns closing it.
func (c *connSet) add(conn net.Conn) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	if c.conns == nil {
		c.conns = make(map[net.Conn]struct{})
	}
	c.conns[conn] = struct{}{}
	return true
}

func (c *connSet) remove(conn net.Conn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.conns, conn)
}

// closeAll closes every live connection and refuses later additions.
func (c *connSet) closeAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	for conn := range c.conns {
		conn.Close()
	}
	clear(c.conns)
}
