package server

import (
	"context"
	"errors"
	"fmt"
	"net"
)

// packet is one datagram on its way from the reader to a worker. buf is owned by
// whoever holds the packet and goes back to the pool when they are done with it.
type packet struct {
	buf  *[]byte
	n    int
	from net.Addr
}

// serveUDP reads datagrams and hands them to the worker pool.
//
// One goroutine does all the reading. That is not a simplification: a datagram
// socket has a single receive queue, and a second reader would only race the
// first for it while doubling the chance of a packet sitting behind a slow
// resolution. The work that takes time is behind the channel, where it is
// bounded.
func (s *Server) serveUDP(ctx context.Context, pc net.PacketConn, queue chan<- packet) error {
	for {
		buf := s.buffer()
		n, from, err := pc.ReadFrom(*buf)
		if err != nil {
			s.release(buf)
			// Shutdown closes the listener under us, which is how this loop is
			// meant to end. Anything else means the socket is gone for a reason
			// we did not choose, and continuing would serve TCP only.
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("server: reading udp: %w", err)
		}

		select {
		case queue <- packet{buf: buf, n: n, from: from}:
		default:
			// Dropped, not queued and not answered. UDP permits this: the
			// protocol has no delivery guarantee and a client that gets no
			// reply retries. The alternative is to block the reader, which
			// stops draining the kernel's receive queue and turns a burst into
			// a stall for every client rather than a retry for one.
			s.release(buf)
			s.dropped.Add(1)
			if s.warnedDrop.CompareAndSwap(false, true) {
				s.log().Warn("udp queue full, dropping packets", "queue", cap(queue))
			}
		}
	}
}

// udpWorker answers queued packets until the queue is closed.
func (s *Server) udpWorker(ctx context.Context, pc net.PacketConn, queue <-chan packet) {
	for p := range queue {
		// Shutdown has started. What is left in the queue has been waiting and
		// its clients have most likely given up, so it is discarded rather than
		// answered. Draining rather than returning matters: the reader may
		// still be putting packets in, and a worker that returned early would
		// leave it to fill the queue against nobody.
		if ctx.Err() != nil {
			s.release(p.buf)
			continue
		}
		s.answerUDP(ctx, pc, p)
		s.release(p.buf)
	}
}

func (s *Server) answerUDP(ctx context.Context, pc net.PacketConn, p packet) {
	qctx, cancel := s.queryContext(ctx)
	defer cancel()

	reply := s.answer(qctx, (*p.buf)[:p.n], clientAddr(p.from), false)
	if reply == nil {
		return
	}

	// No write deadline. The deadline on a PacketConn is a property of the
	// socket, not of one call, so setting it here would have every worker
	// overwriting every other worker's. It buys nothing anyway: a UDP write
	// copies into the socket buffer and returns, and when that buffer is full
	// the kernel discards rather than blocking.
	if _, err := pc.WriteTo(reply, p.from); err != nil {
		s.log().Debug("writing a udp reply", "to", p.from.String(), "err", err)
	}
}

// buffer takes a read buffer from the pool, or makes one.
//
// Written this way rather than with sync.Pool's New field so that the zero
// Server works: a pool with no New returns nil, and the check is cheaper than
// requiring a constructor.
func (s *Server) buffer() *[]byte {
	if v := s.pool.Get(); v != nil {
		return v.(*[]byte)
	}
	b := make([]byte, readBuffer)
	return &b
}

// release returns a buffer to the pool. A pointer goes back rather than the
// slice itself, because putting a slice in an interface allocates and the whole
// point of the pool is not to.
func (s *Server) release(b *[]byte) { s.pool.Put(b) }
