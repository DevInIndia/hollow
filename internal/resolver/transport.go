// Package resolver turns a question into an answer by asking DNS servers.
//
// Transport is the single-exchange layer: one query to one server, over UDP
// with a fallback to TCP when the reply arrives truncated. Deciding which
// server to ask, and what to do with a referral instead of an answer, belongs
// to the iterative loop above it.
package resolver

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/DevInIndia/hollow/internal/wire"
)

// Failures an exchange reports in its own right. Anything malformed on the wire
// surfaces as one of the internal/wire errors instead, wrapped, so a caller can
// tell a server that did not answer from one that answered badly.
var (
	// ErrNoReply means the deadline passed with nothing usable from the server.
	// A packet may well have arrived; it did not match the query.
	ErrNoReply = errors.New("resolver: no usable reply before the deadline")

	// ErrOversized means the server ignored the payload size we advertised.
	// The reply is discarded rather than parsed, because the operating system
	// has already cut the tail off it.
	ErrOversized = errors.New("resolver: reply exceeds the advertised UDP payload size")
)

// DefaultTimeout bounds one exchange with one server, the UDP attempt and any
// TCP retry together.
const DefaultTimeout = 3 * time.Second

// Transport exchanges a single query with a single server. The zero value is
// usable and asks over UDP with recursion cleared, which is what the iterative
// loop wants; a Transport aimed at someone else's recursive server sets
// RecursionDesired.
//
// A Transport holds no per-exchange state and is safe for concurrent use.
type Transport struct {
	// Timeout bounds one call to Exchange. Zero means DefaultTimeout. The TCP
	// retry after a truncated reply gets whatever is left of it rather than a
	// fresh allowance, so a caller's deadline means what it says.
	Timeout time.Duration

	// UDPSize is the EDNS0 payload size advertised to the server, and so also
	// the largest reply that will be accepted over UDP. Zero, or anything below
	// the 512 every implementation must handle, means wire.DefaultUDPSize.
	UDPSize uint16

	// RecursionDesired sets the RD bit. An authoritative server ignores it; a
	// recursive one will not answer a question outside its zones without it.
	RecursionDesired bool

	// ForceTCP skips the UDP attempt. TCP is otherwise reached only by falling
	// back from a truncated reply.
	ForceTCP bool

	// Case, when set, randomises the case of each outgoing UDP query name and
	// refuses a reply that does not echo it exactly, which is the DNS 0x20
	// defence. Nil disables it and is the zero value, so a Transport built for
	// one exchange is unchanged.
	//
	// It is a pointer because it is state that has to outlive one exchange: a
	// server found not to preserve case is remembered, and every copy of this
	// Transport shares that knowledge.
	Case *Casing

	// KeepWire copies the octets of each reply into Reply.Wire, for a caller
	// that wants to show the message as it arrived rather than as it decoded.
	//
	// Off by default because the server would otherwise hold a copy of every
	// reply it ever received for as long as anything referenced it, which is a
	// per-query allocation and a retention bug in one field. The inspect verb
	// sets it; nothing on the serving path does.
	KeepWire bool
}

// Reply is a server's answer together with how it was obtained. The CLI reports
// all of it, and which protocol carried the answer is not cosmetic: a query
// that fell back to TCP behaved differently from one that did not.
type Reply struct {
	Msg *wire.Message

	// Server is the address that answered.
	Server netip.AddrPort

	// Protocol is "udp" or "tcp", as passed to net.Dial, or ProtocolCache for a
	// reply that came from the cache and was never on a wire. Server, Size and
	// RTT are all zero in that case, because none of them happened.
	Protocol string

	// Size is the length in octets of the message as it arrived, excluding the
	// two-octet length prefix on TCP.
	Size int

	// RTT spans the whole exchange, so a reply that fell back to TCP includes
	// the UDP attempt that provoked it.
	RTT time.Duration

	// Wire is the message exactly as it arrived, and is set only when the
	// transport was asked to keep it. It is a copy rather than a slice of the
	// read buffer, since that buffer is reused for the next datagram.
	Wire []byte

	// Sent is the name as it went out, which is the question with its case
	// randomised when the 0x20 defence is on. It is here so that a trace can
	// show the nonce that was actually used rather than assert that one was.
	Sent wire.Name
}

// Exchange asks server one question and returns its reply.
//
// The reply is checked against the query before it is returned: the transaction
// ID must match, the QR bit must be set, and the question section must echo the
// one that was sent. A UDP socket is connected to the server, so the kernel has
// already discarded anything arriving from another address, but a connected
// socket says nothing about a source-spoofing attacker and these checks do.
//
// A truncated reply is discarded and the identical query is asked again over
// TCP, per RFC 1035 section 4.2.1. Nothing in the truncated message is used,
// not even the records that arrived intact.
func (t *Transport) Exchange(ctx context.Context, server netip.AddrPort, q wire.Question) (*Reply, error) {
	if !server.IsValid() {
		return nil, fmt.Errorf("resolver: %v is not a usable server address", server)
	}

	// The parent is kept because one path needs a deadline of its own: a server
	// that turns out not to preserve case has already had this exchange's whole
	// allowance spent waiting for a reply that never came, and the retry cannot
	// run on what is left of it. That costs up to two timeouts, once per server,
	// and every exchange after it is back to one.
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, t.timeout())
	defer cancel()

	start := time.Now()

	if !t.ForceTCP {
		// The case pattern is a nonce, so it is chosen per query and never
		// reused, and only over UDP: a TCP query is not open to an off-path
		// forgery, since answering one means completing a handshake with our
		// address. c-ares makes the same call for the same reason.
		sent := q
		if t.Case.use(server) {
			sent.Name = randomCase(q.Name)
		}

		query, id, err := t.query(sent)
		if err != nil {
			return nil, err
		}

		msg, raw, err := t.overUDP(ctx, server, query, id, sent)
		switch {
		case errors.Is(err, errCaseMismatch):
			// Nothing usable arrived before the deadline and the only thing
			// wrong with what did arrive was the case. That is a server which
			// does not preserve it, so it is recorded and asked again plainly.
			//
			// Waiting for the deadline first is what keeps this from being a
			// way to switch the defence off: a forged reply with the wrong case
			// is discarded and the read continues, so an attacker has to also
			// stop the real answer from arriving before this path is reached at
			// all.
			t.Case.nonconforming(server)
			if parent.Err() != nil {
				return nil, err
			}
			return t.plainExchange(parent, server, q, start)
		case err != nil:
			return nil, err
		}
		if !msg.Header.Truncated {
			restoreCase(msg, sent.Name, q.Name)
			return t.reply(msg, raw, server, "udp", start, sent.Name), nil
		}
	}

	query, id, err := t.query(q)
	if err != nil {
		return nil, err
	}
	msg, raw, err := t.overTCP(ctx, server, query, id, q)
	if err != nil {
		return nil, err
	}
	return t.reply(msg, raw, server, "tcp", start, q.Name), nil
}

// plainExchange asks again without randomised case, for a server that has just
// been found not to echo it. One retry, and only over UDP, since the caller
// falls through to TCP on its own if this reply is truncated.
func (t *Transport) plainExchange(ctx context.Context, server netip.AddrPort, q wire.Question, start time.Time) (*Reply, error) {
	ctx, cancel := context.WithTimeout(ctx, t.timeout())
	defer cancel()

	query, id, err := t.query(q)
	if err != nil {
		return nil, err
	}
	msg, raw, err := t.overUDP(ctx, server, query, id, q)
	if err != nil {
		return nil, err
	}
	if !msg.Header.Truncated {
		return t.reply(msg, raw, server, "udp", start, q.Name), nil
	}
	msg, raw, err = t.overTCP(ctx, server, query, id, q)
	if err != nil {
		return nil, err
	}
	return t.reply(msg, raw, server, "tcp", start, q.Name), nil
}

// reply assembles what came back, keeping a copy of the octets only when the
// caller asked for them. The copy matters: raw aliases the read buffer, which
// the next datagram overwrites.
func (t *Transport) reply(msg *wire.Message, raw []byte, server netip.AddrPort, proto string, start time.Time, sent wire.Name) *Reply {
	r := &Reply{Msg: msg, Server: server, Protocol: proto, Size: len(raw), RTT: time.Since(start), Sent: sent}
	if t.KeepWire {
		r.Wire = append([]byte(nil), raw...)
	}
	return r
}

// query builds the packed query and returns the transaction ID the reply must
// carry.
func (t *Transport) query(q wire.Question) ([]byte, uint16, error) {
	// crypto/rand, not math/rand: the ID is the only thing besides the source
	// port standing between an off-path attacker and a forged answer, and a
	// predictable sequence gives both away. Read cannot fail as of Go 1.24; it
	// panics rather than returning short.
	var seed [2]byte
	rand.Read(seed[:])

	m := &wire.Message{
		Header: wire.Header{
			ID:               binary.BigEndian.Uint16(seed[:]),
			RecursionDesired: t.RecursionDesired,
		},
		Questions: []wire.Question{q},
	}
	m.SetEDNS(wire.EDNS{UDPSize: t.udpSize()})

	buf, err := m.Pack()
	if err != nil {
		return nil, 0, fmt.Errorf("resolver: encoding the query: %w", err)
	}
	return buf, m.Header.ID, nil
}

func (t *Transport) overUDP(ctx context.Context, server netip.AddrPort, query []byte, id uint16, q wire.Question) (*wire.Message, []byte, error) {
	// Dial rather than ListenPacket: a connected UDP socket makes the kernel
	// drop datagrams from any other address and port, which is a filter no
	// amount of checking in this process can match for cost. The source port is
	// left to the operating system, which randomises it on all three target
	// platforms per RFC 6056. Randomising it here with crypto/rand instead was
	// considered and rejected: binding a chosen port means competing with every
	// other socket on the machine and retrying on collision, for no gain over
	// what the kernel already does.
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", server.String())
	if err != nil {
		return nil, nil, fmt.Errorf("resolver: dialing %v over udp: %w", server, err)
	}
	defer conn.Close()
	stop := watch(ctx, conn)
	defer stop()

	if _, err := conn.Write(query); err != nil {
		return nil, nil, fmt.Errorf("resolver: sending to %v over udp: %w", server, err)
	}

	// One octet past what was advertised. A datagram longer than the buffer
	// loses its tail in the kernel with nothing to report it, and the fragment
	// that survives would decode as some other kind of malformed message; the
	// extra octet turns that silence into a length we can test.
	size := int(t.udpSize())
	buf := make([]byte, size+1)

	// The first reply that arrived but could not be used. Reading continues
	// after one, because a mismatch is what an injected packet looks like and
	// abandoning the exchange is what its sender wants. Keeping the reason
	// means a genuinely broken server still gets reported as one.
	var unusable error

	for {
		n, err := conn.Read(buf)
		if err != nil {
			if unusable != nil {
				return nil, nil, fmt.Errorf("resolver: %v over udp: %w", server, unusable)
			}
			return nil, nil, failure(ctx, err, server, "udp", "reading the reply")
		}
		if n > size {
			return nil, nil, fmt.Errorf("resolver: %v replied with more than the %d octets advertised: %w", server, size, ErrOversized)
		}
		msg, err := accept(buf[:n], id, q)
		if err != nil {
			if unusable == nil {
				unusable = err
			}
			continue
		}
		return msg, buf[:n], nil
	}
}

func (t *Transport) overTCP(ctx context.Context, server netip.AddrPort, query []byte, id uint16, q wire.Question) (*wire.Message, []byte, error) {
	if len(query) > 65535 {
		return nil, nil, fmt.Errorf("resolver: query of %d octets does not fit the TCP length prefix", len(query))
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", server.String())
	if err != nil {
		return nil, nil, fmt.Errorf("resolver: dialing %v over tcp: %w", server, err)
	}
	defer conn.Close()
	stop := watch(ctx, conn)
	defer stop()

	// RFC 1035 section 4.2.2: two octets of big-endian length before the
	// message, in both directions. Written as one buffer so the prefix and the
	// message cannot reach the network in separate segments, which is legal but
	// makes a server that reads sloppily look like our bug.
	framed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(framed, uint16(len(query)))
	copy(framed[2:], query)
	if _, err := conn.Write(framed); err != nil {
		return nil, nil, fmt.Errorf("resolver: sending to %v over tcp: %w", server, err)
	}

	var prefix [2]byte
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		return nil, nil, failure(ctx, err, server, "tcp", "reading the length prefix")
	}

	// A zero length needs no special case: an empty message fails to decode as
	// a truncated one, which is what it is.
	body := make([]byte, binary.BigEndian.Uint16(prefix[:]))
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, nil, failure(ctx, err, server, "tcp", fmt.Sprintf("reading the %d octets promised", len(body)))
	}

	// No retry loop here. On UDP anyone can send us a datagram, so a mismatch
	// is discarded and the read continues; on a stream we opened ourselves a
	// mismatch means the server is wrong, and there is no second reply coming.
	msg, err := accept(body, id, q)
	if err != nil {
		return nil, nil, fmt.Errorf("resolver: %v over tcp: %w", server, err)
	}
	return msg, body, nil
}

// accept decodes a reply and reports why it cannot answer the query that was
// sent, or nil if it can.
func accept(datagram []byte, id uint16, q wire.Question) (*wire.Message, error) {
	m, err := wire.Unpack(datagram)
	if err != nil {
		return nil, fmt.Errorf("decoding the reply: %w", err)
	}
	if m.Header.ID != id {
		return nil, fmt.Errorf("reply carries transaction id %#04x, not %#04x", m.Header.ID, id)
	}
	if !m.Header.Response {
		return nil, errors.New("reply has the query bit clear")
	}
	if m.Header.Opcode != 0 {
		return nil, fmt.Errorf("reply carries opcode %d, not a standard query", m.Header.Opcode)
	}
	if len(m.Questions) != 1 {
		return nil, fmt.Errorf("reply echoes %d questions, not one", len(m.Questions))
	}
	// Case-insensitively, per RFC 4343. A server is free to answer "EXAMPLE.com"
	// when asked about "example.com", and several do.
	if got := m.Questions[0]; !got.Name.EqualFold(q.Name) || got.Type != q.Type || got.Class != q.Class {
		return nil, fmt.Errorf("reply echoes the question %s %s class %d, not %s %s class %d",
			got.Name, got.Type, got.Class, q.Name, q.Type, q.Class)
	}

	// With 0x20 the case is a nonce, and a reply that matches everything but the
	// case is either a server that lowercased the question or an attacker who
	// guessed the id and the port but could not see the case. Neither is an
	// answer, and the two are told apart by the caller, not here.
	if q.Name != m.Questions[0].Name && hasCase(q.Name) {
		return nil, fmt.Errorf("reply echoes %s, not the case that was sent, %s: %w",
			m.Questions[0].Name, q.Name, errCaseMismatch)
	}
	return m, nil
}

// errCaseMismatch marks the one failure that has a fallback: everything about
// the reply matched except the case of the name.
var errCaseMismatch = errors.New("question echoed with the case changed")

// hasCase reports whether a name has a letter in it, and so whether the 0x20
// comparison means anything for it. A name of digits and hyphens carries no
// nonce, and refusing a reply over its case would be refusing over nothing.
func hasCase(n wire.Name) bool {
	for i := range len(n) {
		if isASCIILetter(n[i]) {
			return true
		}
	}
	return false
}

// failure names why a socket stopped, distinguishing a caller who cancelled
// from one who simply waited long enough.
//
// The socket's own error decides that the time ran out, not ctx.Err(). The
// context's timer and the deadline derived from it fire at the same instant and
// race, so a read can come back timed out a moment before the context admits to
// being done, and which one wins must not change the error a caller sees.
// Cancellation has no such race: cancel sets ctx.Err() before waking anything.
func failure(ctx context.Context, err error, server netip.AddrPort, proto, doing string) error {
	cause := err
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		cause = ctx.Err()
	case errors.Is(err, os.ErrDeadlineExceeded):
		cause = ErrNoReply
	}
	return fmt.Errorf("resolver: %s from %v over %s: %w", doing, server, proto, cause)
}

// watch unblocks conn when ctx is done, and returns a function that stops
// watching. A socket deadline alone would not do: the context can be cancelled
// before it expires, and a read already parked in the kernel has no other way
// to hear about it. Pushing the deadline into the past rather than closing the
// connection means the read returns a timeout instead of racing a Close, and
// the deferred Close still runs.
func watch(ctx context.Context, conn net.Conn) (stop func()) {
	// Set unconditionally as well, so a timeout does not depend on a goroutine
	// being scheduled promptly. Exchange always installs one.
	if d, ok := ctx.Deadline(); ok {
		conn.SetDeadline(d)
	}

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			conn.SetDeadline(time.Now())
		case <-done:
		}
	}()
	return func() { close(done) }
}

func (t *Transport) timeout() time.Duration {
	if t.Timeout <= 0 {
		return DefaultTimeout
	}
	return t.Timeout
}

func (t *Transport) udpSize() uint16 {
	// Below 512 the advertisement is not a smaller buffer, it is a claim to
	// handle less than the protocol's floor, which no server is obliged to
	// honour and which would make us discard replies we asked for.
	if t.UDPSize < 512 {
		return wire.DefaultUDPSize
	}
	return t.UDPSize
}
