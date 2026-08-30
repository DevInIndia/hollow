package blocklist

import (
	"fmt"
	"net/netip"

	"github.com/DevInIndia/hollow/internal/wire"
)

// Mode is what a blocked query is answered with.
type Mode int

const (
	// ModeNXDomain says the name does not exist. It is the default because it
	// is the only answer that is true in the same way for every query type, and
	// because a client that hears it stops asking.
	ModeNXDomain Mode = iota

	// ModeNull says the name exists and resolves to an unroutable address.
	// Slower to fail than NXDOMAIN, since the client will usually try to
	// connect and wait for the timeout, but some applications handle a dead
	// address better than a missing name.
	ModeNull

	// ModeNoData says the name exists and has no records of the type asked for.
	ModeNoData
)

// blockTTL is the TTL on every synthesised record and on the SOA that carries
// the negative answer.
//
// Sixty seconds: short enough that removing a name from a list takes effect
// while the operator is still looking at the terminal, long enough that a
// client does not re-ask on every page load. Zero would be the other option and
// is worse, because a client with a zero TTL asks again for every connection to
// the same host.
const blockTTL = 60

func (m Mode) String() string {
	switch m {
	case ModeNXDomain:
		return "nxdomain"
	case ModeNull:
		return "null"
	case ModeNoData:
		return "nodata"
	}
	return fmt.Sprintf("Mode(%d)", int(m))
}

// ParseMode reads the --block-mode flag value.
func ParseMode(s string) (Mode, error) {
	switch s {
	case "nxdomain":
		return ModeNXDomain, nil
	case "null":
		return ModeNull, nil
	case "nodata":
		return ModeNoData, nil
	}
	return 0, fmt.Errorf("block mode %q: want nxdomain, null or nodata", s)
}

var (
	nullV4 = netip.AddrFrom4([4]byte{})
	nullV6 = netip.AddrFrom16([16]byte{})
)

// Reply builds the answer to a blocked query.
//
// The modes are internally consistent, which is the requirement that shapes the
// whole function. A name either exists or it does not, and the answer has to
// say the same thing whatever type is asked for. Returning 0.0.0.0 for A and
// NXDOMAIN for AAAA is the obvious implementation of "null" and it is wrong:
// the A answer asserts the name exists, the AAAA answer asserts it does not,
// and a dual-stack client that asks both, as every browser does, gets two
// contradictory statements about the same name. What it does next is anyone's
// guess, and the bug reads as intermittent.
//
// So under ModeNull the types with an unroutable address get one, and every
// other type gets NODATA, which is the same claim: the name exists, this record
// is not there. NXDOMAIN never appears under ModeNull at all.
func Reply(query *wire.Message, mode Mode) *wire.Message {
	out := &wire.Message{
		Header: wire.Header{
			ID:                 query.Header.ID,
			Response:           true,
			Opcode:             query.Header.Opcode,
			RecursionDesired:   query.Header.RecursionDesired,
			RecursionAvailable: true,

			// Authoritative, because for this answer we are. The record was not
			// obtained from anywhere and repeated; it was made here, and this
			// server is the only thing in the world that holds it. Saying
			// otherwise would be claiming to have heard it from a server that
			// does not exist.
			Authoritative: true,
		},
		Questions: query.Questions,
	}
	out.SetEDNS(wire.EDNS{UDPSize: wire.DefaultUDPSize})

	if len(query.Questions) == 0 {
		// Nothing to answer about. A query with no question does not reach here
		// from the server, which rejects it earlier, but Reply is exported and
		// a caller that does this should not get a message asserting something
		// about a name it never named.
		out.Header.Rcode = wire.RcodeNXDomain
		return out
	}
	q := query.Questions[0]

	if mode == ModeNull {
		switch q.Type {
		case wire.TypeA:
			out.Answers = []wire.RR{answer(q, wire.A{Addr: nullV4})}
			return out
		case wire.TypeAAAA:
			out.Answers = []wire.RR{answer(q, wire.AAAA{Addr: nullV6})}
			return out
		}
	}

	if mode == ModeNXDomain {
		out.Header.Rcode = wire.RcodeNXDomain
	}

	// Both negative shapes carry an SOA in the authority section. Without it a
	// resolver downstream of this one has no TTL to cache the negative answer
	// against, RFC 2308 section 5, and will ask again for every query. The
	// blocklist would still work and would do several times the work.
	out.Authority = []wire.RR{soa(q.Name, q.Class)}
	return out
}

func answer(q wire.Question, data wire.RData) wire.RR {
	return wire.RR{Name: q.Name, Type: q.Type, Class: q.Class, TTL: blockTTL, Data: data}
}

// soa builds the record that carries the negative answer's TTL.
//
// The owner is the query name rather than the zone the name really sits in,
// because finding that zone means a resolution, and resolving the name we are
// refusing to resolve defeats the feature. The names inside point at .invalid,
// reserved by RFC 2606 precisely so that a name that must never resolve can be
// written down, which is exactly what a synthetic record needs.
func soa(name wire.Name, class wire.Class) wire.RR {
	return wire.RR{
		Name:  name,
		Type:  wire.TypeSOA,
		Class: class,
		TTL:   blockTTL,
		Data: wire.SOA{
			Primary: "hollow.invalid.",
			Mailbox: "hostmaster.hollow.invalid.",
			Serial:  1,
			Refresh: 3600,
			Retry:   600,
			Expire:  86400,
			Minimum: blockTTL,
		},
	}
}
