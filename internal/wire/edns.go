package wire

import (
	"encoding/binary"
	"fmt"
)

// DefaultUDPSize is the requestor's UDP payload size this implementation
// advertises, in octets.
//
// 1232 is the current operational recommendation: it keeps a response inside
// the smallest MTU in common use once IPv6 and UDP headers are accounted for,
// so a large answer arrives whole rather than as IP fragments that middleboxes
// and firewalls routinely drop. Measured on this network, 1232 carries the full
// 828-octet com. NS response intact, while the same query without EDNS0 comes
// back capped at 509 octets with TC set.
const DefaultUDPSize uint16 = 1232

// Option is one EDNS0 option, RFC 6891 section 6.1.2.
//
// Data aliases the message buffer it was decoded from; see Unknown.
type Option struct {
	Code uint16
	Data []byte
}

// OPT is the rdata of the EDNS0 pseudo-record, a bare sequence of options.
//
// The rest of what EDNS0 carries lives outside the rdata, in fields the
// pseudo-record repurposes: CLASS holds the requestor's payload size and TTL
// holds the extended RCODE, the version and the DO bit. EDNS presents all of it
// as one value, and is what callers should use.
type OPT struct{ Options []Option }

// EDNS is the whole OPT pseudo-record, gathering the fields RFC 6891 scatters
// across the record's CLASS and TTL.
type EDNS struct {
	// UDPSize is the largest response the sender will accept over UDP. Zero
	// packs as DefaultUDPSize, since advertising no capacity at all is never
	// what a caller means.
	UDPSize uint16

	// ExtRcode is the high 8 bits of the 12-bit extended RCODE. The low 4
	// bits stay in the message header, so the full code is
	// uint16(ExtRcode)<<4 | Rcode.
	ExtRcode uint8

	// Version is the EDNS version, 0 for RFC 6891.
	Version uint8

	// DO is the DNSSEC OK bit, RFC 3225.
	DO bool

	Options []Option
}

// ttl packs the fields EDNS0 stores in the record's TTL: extended RCODE in the
// top octet, version in the next, then the DO bit and the reserved Z bits.
func (e EDNS) ttl() uint32 {
	v := uint32(e.ExtRcode)<<24 | uint32(e.Version)<<16
	if e.DO {
		v |= 1 << 15
	}
	return v
}

func (e *EDNS) setTTL(v uint32) {
	e.ExtRcode = uint8(v >> 24)
	e.Version = uint8(v >> 16)
	e.DO = v&(1<<15) != 0
}

// RR builds the OPT pseudo-record. The owner name is the root, which is the
// only name RFC 6891 permits.
func (e EDNS) RR() RR {
	size := e.UDPSize
	if size == 0 {
		size = DefaultUDPSize
	}
	return RR{
		Name:  Root,
		Type:  TypeOPT,
		Class: Class(size),
		TTL:   int32(e.ttl()),
		Data:  OPT{Options: e.Options},
	}
}

// EDNS returns the OPT pseudo-record from the additional section, reporting
// whether one was present.
//
// RFC 6891 section 6.1.1 permits at most one, and a message carrying more is a
// format error rather than something to resolve by picking a winner.
func (m *Message) EDNS() (EDNS, bool, error) {
	var (
		found bool
		out   EDNS
	)
	for i, rr := range m.Additional {
		if rr.Type != TypeOPT {
			continue
		}
		if found {
			return EDNS{}, false, fmt.Errorf("additional %d: second OPT record: %w", i, ErrRData)
		}
		opt, ok := rr.Data.(OPT)
		if !ok {
			return EDNS{}, false, fmt.Errorf("additional %d: OPT holds %T rdata: %w", i, rr.Data, ErrRData)
		}
		if rr.Name != Root {
			return EDNS{}, false, fmt.Errorf("additional %d: OPT owned by %q, want the root: %w", i, rr.Name, ErrRData)
		}
		found = true
		out = EDNS{UDPSize: uint16(rr.Class), Options: opt.Options}
		out.setTTL(uint32(rr.TTL))
	}
	return out, found, nil
}

// SetEDNS installs the OPT pseudo-record, replacing any already present.
func (m *Message) SetEDNS(e EDNS) {
	rr := e.RR()
	for i := range m.Additional {
		if m.Additional[i].Type == TypeOPT {
			m.Additional[i] = rr
			return
		}
	}
	m.Additional = append(m.Additional, rr)
}

func decodeOPT(d *decoder) (RData, error) {
	var opts []Option
	for d.remaining() > 0 {
		code, err := d.uint16()
		if err != nil {
			return nil, fmt.Errorf("option code: %w", err)
		}
		n, err := d.uint16()
		if err != nil {
			return nil, fmt.Errorf("option %d length: %w", code, err)
		}
		b, err := d.bytes(int(n))
		if err != nil {
			return nil, fmt.Errorf("option %d claims %d octets: %w", code, n, err)
		}
		opts = append(opts, Option{Code: code, Data: b})
	}
	return OPT{Options: opts}, nil
}

func (OPT) Type() Type { return TypeOPT }

func (o OPT) pack(e *encoder) error {
	for _, opt := range o.Options {
		if len(opt.Data) > 0xFFFF {
			return fmt.Errorf("option %d is %d octets: %w", opt.Code, len(opt.Data), ErrRData)
		}
		e.buf = binary.BigEndian.AppendUint16(e.buf, opt.Code)
		e.buf = binary.BigEndian.AppendUint16(e.buf, uint16(len(opt.Data)))
		e.buf = append(e.buf, opt.Data...)
	}
	return nil
}
