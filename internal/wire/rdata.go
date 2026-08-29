package wire

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// RData is the parsed contents of a resource record's RDATA field. Every RR
// carries one. A type this package does not model decodes as Unknown, which
// keeps the octets verbatim so that an unfamiliar record still round-trips.
//
// pack is unexported, so the set of implementations is closed to this package.
// Encoding a record means knowing whether the names inside it may be replaced
// by a compression pointer, and that is a property of the record type rather
// than something a caller should be able to supply.
type RData interface {
	// Type reports the record type whose RDATA this is.
	Type() Type

	pack(e *encoder) error
}

// A is an IPv4 host address, RFC 1035 section 3.4.1.
type A struct{ Addr netip.Addr }

// AAAA is an IPv6 host address, RFC 3596.
type AAAA struct{ Addr netip.Addr }

// NS is an authoritative nameserver for a zone, RFC 1035 section 3.3.11.
type NS struct{ Host Name }

// CNAME is the canonical name of an alias, RFC 1035 section 3.3.1.
type CNAME struct{ Target Name }

// PTR is a pointer to another name, RFC 1035 section 3.3.12. Unlike CNAME it
// triggers no further processing at the resolver.
type PTR struct{ Target Name }

// MX is a mail exchange, RFC 1035 section 3.3.9.
type MX struct {
	Preference uint16
	Exchange   Name
}

// TXT is one or more character-strings, RFC 1035 section 3.3.14.
//
// The strings stay separate. One TXT record can carry several, each capped at
// 255 octets, and joining them destroys a boundary that SPF and DKIM both
// depend on.
type TXT struct{ Strings []string }

// SOA marks the start of a zone of authority, RFC 1035 section 3.3.13.
type SOA struct {
	Primary Name // MNAME, the authoritative server for the zone
	Mailbox Name // RNAME, the maintainer's mailbox with '.' standing in for '@'
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	Minimum uint32 // also the negative caching TTL, RFC 2308 section 4
}

// SRV locates the host serving a protocol, RFC 2782.
type SRV struct {
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   Name
}

// Unknown is the rdata of a type this package does not model, held verbatim
// because a resolver that rejects an unfamiliar record is broken.
//
// Data aliases the message buffer it was decoded from, so a caller that keeps
// the record beyond the life of that buffer must copy it first. Every other
// RData implementation owns its contents, apart from Option.Data.
type Unknown struct {
	Kind Type
	Data []byte
}

func (A) Type() Type         { return TypeA }
func (AAAA) Type() Type      { return TypeAAAA }
func (NS) Type() Type        { return TypeNS }
func (CNAME) Type() Type     { return TypeCNAME }
func (PTR) Type() Type       { return TypePTR }
func (MX) Type() Type        { return TypeMX }
func (TXT) Type() Type       { return TypeTXT }
func (SOA) Type() Type       { return TypeSOA }
func (SRV) Type() Type       { return TypeSRV }
func (u Unknown) Type() Type { return u.Kind }

// decodeRData parses the rdata of one record.
//
// d is bounded at the RDLENGTH boundary rather than at the end of the message,
// so a field that reads past its own end fails as a truncation instead of
// silently consuming the record that follows. Compression pointers still
// resolve, because they only ever target an offset behind the field.
func decodeRData(d *decoder, typ Type) (RData, error) {
	switch typ {
	case TypeA:
		b, err := d.address(4)
		if err != nil {
			return nil, err
		}
		return A{Addr: netip.AddrFrom4([4]byte(b))}, nil

	case TypeAAAA:
		b, err := d.address(16)
		if err != nil {
			return nil, err
		}
		return AAAA{Addr: netip.AddrFrom16([16]byte(b))}, nil

	case TypeNS:
		n, err := d.name()
		if err != nil {
			return nil, fmt.Errorf("NS host: %w", err)
		}
		return NS{Host: n}, nil

	case TypeCNAME:
		n, err := d.name()
		if err != nil {
			return nil, fmt.Errorf("CNAME target: %w", err)
		}
		return CNAME{Target: n}, nil

	case TypePTR:
		n, err := d.name()
		if err != nil {
			return nil, fmt.Errorf("PTR target: %w", err)
		}
		return PTR{Target: n}, nil

	case TypeMX:
		pref, err := d.uint16()
		if err != nil {
			return nil, fmt.Errorf("MX preference: %w", err)
		}
		n, err := d.name()
		if err != nil {
			return nil, fmt.Errorf("MX exchange: %w", err)
		}
		return MX{Preference: pref, Exchange: n}, nil

	case TypeTXT:
		var out []string
		for d.remaining() > 0 {
			n, err := d.uint8()
			if err != nil {
				return nil, err
			}
			b, err := d.bytes(int(n))
			if err != nil {
				return nil, fmt.Errorf("TXT character-string: %w", err)
			}
			out = append(out, string(b))
		}
		return TXT{Strings: out}, nil

	case TypeSOA:
		var s SOA
		var err error
		if s.Primary, err = d.name(); err != nil {
			return nil, fmt.Errorf("SOA primary: %w", err)
		}
		if s.Mailbox, err = d.name(); err != nil {
			return nil, fmt.Errorf("SOA mailbox: %w", err)
		}
		if s.Serial, err = d.uint32(); err != nil {
			return nil, fmt.Errorf("SOA serial: %w", err)
		}
		if s.Refresh, err = d.uint32(); err != nil {
			return nil, fmt.Errorf("SOA refresh: %w", err)
		}
		if s.Retry, err = d.uint32(); err != nil {
			return nil, fmt.Errorf("SOA retry: %w", err)
		}
		if s.Expire, err = d.uint32(); err != nil {
			return nil, fmt.Errorf("SOA expire: %w", err)
		}
		if s.Minimum, err = d.uint32(); err != nil {
			return nil, fmt.Errorf("SOA minimum: %w", err)
		}
		return s, nil

	case TypeSRV:
		var s SRV
		var err error
		if s.Priority, err = d.uint16(); err != nil {
			return nil, fmt.Errorf("SRV priority: %w", err)
		}
		if s.Weight, err = d.uint16(); err != nil {
			return nil, fmt.Errorf("SRV weight: %w", err)
		}
		if s.Port, err = d.uint16(); err != nil {
			return nil, fmt.Errorf("SRV port: %w", err)
		}
		// Decoded through the ordinary name reader even though RFC 2782
		// forbids compressing a target, because some servers compress it
		// anyway and refusing the response helps nobody.
		if s.Target, err = d.name(); err != nil {
			return nil, fmt.Errorf("SRV target: %w", err)
		}
		return s, nil

	case TypeOPT:
		return decodeOPT(d)
	}

	return Unknown{Kind: typ, Data: d.rest()}, nil
}

func (a A) pack(e *encoder) error {
	if !a.Addr.Is4() {
		return fmt.Errorf("A holds %v, want an IPv4 address: %w", a.Addr, ErrRData)
	}
	v := a.Addr.As4()
	e.buf = append(e.buf, v[:]...)
	return nil
}

func (a AAAA) pack(e *encoder) error {
	if !a.Addr.Is6() {
		return fmt.Errorf("AAAA holds %v, want an IPv6 address: %w", a.Addr, ErrRData)
	}
	v := a.Addr.As16()
	e.buf = append(e.buf, v[:]...)
	return nil
}

func (ns NS) pack(e *encoder) error   { return e.name(ns.Host) }
func (c CNAME) pack(e *encoder) error { return e.name(c.Target) }
func (p PTR) pack(e *encoder) error   { return e.name(p.Target) }

func (mx MX) pack(e *encoder) error {
	e.buf = binary.BigEndian.AppendUint16(e.buf, mx.Preference)
	return e.name(mx.Exchange)
}

func (t TXT) pack(e *encoder) error {
	for i, s := range t.Strings {
		if len(s) > 0xFF {
			return fmt.Errorf("TXT character-string %d is %d octets, max 255: %w", i, len(s), ErrRData)
		}
		e.buf = append(e.buf, byte(len(s)))
		e.buf = append(e.buf, s...)
	}
	return nil
}

func (s SOA) pack(e *encoder) error {
	if err := e.name(s.Primary); err != nil {
		return fmt.Errorf("SOA primary: %w", err)
	}
	if err := e.name(s.Mailbox); err != nil {
		return fmt.Errorf("SOA mailbox: %w", err)
	}
	for _, v := range [...]uint32{s.Serial, s.Refresh, s.Retry, s.Expire, s.Minimum} {
		e.buf = binary.BigEndian.AppendUint32(e.buf, v)
	}
	return nil
}

func (s SRV) pack(e *encoder) error {
	for _, v := range [...]uint16{s.Priority, s.Weight, s.Port} {
		e.buf = binary.BigEndian.AppendUint16(e.buf, v)
	}
	return e.nameUncompressed(s.Target)
}

func (u Unknown) pack(e *encoder) error {
	e.buf = append(e.buf, u.Data...)
	return nil
}
