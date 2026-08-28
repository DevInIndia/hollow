// Package wire implements DNS message encoding and decoding from RFC 1035
// sections 3 and 4, including name compression in both directions.
//
// Decoding never trusts the header counts. Each count is an upper bound on a
// loop, and every read is bounded by the octets actually present, so a message
// claiming 65535 answers in 40 octets fails with a typed error rather than
// allocating.
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const headerLen = 12

// Decode and encode failures. Every malformed message returns one of these,
// wrapped with the offset or field that failed, so callers and tests can match
// on the class of failure with errors.Is.
var (
	ErrTruncated      = errors.New("wire: message truncated")
	ErrLabelType      = errors.New("wire: reserved label type")
	ErrLabelTooLong   = errors.New("wire: label exceeds 63 octets")
	ErrNameTooLong    = errors.New("wire: name exceeds 255 octets")
	ErrNameSyntax     = errors.New("wire: malformed name")
	ErrBadPointer     = errors.New("wire: compression pointer does not point strictly backwards")
	ErrTooManyRecords = errors.New("wire: section exceeds 65535 records")
)

// Type is a DNS resource record type code.
type Type uint16

// Record types carried by this implementation. Types outside this set decode
// successfully with opaque RDATA, because a resolver that rejects an unfamiliar
// type is broken.
const (
	TypeA     Type = 1
	TypeNS    Type = 2
	TypeCNAME Type = 5
	TypeSOA   Type = 6
	TypePTR   Type = 12
	TypeMX    Type = 15
	TypeTXT   Type = 16
	TypeAAAA  Type = 28
	TypeSRV   Type = 33
	TypeOPT   Type = 41
	TypeANY   Type = 255
)

func (t Type) String() string {
	switch t {
	case TypeA:
		return "A"
	case TypeNS:
		return "NS"
	case TypeCNAME:
		return "CNAME"
	case TypeSOA:
		return "SOA"
	case TypePTR:
		return "PTR"
	case TypeMX:
		return "MX"
	case TypeTXT:
		return "TXT"
	case TypeAAAA:
		return "AAAA"
	case TypeSRV:
		return "SRV"
	case TypeOPT:
		return "OPT"
	case TypeANY:
		return "ANY"
	}
	return fmt.Sprintf("TYPE%d", uint16(t))
}

// Class is a DNS class code.
type Class uint16

// ClassIN is the internet class, the only one this implementation serves.
const ClassIN Class = 1

// Response codes from RFC 1035 section 4.1.1.
const (
	RcodeSuccess  uint8 = 0
	RcodeFormErr  uint8 = 1
	RcodeServFail uint8 = 2
	RcodeNXDomain uint8 = 3
	RcodeNotImp   uint8 = 4
	RcodeRefused  uint8 = 5
)

// Header is the 12-octet message header. The section counts are not stored,
// because they are a function of the sections themselves and a Header that can
// disagree with its own message is a bug waiting to happen.
type Header struct {
	ID                 uint16
	Response           bool
	Opcode             uint8
	Authoritative      bool
	Truncated          bool
	RecursionDesired   bool
	RecursionAvailable bool
	AuthenticData      bool
	CheckingDisabled   bool
	Rcode              uint8
}

func (h Header) flags() uint16 {
	var f uint16
	if h.Response {
		f |= 1 << 15
	}
	f |= uint16(h.Opcode&0xF) << 11
	if h.Authoritative {
		f |= 1 << 10
	}
	if h.Truncated {
		f |= 1 << 9
	}
	if h.RecursionDesired {
		f |= 1 << 8
	}
	if h.RecursionAvailable {
		f |= 1 << 7
	}
	if h.AuthenticData {
		f |= 1 << 5
	}
	if h.CheckingDisabled {
		f |= 1 << 4
	}
	return f | uint16(h.Rcode&0xF)
}

func (h *Header) setFlags(f uint16) {
	h.Response = f&(1<<15) != 0
	h.Opcode = uint8(f>>11) & 0xF
	h.Authoritative = f&(1<<10) != 0
	h.Truncated = f&(1<<9) != 0
	h.RecursionDesired = f&(1<<8) != 0
	h.RecursionAvailable = f&(1<<7) != 0
	h.AuthenticData = f&(1<<5) != 0
	h.CheckingDisabled = f&(1<<4) != 0
	h.Rcode = uint8(f & 0xF)
}

// Question is an entry in the question section.
type Question struct {
	Name  Name
	Type  Type
	Class Class
}

// RR is a resource record with its RDATA left opaque. Per-type interpretation
// lives in rdata.go, so an unknown type still round-trips.
//
// RData aliases the message buffer it was decoded from. Callers that keep an RR
// beyond the lifetime of that buffer, notably anything caching or pooling, must
// copy it first.
type RR struct {
	Name  Name
	Type  Type
	Class Class
	TTL   int32
	RData []byte
}

// Message is a decoded DNS message.
type Message struct {
	Header     Header
	Questions  []Question
	Answers    []RR
	Authority  []RR
	Additional []RR
}

// decoder walks a message, keeping the whole buffer because compression
// pointers reference absolute offsets from the start of it.
type decoder struct {
	msg []byte
	off int
}

func (d *decoder) uint16() (uint16, error) {
	if d.off+2 > len(d.msg) {
		return 0, fmt.Errorf("uint16 at offset %d: %w", d.off, ErrTruncated)
	}
	v := binary.BigEndian.Uint16(d.msg[d.off:])
	d.off += 2
	return v, nil
}

func (d *decoder) uint32() (uint32, error) {
	if d.off+4 > len(d.msg) {
		return 0, fmt.Errorf("uint32 at offset %d: %w", d.off, ErrTruncated)
	}
	v := binary.BigEndian.Uint32(d.msg[d.off:])
	d.off += 4
	return v, nil
}

func (d *decoder) question() (Question, error) {
	name, err := d.name()
	if err != nil {
		return Question{}, err
	}
	typ, err := d.uint16()
	if err != nil {
		return Question{}, err
	}
	class, err := d.uint16()
	if err != nil {
		return Question{}, err
	}
	return Question{Name: name, Type: Type(typ), Class: Class(class)}, nil
}

func (d *decoder) rr() (RR, error) {
	name, err := d.name()
	if err != nil {
		return RR{}, err
	}
	typ, err := d.uint16()
	if err != nil {
		return RR{}, err
	}
	class, err := d.uint16()
	if err != nil {
		return RR{}, err
	}
	ttl, err := d.uint32()
	if err != nil {
		return RR{}, err
	}
	rdlen, err := d.uint16()
	if err != nil {
		return RR{}, err
	}
	if d.off+int(rdlen) > len(d.msg) {
		return RR{}, fmt.Errorf("rdlength %d at offset %d exceeds %d remaining: %w",
			rdlen, d.off, len(d.msg)-d.off, ErrTruncated)
	}
	rdata := d.msg[d.off : d.off+int(rdlen)]
	d.off += int(rdlen)
	return RR{
		Name:  name,
		Type:  Type(typ),
		Class: Class(class),
		TTL:   int32(ttl),
		RData: rdata,
	}, nil
}

// section decodes n records. n comes from a header count, so it bounds the loop
// but never sizes an allocation.
func (d *decoder) section(n uint16, what string) ([]RR, error) {
	var out []RR
	for i := range int(n) {
		rr, err := d.rr()
		if err != nil {
			return nil, fmt.Errorf("%s %d: %w", what, i, err)
		}
		out = append(out, rr)
	}
	return out, nil
}

// Unpack decodes a DNS message. The returned RRs alias msg; see RR.
func Unpack(msg []byte) (*Message, error) {
	if len(msg) < headerLen {
		return nil, fmt.Errorf("header is %d octets, need %d: %w", len(msg), headerLen, ErrTruncated)
	}

	m := &Message{}
	m.Header.ID = binary.BigEndian.Uint16(msg[0:2])
	m.Header.setFlags(binary.BigEndian.Uint16(msg[2:4]))
	qdcount := binary.BigEndian.Uint16(msg[4:6])
	ancount := binary.BigEndian.Uint16(msg[6:8])
	nscount := binary.BigEndian.Uint16(msg[8:10])
	arcount := binary.BigEndian.Uint16(msg[10:12])

	d := &decoder{msg: msg, off: headerLen}
	for i := range int(qdcount) {
		q, err := d.question()
		if err != nil {
			return nil, fmt.Errorf("question %d: %w", i, err)
		}
		m.Questions = append(m.Questions, q)
	}

	var err error
	if m.Answers, err = d.section(ancount, "answer"); err != nil {
		return nil, err
	}
	if m.Authority, err = d.section(nscount, "authority"); err != nil {
		return nil, err
	}
	if m.Additional, err = d.section(arcount, "additional"); err != nil {
		return nil, err
	}
	return m, nil
}

// encoder accumulates a message and the offsets of names already written, so a
// later name sharing a suffix can be replaced by a pointer.
type encoder struct {
	buf  []byte
	ptrs map[string]int
}

func (e *encoder) question(q Question) error {
	if err := e.name(q.Name); err != nil {
		return err
	}
	e.buf = binary.BigEndian.AppendUint16(e.buf, uint16(q.Type))
	e.buf = binary.BigEndian.AppendUint16(e.buf, uint16(q.Class))
	return nil
}

func (e *encoder) rr(rr RR) error {
	if err := e.name(rr.Name); err != nil {
		return err
	}
	e.buf = binary.BigEndian.AppendUint16(e.buf, uint16(rr.Type))
	e.buf = binary.BigEndian.AppendUint16(e.buf, uint16(rr.Class))
	e.buf = binary.BigEndian.AppendUint32(e.buf, uint32(rr.TTL))
	if len(rr.RData) > 0xFFFF {
		return fmt.Errorf("rdata is %d octets: %w", len(rr.RData), ErrTooManyRecords)
	}
	e.buf = binary.BigEndian.AppendUint16(e.buf, uint16(len(rr.RData)))
	e.buf = append(e.buf, rr.RData...)
	return nil
}

// Pack encodes a message, compressing names against those already written.
func (m *Message) Pack() ([]byte, error) {
	sections := [...]struct {
		rrs  []RR
		what string
	}{
		{m.Answers, "answer"},
		{m.Authority, "authority"},
		{m.Additional, "additional"},
	}
	if len(m.Questions) > 0xFFFF {
		return nil, fmt.Errorf("question section holds %d: %w", len(m.Questions), ErrTooManyRecords)
	}
	for _, s := range sections {
		if len(s.rrs) > 0xFFFF {
			return nil, fmt.Errorf("%s section holds %d: %w", s.what, len(s.rrs), ErrTooManyRecords)
		}
	}

	e := &encoder{buf: make([]byte, 0, 512), ptrs: make(map[string]int)}
	e.buf = binary.BigEndian.AppendUint16(e.buf, m.Header.ID)
	e.buf = binary.BigEndian.AppendUint16(e.buf, m.Header.flags())
	e.buf = binary.BigEndian.AppendUint16(e.buf, uint16(len(m.Questions)))
	e.buf = binary.BigEndian.AppendUint16(e.buf, uint16(len(m.Answers)))
	e.buf = binary.BigEndian.AppendUint16(e.buf, uint16(len(m.Authority)))
	e.buf = binary.BigEndian.AppendUint16(e.buf, uint16(len(m.Additional)))

	for i, q := range m.Questions {
		if err := e.question(q); err != nil {
			return nil, fmt.Errorf("question %d: %w", i, err)
		}
	}
	for _, s := range sections {
		for i, rr := range s.rrs {
			if err := e.rr(rr); err != nil {
				return nil, fmt.Errorf("%s %d: %w", s.what, i, err)
			}
		}
	}
	return e.buf, nil
}
