package wire

import (
	"fmt"
	"net/netip"
	"strings"
)

// Span is one field of a message, in the order the decoder read it.
//
// Spans are contiguous and cover the whole buffer: the offsets of any two
// neighbours meet exactly, and the last one ends at the final octet. That is the
// property that makes an annotated dump worth anything, because a region nobody
// can name is a region the decoder was not really reading.
type Span struct {
	Offset  int
	Length  int
	Section string // header, question, answer, authority, additional, or trailing
	Field   string // ID, flags, QNAME, TTL, RDATA, and so on
	Detail  string // the decoded value, in the terms of the field
}

// End is the offset one past the last octet of the span.
func (s Span) End() int { return s.Offset + s.Length }

// Annotate walks a raw message and returns a span per field.
//
// It reads with the same decoder the resolver reads with, field by field and in
// the same order, so an annotation is a record of what the parser did rather
// than a second opinion about what the bytes mean. A message that fails to
// decode returns the spans read so far along with the error, because the field
// the parser stopped on is usually the whole answer to why.
func Annotate(msg []byte) ([]Span, error) {
	a := &annotator{d: &decoder{msg: msg}}
	err := a.message()

	// Whatever is left is named as unread rather than left silent. A message
	// with trailing octets is either a padded datagram or two messages in one
	// buffer, and both are worth seeing.
	if err == nil && a.d.off < len(msg) {
		a.spans = append(a.spans, Span{
			Offset:  a.d.off,
			Length:  len(msg) - a.d.off,
			Section: "trailing",
			Field:   "unread",
			Detail:  fmt.Sprintf("%d octets past the end of the message", len(msg)-a.d.off),
		})
	}
	return a.spans, err
}

type annotator struct {
	d       *decoder
	spans   []Span
	section string
	counts  [4]uint16 // QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT, as the header gave them
}

// mark records a span running from start to wherever the decoder now is.
func (a *annotator) mark(start int, field, detail string) {
	a.spans = append(a.spans, Span{
		Offset:  start,
		Length:  a.d.off - start,
		Section: a.section,
		Field:   field,
		Detail:  detail,
	})
}

func (a *annotator) message() error {
	if err := a.header(); err != nil {
		return err
	}
	a.section = "question"
	for i := range int(a.counts[0]) {
		if err := a.question(); err != nil {
			return fmt.Errorf("question %d: %w", i, err)
		}
	}
	for _, sec := range []struct {
		name  string
		count uint16
	}{
		{"answer", a.counts[1]},
		{"authority", a.counts[2]},
		{"additional", a.counts[3]},
	} {
		a.section = sec.name
		for j := range int(sec.count) {
			if err := a.rr(); err != nil {
				return fmt.Errorf("%s %d: %w", sec.name, j, err)
			}
		}
	}
	return nil
}

func (a *annotator) header() error {
	a.section = "header"

	start := a.d.off
	id, err := a.d.uint16()
	if err != nil {
		return err
	}
	a.mark(start, "ID", fmt.Sprintf("%#04x", id))

	start = a.d.off
	bits, err := a.d.uint16()
	if err != nil {
		return err
	}
	var h Header
	h.setFlags(bits)
	a.mark(start, "flags", flagDetail(h))

	names := [4]string{"QDCOUNT", "ANCOUNT", "NSCOUNT", "ARCOUNT"}
	for i := range names {
		start = a.d.off
		n, err := a.d.uint16()
		if err != nil {
			return err
		}
		a.counts[i] = n
		a.mark(start, names[i], fmt.Sprintf("%d", n))
	}
	return nil
}

func flagDetail(h Header) string {
	var b strings.Builder
	fmt.Fprintf(&b, "QR=%d opcode=%d", btoi(h.Response), h.Opcode)
	for _, f := range []struct {
		name string
		set  bool
	}{
		{"AA", h.Authoritative}, {"TC", h.Truncated}, {"RD", h.RecursionDesired},
		{"RA", h.RecursionAvailable}, {"AD", h.AuthenticData}, {"CD", h.CheckingDisabled},
	} {
		fmt.Fprintf(&b, " %s=%d", f.name, btoi(f.set))
	}
	fmt.Fprintf(&b, " rcode=%d", h.Rcode)
	return b.String()
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (a *annotator) question() error {
	if err := a.name("QNAME"); err != nil {
		return err
	}
	start := a.d.off
	typ, err := a.d.uint16()
	if err != nil {
		return err
	}
	a.mark(start, "QTYPE", fmt.Sprintf("%s (%d)", Type(typ), typ))

	start = a.d.off
	class, err := a.d.uint16()
	if err != nil {
		return err
	}
	a.mark(start, "QCLASS", classDetail(Class(class)))
	return nil
}

func (a *annotator) rr() error {
	if err := a.name("NAME"); err != nil {
		return err
	}

	start := a.d.off
	typ, err := a.d.uint16()
	if err != nil {
		return err
	}
	rtype := Type(typ)
	a.mark(start, "TYPE", fmt.Sprintf("%s (%d)", rtype, typ))

	// An OPT record is not a record about a name. RFC 6891 reuses the class
	// field for the sender's UDP payload size and the TTL field for the
	// extended rcode, the version and the DO bit, so labelling them as class
	// and TTL would be repeating the layout rather than reading it.
	start = a.d.off
	class, err := a.d.uint16()
	if err != nil {
		return err
	}
	if rtype == TypeOPT {
		a.mark(start, "UDP size", fmt.Sprintf("%d octets the sender will accept", class))
	} else {
		a.mark(start, "CLASS", classDetail(Class(class)))
	}

	start = a.d.off
	ttl, err := a.d.uint32()
	if err != nil {
		return err
	}
	if rtype == TypeOPT {
		a.mark(start, "extended rcode and flags", fmt.Sprintf("version %d, DO=%d", (ttl>>16)&0xFF, (ttl>>15)&1))
	} else {
		a.mark(start, "TTL", fmt.Sprintf("%d seconds", int32(ttl)))
	}

	start = a.d.off
	rdlen, err := a.d.uint16()
	if err != nil {
		return err
	}
	a.mark(start, "RDLENGTH", fmt.Sprintf("%d", rdlen))

	if a.d.off+int(rdlen) > len(a.d.msg) {
		return fmt.Errorf("rdlength %d at offset %d exceeds %d remaining: %w",
			rdlen, a.d.off, len(a.d.msg)-a.d.off, ErrTruncated)
	}
	return a.rdata(rtype, a.d.off+int(rdlen))
}

// rdata names the fields inside one record's rdata. The shape of each type is
// the shape decodeRData reads, and every field is read with the same primitives,
// so the values here are decoded rather than guessed at. The end offset is the
// RDLENGTH boundary: anything the type does not account for is marked as
// unparsed instead of being quietly skipped.
func (a *annotator) rdata(typ Type, end int) error {
	// A decoder cut off at the boundary, exactly as rr does, so a field that
	// reads past its own end fails here the way it would there.
	outer := a.d
	a.d = &decoder{msg: outer.msg[:end], off: outer.off}
	defer func() {
		outer.off = end
		a.d = outer
	}()

	var err error
	switch typ {
	case TypeA, TypeAAAA:
		start := a.d.off
		width := 4
		if typ == TypeAAAA {
			width = 16
		}
		var b []byte
		if b, err = a.d.address(width); err == nil {
			addr, _ := netip.AddrFromSlice(b)
			a.mark(start, "RDATA address", addr.String())
		}

	case TypeNS:
		err = a.name("RDATA host")
	case TypeCNAME, TypePTR:
		err = a.name("RDATA target")

	case TypeMX:
		if err = a.uint16Field("RDATA preference"); err == nil {
			err = a.name("RDATA exchange")
		}

	case TypeSRV:
		for _, f := range []string{"RDATA priority", "RDATA weight", "RDATA port"} {
			if err = a.uint16Field(f); err != nil {
				break
			}
		}
		if err == nil {
			err = a.name("RDATA target")
		}

	case TypeSOA:
		if err = a.name("RDATA primary"); err == nil {
			err = a.name("RDATA mailbox")
		}
		for _, f := range []string{"RDATA serial", "RDATA refresh", "RDATA retry", "RDATA expire", "RDATA minimum"} {
			if err != nil {
				break
			}
			err = a.uint32Field(f)
		}

	case TypeTXT:
		for a.d.remaining() > 0 && err == nil {
			start := a.d.off
			var n uint8
			if n, err = a.d.uint8(); err != nil {
				break
			}
			var b []byte
			if b, err = a.d.bytes(int(n)); err != nil {
				break
			}
			a.mark(start, "RDATA string", fmt.Sprintf("%d octets, %q", n, string(b)))
		}

	default:
		// Includes OPT, whose options are length-prefixed the same way, and
		// every type this package does not model. RFC 3597 says an unknown
		// rdata is octets and nothing more, and saying so is more honest than
		// inventing a structure for it.
		if a.d.remaining() > 0 {
			start := a.d.off
			b := a.d.rest()
			a.mark(start, "RDATA", fmt.Sprintf("%d octets, % x", len(b), b))
		}
	}
	if err != nil {
		return err
	}

	// Anything the type did not consume is still part of the record, so it is
	// named rather than jumped over.
	if a.d.off < end {
		start := a.d.off
		b := a.d.rest()
		a.mark(start, "RDATA unparsed", fmt.Sprintf("%d octets the %s layout does not account for", len(b), typ))
	}
	return nil
}

func (a *annotator) uint16Field(field string) error {
	start := a.d.off
	v, err := a.d.uint16()
	if err != nil {
		return err
	}
	a.mark(start, field, fmt.Sprintf("%d", v))
	return nil
}

func (a *annotator) uint32Field(field string) error {
	start := a.d.off
	v, err := a.d.uint32()
	if err != nil {
		return err
	}
	a.mark(start, field, fmt.Sprintf("%d", v))
	return nil
}

// name reads one name with the real name decoder and then describes the octets
// it consumed: the labels as they sit in the buffer, and where a compression
// pointer went if the name ended in one.
func (a *annotator) name(field string) error {
	start := a.d.off
	n, err := a.d.name()
	if err != nil {
		return err
	}
	a.mark(start, field, nameDetail(a.d.msg, start, n))
	return nil
}

// nameDetail describes the encoding of a name that has already been decoded.
//
// It re-reads the octets the decoder consumed purely to say what they were: how
// the labels were split, and whether the name ended by pointing somewhere else.
// It decides nothing, which is why it can afford to stop at the first thing it
// does not recognise.
func nameDetail(msg []byte, start int, n Name) string {
	var labels []string
	pointer := -1
	for i := start; i < len(msg); {
		b := msg[i]
		switch {
		case b == 0:
			i = len(msg)
		case b&0xC0 == 0xC0:
			if i+1 < len(msg) {
				pointer = int(b&0x3F)<<8 | int(msg[i+1])
			}
			i = len(msg)
		default:
			end := i + 1 + int(b)
			if end > len(msg) {
				i = len(msg)
				break
			}
			labels = append(labels, fmt.Sprintf("%q", string(msg[i+1:end])))
			i = end
		}
	}

	var b strings.Builder
	b.WriteString(string(n))
	if len(labels) > 0 {
		fmt.Fprintf(&b, " = %s", strings.Join(labels, " "))
	}
	if pointer >= 0 {
		if len(labels) > 0 {
			b.WriteString(" +")
		} else {
			b.WriteString(" =")
		}
		fmt.Fprintf(&b, " pointer to %#04x", pointer)
	} else if len(labels) == 0 {
		b.WriteString(" = root, one zero octet")
	}
	return b.String()
}

func classDetail(c Class) string {
	if c == ClassIN {
		return "IN (1)"
	}
	return fmt.Sprintf("CLASS%d (%d)", uint16(c), uint16(c))
}
