package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"testing"
)

func TestQueryRoundTrip(t *testing.T) {
	q := &Message{
		Header:    Header{ID: 0x1a2b, RecursionDesired: true},
		Questions: []Question{{Name: "example.com.", Type: TypeA, Class: ClassIN}},
	}

	got, err := q.Pack()
	if err != nil {
		t.Fatalf("Pack() = %v", err)
	}
	want := []byte{
		0x1a, 0x2b, // ID
		0x01, 0x00, // RD
		0x00, 0x01, // QDCOUNT
		0x00, 0x00, // ANCOUNT
		0x00, 0x00, // NSCOUNT
		0x00, 0x00, // ARCOUNT
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		0x00, 0x01, // QTYPE A
		0x00, 0x01, // QCLASS IN
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Pack()\n got % x\nwant % x", got, want)
	}

	back, err := Unpack(got)
	if err != nil {
		t.Fatalf("Unpack() = %v", err)
	}
	if back.Header.ID != 0x1a2b {
		t.Errorf("ID = %#04x, want 0x1a2b", back.Header.ID)
	}
	if !back.Header.RecursionDesired || back.Header.Response {
		t.Errorf("flags: RD = %v, QR = %v; want true, false",
			back.Header.RecursionDesired, back.Header.Response)
	}
	if len(back.Questions) != 1 {
		t.Fatalf("got %d questions, want 1", len(back.Questions))
	}
	if q := back.Questions[0]; q.Name != "example.com." || q.Type != TypeA || q.Class != ClassIN {
		t.Errorf("question = %q %v %v, want example.com. A IN", q.Name, q.Type, q.Class)
	}

	again, err := back.Pack()
	if err != nil {
		t.Fatalf("re-Pack() = %v", err)
	}
	if !bytes.Equal(got, again) {
		t.Fatalf("re-encode differs\n got % x\nwant % x", again, got)
	}
}

func TestHeaderFlagsRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		flags uint16
		hdr   Header
	}{
		{"query with RD", 0x0100, Header{RecursionDesired: true}},
		// The flag word of golden fixture 1, a recursive answer from 8.8.8.8.
		{"response RD RA", 0x8180, Header{Response: true, RecursionDesired: true, RecursionAvailable: true}},
		// The flag word of golden fixture 2, a truncated referral from a root.
		{"response truncated", 0x8200, Header{Response: true, Truncated: true}},
		{"authoritative", 0x8400, Header{Response: true, Authoritative: true}},
		{"nxdomain", 0x8183, Header{
			Response: true, RecursionDesired: true, RecursionAvailable: true, Rcode: RcodeNXDomain,
		}},
		{"servfail", 0x8182, Header{
			Response: true, RecursionDesired: true, RecursionAvailable: true, Rcode: RcodeServFail,
		}},
		{"AD and CD", 0x0130, Header{RecursionDesired: true, AuthenticData: true, CheckingDisabled: true}},
		{"opcode 2", 0x1000, Header{Opcode: 2}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.hdr.flags(); got != tt.flags {
				t.Errorf("flags() = %#04x, want %#04x", got, tt.flags)
			}
			var h Header
			h.setFlags(tt.flags)
			if h != tt.hdr {
				t.Errorf("setFlags(%#04x) = %+v, want %+v", tt.flags, h, tt.hdr)
			}
		})
	}
}

func TestMessageCompressesAcrossRecords(t *testing.T) {
	m := &Message{
		Header:    Header{ID: 1, Response: true},
		Questions: []Question{{Name: "example.com.", Type: TypeA, Class: ClassIN}},
		Answers: []RR{
			{Name: "example.com.", Type: TypeA, Class: ClassIN, TTL: 300, Data: A{Addr: netip.AddrFrom4([4]byte{93, 184, 216, 34})}},
			{Name: "www.example.com.", Type: TypeA, Class: ClassIN, TTL: 300, Data: A{Addr: netip.AddrFrom4([4]byte{1, 2, 3, 4})}},
		},
		Authority: []RR{
			{Name: "example.com.", Type: TypeNS, Class: ClassIN, TTL: 300, Data: NS{Host: Root}},
		},
	}

	buf, err := m.Pack()
	if err != nil {
		t.Fatalf("Pack() = %v", err)
	}

	// The question name occupies offset 12, so every later example.com. is a
	// two-octet pointer to it rather than 13 octets of labels.
	if got := buf[29:31]; !bytes.Equal(got, []byte{0xC0, 0x0C}) {
		t.Errorf("first answer name = % x, want c0 0c", got)
	}

	back, err := Unpack(buf)
	if err != nil {
		t.Fatalf("Unpack() = %v", err)
	}
	names := []Name{back.Answers[0].Name, back.Answers[1].Name, back.Authority[0].Name}
	want := []Name{"example.com.", "www.example.com.", "example.com."}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("name %d = %q, want %q", i, names[i], want[i])
		}
	}
	if got, want := back.Answers[0].Data, (A{Addr: netip.AddrFrom4([4]byte{93, 184, 216, 34})}); got != want {
		t.Errorf("rdata = %v, want %v", got, want)
	}

	again, err := back.Pack()
	if err != nil {
		t.Fatalf("re-Pack() = %v", err)
	}
	if !bytes.Equal(buf, again) {
		t.Fatalf("re-encode differs\n got % x\nwant % x", again, buf)
	}
}

// Header counts are attacker-controlled. Each must bound a loop and never size
// an allocation, so an inflated count fails on the octets actually present.
func TestUnpackRejects(t *testing.T) {
	// A well-formed 12-octet header with the counts left to the caller.
	header := func(qd, an, ns, ar uint16) []byte {
		b := make([]byte, headerLen)
		binary.BigEndian.PutUint16(b[0:], 0x1234)
		binary.BigEndian.PutUint16(b[2:], 0x8180)
		binary.BigEndian.PutUint16(b[4:], qd)
		binary.BigEndian.PutUint16(b[6:], an)
		binary.BigEndian.PutUint16(b[8:], ns)
		binary.BigEndian.PutUint16(b[10:], ar)
		return b
	}
	question := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}

	claims65535 := append(header(0, 0xFFFF, 0, 0), make([]byte, 28)...)

	// A record owned by the root, so the name is a single zero octet and the
	// failure under test is the rdlength rather than the name.
	rdlenOverrun := append(header(0, 1, 0, 0),
		0,    // NAME, root
		0, 1, // TYPE A
		0, 1, // CLASS IN
		0, 0, 1, 44, // TTL 300
		0xFF, 0xFF, // RDLENGTH 65535, with four octets actually present
		1, 2, 3, 4)

	tests := []struct {
		name string
		msg  []byte
		want error
	}{
		{"empty message", []byte{}, ErrTruncated},
		{"shorter than a header", make([]byte, 11), ErrTruncated},
		{"qdcount 3 with one question", append(header(3, 0, 0, 0), question...), ErrTruncated},
		{"ancount 65535 in 40 octets", claims65535, ErrTruncated},
		{"rdlength past end of buffer", rdlenOverrun, ErrTruncated},
		{"answer section truncated mid record", append(header(0, 1, 0, 0), 0, 0, 1), ErrTruncated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Unpack(tt.msg); !errors.Is(err, tt.want) {
				t.Fatalf("Unpack() = %v, want %v", err, tt.want)
			}
		})
	}
}

// 512 octets is the pre-EDNS0 UDP limit, so it is the boundary most likely to
// be special-cased by accident. Nothing here should treat it as one.
//
// The payload is an unmodelled type, whose rdata is a plain octet run and so
// can be sized to land the message exactly on each boundary.
func TestMessageAtUDPSizeBoundary(t *testing.T) {
	const typeFiller Type = 65280
	for _, size := range []int{511, 512, 513} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			// Header 12 + question 17 + record overhead 12 leaves the rest
			// of the message to rdata.
			const overhead = 12 + 17 + 12
			m := &Message{
				Header:    Header{ID: 9, Response: true},
				Questions: []Question{{Name: "example.com.", Type: typeFiller, Class: ClassIN}},
				Answers: []RR{{
					Name: "example.com.", Type: typeFiller, Class: ClassIN, TTL: 60,
					Data: Unknown{Kind: typeFiller, Data: bytes.Repeat([]byte{'x'}, size-overhead)},
				}},
			}
			buf, err := m.Pack()
			if err != nil {
				t.Fatalf("Pack() = %v", err)
			}
			if len(buf) != size {
				t.Fatalf("packed %d octets, want %d", len(buf), size)
			}
			back, err := Unpack(buf)
			if err != nil {
				t.Fatalf("Unpack() = %v", err)
			}
			u, ok := back.Answers[0].Data.(Unknown)
			if !ok {
				t.Fatalf("rdata is %T, want Unknown", back.Answers[0].Data)
			}
			if got := len(u.Data); got != size-overhead {
				t.Errorf("rdata = %d octets, want %d", got, size-overhead)
			}
		})
	}
}

// A header with all counts zero is a valid, if useless, message.
func TestUnpackBareHeader(t *testing.T) {
	m, err := Unpack(make([]byte, headerLen))
	if err != nil {
		t.Fatalf("Unpack() = %v", err)
	}
	if len(m.Questions)+len(m.Answers)+len(m.Authority)+len(m.Additional) != 0 {
		t.Errorf("expected no records, got %+v", m)
	}
}

// Unknown types keep their RDATA verbatim rather than being rejected, so a
// resolver does not choke on a record it was not taught about.
func TestUnknownTypeRoundTrips(t *testing.T) {
	const typeCAA Type = 257
	rdata := []byte{0, 5, 'i', 's', 's', 'u', 'e'}
	m := &Message{
		Header: Header{ID: 7, Response: true},
		Answers: []RR{{
			Name: "example.com.", Type: typeCAA, Class: ClassIN, TTL: 60,
			Data: Unknown{Kind: typeCAA, Data: rdata},
		}},
	}
	buf, err := m.Pack()
	if err != nil {
		t.Fatalf("Pack() = %v", err)
	}
	back, err := Unpack(buf)
	if err != nil {
		t.Fatalf("Unpack() = %v", err)
	}
	rr := back.Answers[0]
	if rr.Type != typeCAA {
		t.Errorf("type = %v, want %v", rr.Type, typeCAA)
	}
	u, ok := rr.Data.(Unknown)
	if !ok {
		t.Fatalf("rdata is %T, want Unknown", rr.Data)
	}
	if !bytes.Equal(u.Data, rdata) {
		t.Errorf("rdata = % x, want % x", u.Data, rdata)
	}
	if rr.Type.String() != "TYPE257" {
		t.Errorf("Type.String() = %q, want TYPE257", rr.Type.String())
	}
}

// ParseType is the inverse of Type.String, and the property worth pinning is
// that round trip: a type this package does not model has to survive being
// printed and read back, or a caller cannot ask for the record they were just
// shown.
func TestParseTypeRoundTrip(t *testing.T) {
	known := []Type{TypeA, TypeNS, TypeCNAME, TypeSOA, TypePTR, TypeMX, TypeTXT, TypeAAAA, TypeSRV, TypeOPT, TypeANY}
	for _, want := range append(known, 0, 99, 65535) {
		got, err := ParseType(want.String())
		if err != nil {
			t.Errorf("ParseType(%q) = %v", want.String(), err)
			continue
		}
		if got != want {
			t.Errorf("ParseType(%q) = %d, want %d", want.String(), got, want)
		}
	}
}

func TestParseTypeSpelling(t *testing.T) {
	// Zone files and dig both accept either case, and refusing "aaaa" would be
	// a difference from every other tool for no reason.
	for _, s := range []string{"aaaa", "AAAA", "AaAa", "type28", "TYPE28"} {
		if got, err := ParseType(s); err != nil || got != TypeAAAA {
			t.Errorf("ParseType(%q) = %d, %v, want %d, nil", s, got, err, TypeAAAA)
		}
	}
	for _, s := range []string{"", "NOTATYPE", "TYPE", "TYPE65536", "TYPE-1", "TYPE 1", "TYPEA"} {
		if got, err := ParseType(s); err == nil {
			t.Errorf("ParseType(%q) = %d, nil, want an error", s, got)
		}
	}
}
