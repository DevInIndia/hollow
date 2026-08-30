package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

// answerMsg builds a response carrying one record of type typ whose RDATA is
// the given octets. The owner name is the root, so a failure is always about
// the rdata rather than the envelope around it.
func answerMsg(typ Type, rdlen int, rdata []byte) []byte {
	b := make([]byte, 0, headerLen+11+len(rdata))
	b = append(b,
		0x12, 0x34, // ID
		0x81, 0x80, // QR RD RA
		0, 0, // QDCOUNT
		0, 1, // ANCOUNT
		0, 0, // NSCOUNT
		0, 0, // ARCOUNT
	)
	b = append(b, 0) // NAME, root
	b = binary.BigEndian.AppendUint16(b, uint16(typ))
	b = binary.BigEndian.AppendUint16(b, uint16(ClassIN))
	b = binary.BigEndian.AppendUint32(b, 300)
	b = binary.BigEndian.AppendUint16(b, uint16(rdlen))
	return append(b, rdata...)
}

// Every supported type encodes, decodes, and re-encodes to the same octets.
func TestRDataRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		typ  Type
		data RData
	}{
		{"A", TypeA, A{Addr: netip.MustParseAddr("192.0.2.1")}},
		{"AAAA", TypeAAAA, AAAA{Addr: netip.MustParseAddr("2001:db8::1")}},
		{"NS", TypeNS, NS{Host: "ns1.example.net."}},
		{"NS root", TypeNS, NS{Host: Root}},
		{"CNAME", TypeCNAME, CNAME{Target: "canonical.example.net."}},
		{"PTR", TypePTR, PTR{Target: "host.example.net."}},
		{"MX", TypeMX, MX{Preference: 10, Exchange: "mail.example.net."}},
		{"MX preference zero", TypeMX, MX{Preference: 0, Exchange: "mail.example.net."}},
		{"TXT one string", TypeTXT, TXT{Strings: []string{"v=spf1 -all"}}},
		{"TXT several strings", TypeTXT, TXT{Strings: []string{"first", "second", "third"}}},
		{"TXT empty string", TypeTXT, TXT{Strings: []string{""}}},
		{"TXT maximum string", TypeTXT, TXT{Strings: []string{strings.Repeat("x", 255)}}},
		{"SOA", TypeSOA, SOA{
			Primary: "ns1.example.net.", Mailbox: "hostmaster.example.net.",
			Serial: 2026082901, Refresh: 7200, Retry: 3600, Expire: 1209600, Minimum: 300,
		}},
		{"SRV", TypeSRV, SRV{Priority: 10, Weight: 60, Port: 5060, Target: "sip.example.net."}},
		{"unknown type", 65280, Unknown{Kind: 65280, Data: []byte{1, 2, 3}}},
		{"unknown type empty", 65281, Unknown{Kind: 65281, Data: nil}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Message{
				Header:    Header{ID: 0x4242, Response: true},
				Questions: []Question{{Name: "example.org.", Type: tt.typ, Class: ClassIN}},
				Answers: []RR{{
					Name: "example.org.", Type: tt.typ, Class: ClassIN, TTL: 3600, Data: tt.data,
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
			if len(back.Answers) != 1 {
				t.Fatalf("got %d answers, want 1", len(back.Answers))
			}
			got := back.Answers[0].Data
			if got.Type() != tt.typ {
				t.Errorf("rdata type = %v, want %v", got.Type(), tt.typ)
			}
			// An empty Unknown decodes to a zero-length slice rather than a
			// nil one, which DeepEqual distinguishes and nothing else does.
			if u, ok := got.(Unknown); ok && len(u.Data) == 0 {
				u.Data = nil
				got = u
			}
			if !reflect.DeepEqual(got, tt.data) {
				t.Errorf("rdata = %#v, want %#v", got, tt.data)
			}

			again, err := back.Pack()
			if err != nil {
				t.Fatalf("re-Pack() = %v", err)
			}
			if !bytes.Equal(buf, again) {
				t.Fatalf("re-encode differs\n got % x\nwant % x", again, buf)
			}
		})
	}
}

// Every case here is a record whose rdata and RDLENGTH disagree, which the
// exact-boundary check is there to catch.
func TestRDataRejects(t *testing.T) {
	tests := []struct {
		name  string
		msg   []byte
		want  error
		about string
	}{
		{
			name: "A with rdlength 5", about: "case 13",
			msg:  answerMsg(TypeA, 5, []byte{192, 0, 2, 1, 0}),
			want: ErrRData,
		},
		{
			name: "A with rdlength 3", about: "the same rule from below",
			msg:  answerMsg(TypeA, 3, []byte{192, 0, 2}),
			want: ErrRData,
		},
		{
			name: "AAAA with rdlength 4", about: "case 14",
			msg:  answerMsg(TypeAAAA, 4, []byte{192, 0, 2, 1}),
			want: ErrRData,
		},
		{
			name: "rdlength shorter than the name it holds", about: "case 12",
			msg:  answerMsg(TypeCNAME, 4, []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0}),
			want: ErrTruncated,
		},
		{
			name: "rdlength longer than the name it holds", about: "case 12 from the other side",
			msg:  answerMsg(TypeNS, 9, []byte{2, 'n', 's', 0, 0, 0, 0, 0, 0}),
			want: ErrRData,
		},
		{
			name: "TXT character-string past the rdata end", about: "case 15",
			msg:  answerMsg(TypeTXT, 3, []byte{5, 'a', 'b'}),
			want: ErrTruncated,
		},
		{
			name: "MX truncated mid name", about: "case 16",
			msg:  answerMsg(TypeMX, 5, []byte{0, 10, 4, 'm', 'a'}),
			want: ErrTruncated,
		},
		{
			name: "SOA with four of its five values", about: "case 17",
			msg: answerMsg(TypeSOA, 18, []byte{
				0, 0, // primary and mailbox, both root
				0, 0, 0, 1, // serial
				0, 0, 0, 2, // refresh
				0, 0, 0, 3, // retry
				0, 0, 0, 4, // expire, and then nothing
			}),
			want: ErrTruncated,
		},
		{
			name: "SRV truncated before its target", about: "fixed fields then nothing",
			msg:  answerMsg(TypeSRV, 6, []byte{0, 10, 0, 60, 0x13, 0xc4}),
			want: ErrTruncated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Unpack(tt.msg); !errors.Is(err, tt.want) {
				t.Fatalf("Unpack() = %v, want %v (%s)", err, tt.want, tt.about)
			}
		})
	}
}

// A name inside rdata is compressed against the rest of the message, and a
// pointer inside rdata is followed on the way back.
func TestRDataNameCompression(t *testing.T) {
	m := &Message{
		Header:    Header{ID: 1, Response: true},
		Questions: []Question{{Name: "example.com.", Type: TypeNS, Class: ClassIN}},
		Answers: []RR{
			{Name: "example.com.", Type: TypeNS, Class: ClassIN, TTL: 300, Data: NS{Host: "ns1.example.com."}},
			{Name: "example.com.", Type: TypeMX, Class: ClassIN, TTL: 300, Data: MX{Preference: 10, Exchange: "ns1.example.com."}},
		},
	}
	buf, err := m.Pack()
	if err != nil {
		t.Fatalf("Pack() = %v", err)
	}

	// The NS host is "ns1" plus a pointer to example.com. at offset 12, and the
	// MX exchange is a bare pointer to the host the NS record just wrote.
	back, err := Unpack(buf)
	if err != nil {
		t.Fatalf("Unpack() = %v", err)
	}
	if got := back.Answers[0].Data.(NS).Host; got != "ns1.example.com." {
		t.Errorf("NS host = %q, want ns1.example.com.", got)
	}
	if got := back.Answers[1].Data.(MX).Exchange; got != "ns1.example.com." {
		t.Errorf("MX exchange = %q, want ns1.example.com.", got)
	}

	// Uncompressed the two rdata fields would be 17 and 19 octets. Compression
	// is what keeps the message this small, so a size check proves the pointer
	// was actually emitted rather than merely tolerated on the way back.
	if len(buf) != 63 {
		t.Errorf("packed %d octets, want 63; compression inside rdata did not happen", len(buf))
	}

	again, err := back.Pack()
	if err != nil {
		t.Fatalf("re-Pack() = %v", err)
	}
	if !bytes.Equal(buf, again) {
		t.Fatalf("re-encode differs\n got % x\nwant % x", again, buf)
	}
}

// RFC 2782 forbids compressing an SRV target, because a receiver treating the
// rdata as opaque never expands the pointer.
func TestSRVTargetNotCompressed(t *testing.T) {
	m := &Message{
		Header:    Header{ID: 1, Response: true},
		Questions: []Question{{Name: "example.com.", Type: TypeSRV, Class: ClassIN}},
		Answers: []RR{{
			Name: "example.com.", Type: TypeSRV, Class: ClassIN, TTL: 300,
			Data: SRV{Priority: 10, Weight: 60, Port: 5060, Target: "example.com."},
		}},
	}
	buf, err := m.Pack()
	if err != nil {
		t.Fatalf("Pack() = %v", err)
	}

	// Six octets of fixed fields plus the name in full, not six plus a pointer.
	const wantRDLen = 6 + 13
	rdlen := binary.BigEndian.Uint16(buf[len(buf)-wantRDLen-2:])
	if int(rdlen) != wantRDLen {
		t.Fatalf("SRV rdlength = %d, want %d; the target was compressed", rdlen, wantRDLen)
	}
	if i := bytes.IndexByte(buf[len(buf)-wantRDLen:], 0xC0); i >= 0 {
		t.Errorf("SRV rdata holds a pointer at offset %d: % x", i, buf[len(buf)-wantRDLen:])
	}
}

// Some servers compress an SRV target regardless. Refusing the response would
// help nobody, so the decoder follows the pointer.
func TestSRVCompressedTargetStillDecodes(t *testing.T) {
	msg := []byte{
		0x12, 0x34, 0x81, 0x80,
		0, 1, // QDCOUNT
		0, 1, // ANCOUNT
		0, 0, 0, 0,
	}
	msg = append(msg, 3, 's', 'i', 'p', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0)
	msg = append(msg, 0, 33, 0, 1) // QTYPE SRV, QCLASS IN
	msg = append(msg, 0xC0, 0x0C)  // owner, pointer to the question name
	msg = append(msg, 0, 33, 0, 1) // TYPE SRV, CLASS IN
	msg = append(msg, 0, 0, 1, 44) // TTL
	msg = append(msg, 0, 8)        // RDLENGTH
	msg = append(msg, 0, 10, 0, 60, 0x13, 0xC4, 0xC0, 0x0C)

	back, err := Unpack(msg)
	if err != nil {
		t.Fatalf("Unpack() = %v", err)
	}
	srv, ok := back.Answers[0].Data.(SRV)
	if !ok {
		t.Fatalf("rdata is %T, want SRV", back.Answers[0].Data)
	}
	if srv.Target != "sip.example.com." {
		t.Errorf("target = %q, want sip.example.com.", srv.Target)
	}
	if srv.Port != 5060 {
		t.Errorf("port = %d, want 5060", srv.Port)
	}
}

// A record whose declared type disagrees with the rdata it carries is a caller
// bug, and silently writing one type's octets under another type's code would
// put a corrupt record on the wire.
func TestPackRejectsMismatchedRData(t *testing.T) {
	tests := []struct {
		name string
		rr   RR
	}{
		{"type disagrees with rdata", RR{
			Name: "example.com.", Type: TypeA, Class: ClassIN,
			Data: NS{Host: "ns1.example.com."},
		}},
		{"unknown rdata under the wrong code", RR{
			Name: "example.com.", Type: 65280, Class: ClassIN,
			Data: Unknown{Kind: 65281, Data: []byte{1}},
		}},
		{"no rdata at all", RR{
			Name: "example.com.", Type: TypeA, Class: ClassIN,
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Message{Header: Header{ID: 1}, Answers: []RR{tt.rr}}
			if _, err := m.Pack(); !errors.Is(err, ErrRData) {
				t.Fatalf("Pack() = %v, want %v", err, ErrRData)
			}
		})
	}
}

// A holds four octets and AAAA sixteen, so an address of the wrong family has
// no valid encoding.
func TestPackRejectsWrongAddressFamily(t *testing.T) {
	tests := []struct {
		name string
		rr   RR
	}{
		{"A holding IPv6", RR{
			Name: "example.com.", Type: TypeA, Class: ClassIN,
			Data: A{Addr: netip.MustParseAddr("2001:db8::1")},
		}},
		{"AAAA holding IPv4", RR{
			Name: "example.com.", Type: TypeAAAA, Class: ClassIN,
			Data: AAAA{Addr: netip.MustParseAddr("192.0.2.1")},
		}},
		{"A with no address", RR{
			Name: "example.com.", Type: TypeA, Class: ClassIN, Data: A{},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Message{Header: Header{ID: 1}, Answers: []RR{tt.rr}}
			if _, err := m.Pack(); !errors.Is(err, ErrRData) {
				t.Fatalf("Pack() = %v, want %v", err, ErrRData)
			}
		})
	}
}

// A character-string carries its length in one octet, so 256 of them cannot be
// expressed and must fail at the encoder rather than being silently cut.
func TestPackRejectsOversizedTXT(t *testing.T) {
	m := &Message{
		Header: Header{ID: 1},
		Answers: []RR{{
			Name: "example.com.", Type: TypeTXT, Class: ClassIN,
			Data: TXT{Strings: []string{strings.Repeat("x", 256)}},
		}},
	}
	if _, err := m.Pack(); !errors.Is(err, ErrRData) {
		t.Fatalf("Pack() = %v, want %v", err, ErrRData)
	}
}

// A NODATA answer is RCODE 0 with an empty answer section and an SOA in
// authority. It is not NXDOMAIN, and the two must stay distinguishable.
func TestNoDataAndNXDomainRoundTrip(t *testing.T) {
	soa := SOA{
		Primary: "ns1.example.com.", Mailbox: "hostmaster.example.com.",
		Serial: 1, Refresh: 7200, Retry: 3600, Expire: 1209600, Minimum: 300,
	}
	authority := []RR{{
		Name: "example.com.", Type: TypeSOA, Class: ClassIN, TTL: 300, Data: soa,
	}}

	tests := []struct {
		name  string
		rcode uint8
	}{
		{"NODATA", RcodeSuccess},
		{"NXDOMAIN", RcodeNXDomain},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Message{
				Header: Header{
					ID: 5, Response: true, RecursionDesired: true,
					RecursionAvailable: true, Rcode: tt.rcode,
				},
				Questions: []Question{{Name: "example.com.", Type: TypeAAAA, Class: ClassIN}},
				Authority: authority,
			}
			buf, err := m.Pack()
			if err != nil {
				t.Fatalf("Pack() = %v", err)
			}
			back, err := Unpack(buf)
			if err != nil {
				t.Fatalf("Unpack() = %v", err)
			}
			if back.Header.Rcode != tt.rcode {
				t.Errorf("rcode = %d, want %d", back.Header.Rcode, tt.rcode)
			}
			if len(back.Answers) != 0 {
				t.Errorf("got %d answers, want none", len(back.Answers))
			}
			if got, ok := back.Authority[0].Data.(SOA); !ok || got != soa {
				t.Errorf("authority rdata = %#v, want %#v", back.Authority[0].Data, soa)
			}
		})
	}
}
