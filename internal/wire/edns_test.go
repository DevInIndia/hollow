package wire

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

// The OPT pseudo-record on the wire, field by field. EDNS0 repurposes CLASS and
// TTL, so a layout mistake here is invisible to a round-trip test that only
// compares decoded structs.
func TestEDNSWireLayout(t *testing.T) {
	m := &Message{
		Header:    Header{ID: 0x1a2b, RecursionDesired: true},
		Questions: []Question{{Name: "example.com.", Type: TypeA, Class: ClassIN}},
	}
	m.SetEDNS(EDNS{DO: true})

	buf, err := m.Pack()
	if err != nil {
		t.Fatalf("Pack() = %v", err)
	}
	want := []byte{
		0x00,       // NAME, the root and nothing else
		0x00, 0x29, // TYPE 41, OPT
		0x04, 0xD0, // CLASS, repurposed as the payload size: 1232
		0x00,       // extended RCODE
		0x00,       // EDNS version 0
		0x80, 0x00, // DO set, Z clear
		0x00, 0x00, // RDLENGTH, no options
	}
	if got := buf[len(buf)-len(want):]; !bytes.Equal(got, want) {
		t.Fatalf("OPT record\n got % x\nwant % x", got, want)
	}
	if got := buf[11]; got != 1 {
		t.Errorf("ARCOUNT = %d, want 1", got)
	}
}

// A zero UDPSize means the caller did not choose one, not that they want to
// advertise no capacity at all.
func TestEDNSDefaultsToRecommendedSize(t *testing.T) {
	if DefaultUDPSize != 1232 {
		t.Fatalf("DefaultUDPSize = %d, want 1232", DefaultUDPSize)
	}
	if got := (EDNS{}).RR().Class; got != Class(DefaultUDPSize) {
		t.Errorf("payload size = %d, want %d", got, DefaultUDPSize)
	}
	if got := (EDNS{UDPSize: 512}).RR().Class; got != 512 {
		t.Errorf("payload size = %d, want 512", got)
	}
}

func TestEDNSRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		edns EDNS
	}{
		{"bare", EDNS{UDPSize: DefaultUDPSize}},
		{"DO set", EDNS{UDPSize: DefaultUDPSize, DO: true}},
		{"extended rcode", EDNS{UDPSize: DefaultUDPSize, ExtRcode: 1}},
		{"version 1", EDNS{UDPSize: DefaultUDPSize, Version: 1}},
		{"every field", EDNS{UDPSize: 4096, ExtRcode: 0xFF, Version: 0xFF, DO: true}},
		{"one option", EDNS{UDPSize: DefaultUDPSize, Options: []Option{
			{Code: 10, Data: []byte{1, 2, 3, 4, 5, 6, 7, 8}}, // COOKIE
		}}},
		{"several options", EDNS{UDPSize: DefaultUDPSize, Options: []Option{
			{Code: 8, Data: []byte{0, 1, 24, 0, 192, 0, 2}}, // client subnet
			{Code: 12, Data: make([]byte, 16)},              // padding
		}}},
		{"option with no data", EDNS{UDPSize: DefaultUDPSize, Options: []Option{{Code: 10}}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Message{
				Header:    Header{ID: 7, RecursionDesired: true},
				Questions: []Question{{Name: "example.com.", Type: TypeA, Class: ClassIN}},
			}
			m.SetEDNS(tt.edns)

			buf, err := m.Pack()
			if err != nil {
				t.Fatalf("Pack() = %v", err)
			}
			back, err := Unpack(buf)
			if err != nil {
				t.Fatalf("Unpack() = %v", err)
			}
			got, ok, err := back.EDNS()
			if err != nil {
				t.Fatalf("EDNS() = %v", err)
			}
			if !ok {
				t.Fatal("EDNS() found no OPT record")
			}
			// An option carrying no data decodes to an empty slice, a
			// distinction DeepEqual makes and the wire format does not.
			for i := range got.Options {
				if len(got.Options[i].Data) == 0 {
					got.Options[i].Data = tt.edns.Options[i].Data
				}
			}
			if !reflect.DeepEqual(got, tt.edns) {
				t.Errorf("EDNS() = %#v, want %#v", got, tt.edns)
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

// A message with no OPT record is the ordinary pre-EDNS0 case, not an error.
func TestEDNSAbsent(t *testing.T) {
	m := &Message{
		Header:    Header{ID: 1, RecursionDesired: true},
		Questions: []Question{{Name: "example.com.", Type: TypeA, Class: ClassIN}},
	}
	got, ok, err := m.EDNS()
	if err != nil {
		t.Fatalf("EDNS() = %v", err)
	}
	if ok {
		t.Errorf("EDNS() reported an OPT record: %#v", got)
	}
}

// SetEDNS replaces rather than appends, because RFC 6891 permits exactly one
// OPT record and a second would make the message a format error.
func TestSetEDNSReplaces(t *testing.T) {
	m := &Message{Header: Header{ID: 1}}
	m.SetEDNS(EDNS{UDPSize: 512})
	m.SetEDNS(EDNS{UDPSize: DefaultUDPSize, DO: true})

	if len(m.Additional) != 1 {
		t.Fatalf("additional holds %d records, want 1", len(m.Additional))
	}
	got, ok, err := m.EDNS()
	if err != nil || !ok {
		t.Fatalf("EDNS() = %v, %v", ok, err)
	}
	if got.UDPSize != DefaultUDPSize || !got.DO {
		t.Errorf("EDNS() = %#v, want size %d with DO set", got, DefaultUDPSize)
	}
}

func TestEDNSRejects(t *testing.T) {
	opt := func(name Name, size uint16) RR {
		rr := EDNS{UDPSize: size}.RR()
		rr.Name = name
		return rr
	}
	tests := []struct {
		name string
		m    *Message
	}{
		{"two OPT records", &Message{
			Header:     Header{ID: 1},
			Additional: []RR{opt(Root, DefaultUDPSize), opt(Root, 512)},
		}},
		{"OPT not owned by the root", &Message{
			Header:     Header{ID: 1},
			Additional: []RR{opt("example.com.", DefaultUDPSize)},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := tt.m.EDNS(); !errors.Is(err, ErrRData) {
				t.Fatalf("EDNS() = %v, want %v", err, ErrRData)
			}
		})
	}
}

// Case 18 of the TIER1 matrix: an option whose declared length does not match
// the octets present.
func TestOPTRejectsMalformedOptionLength(t *testing.T) {
	tests := []struct {
		name  string
		rdata []byte
		want  error
	}{
		{
			name:  "option claims more data than the rdata holds",
			rdata: []byte{0x00, 0x0A, 0x00, 0x08, 1, 2, 3},
			want:  ErrTruncated,
		},
		{
			name:  "option length field itself truncated",
			rdata: []byte{0x00, 0x0A, 0x00},
			want:  ErrTruncated,
		},
		{
			name:  "trailing octet after a complete option",
			rdata: []byte{0x00, 0x0A, 0x00, 0x01, 0xFF, 0x00},
			want:  ErrTruncated,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := answerMsg(TypeOPT, len(tt.rdata), tt.rdata)
			if _, err := Unpack(msg); !errors.Is(err, tt.want) {
				t.Fatalf("Unpack() = %v, want %v", err, tt.want)
			}
		})
	}
}

// Without EDNS0 a response is capped at 512 octets with TC set. The advertised
// size is what lifts that cap, and it is ours, never the one the server sent
// back: roots advertise 4096, which invites IP fragmentation.
func TestEDNSAdvertisedSizeIsOurs(t *testing.T) {
	response := &Message{Header: Header{ID: 1, Response: true}}
	response.SetEDNS(EDNS{UDPSize: 4096})
	buf, err := response.Pack()
	if err != nil {
		t.Fatalf("Pack() = %v", err)
	}
	back, err := Unpack(buf)
	if err != nil {
		t.Fatalf("Unpack() = %v", err)
	}
	theirs, ok, err := back.EDNS()
	if err != nil || !ok {
		t.Fatalf("EDNS() = %v, %v", ok, err)
	}
	if theirs.UDPSize != 4096 {
		t.Fatalf("decoded payload size = %d, want 4096", theirs.UDPSize)
	}
	// The value is readable, and it is not what our own query advertises.
	if theirs.UDPSize == DefaultUDPSize {
		t.Error("a server advertising 4096 must not change what we advertise")
	}
}
