package blocklist

import (
	"testing"

	"github.com/DevInIndia/hollow/internal/wire"
)

func query(t *testing.T, n string, typ wire.Type) *wire.Message {
	t.Helper()
	return &wire.Message{
		Header:    wire.Header{ID: 0x1234, RecursionDesired: true},
		Questions: []wire.Question{{Name: name(t, n), Type: typ, Class: wire.ClassIN}},
	}
}

// existence is what an answer claims about the name, which is the property the
// modes have to keep consistent across query types.
type existence int

const (
	exists existence = iota
	doesNotExist
)

func claim(t *testing.T, m *wire.Message) existence {
	t.Helper()
	if m.Header.Rcode == wire.RcodeNXDomain {
		return doesNotExist
	}
	return exists
}

func (e existence) String() string {
	if e == exists {
		return "the name exists"
	}
	return "the name does not exist"
}

// TestEveryModeSaysTheSameThingAboutTheNameWhateverIsAsked is the test the
// block modes exist for.
//
// A browser asks A and AAAA for the same name at the same time, and increasingly
// HTTPS beside them. If the A answer is 0.0.0.0 and the AAAA is NXDOMAIN, the
// resolver has told one client two incompatible things about one name inside a
// few milliseconds, and what the client does with that is undefined and looks
// intermittent from the outside.
func TestEveryModeSaysTheSameThingAboutTheNameWhateverIsAsked(t *testing.T) {
	types := []struct {
		name string
		typ  wire.Type
	}{
		{"A", wire.TypeA},
		{"AAAA", wire.TypeAAAA},
		{"HTTPS", wire.Type(65)},
		{"MX", wire.TypeMX},
		{"TXT", wire.TypeTXT},
		{"SOA", wire.TypeSOA},
	}
	for _, mode := range []Mode{ModeNXDomain, ModeNull, ModeNoData} {
		t.Run(mode.String(), func(t *testing.T) {
			var first existence
			for i, tt := range types {
				got := claim(t, Reply(query(t, "ads.example.com.", tt.typ), mode))
				if i == 0 {
					first = got
					continue
				}
				if got != first {
					t.Errorf("%s says %v but %s says %v", types[0].name, first, tt.name, got)
				}
			}
		})
	}
}

func TestNullModeAnswersTheAddressTypesAndNoDatasTheRest(t *testing.T) {
	m := Reply(query(t, "ads.example.com.", wire.TypeA), ModeNull)
	if len(m.Answers) != 1 {
		t.Fatalf("A answer count = %d, want 1", len(m.Answers))
	}
	a, ok := m.Answers[0].Data.(wire.A)
	if !ok {
		t.Fatalf("A answer rdata is %T, want wire.A", m.Answers[0].Data)
	}
	if a.Addr.String() != "0.0.0.0" {
		t.Errorf("A = %s, want 0.0.0.0", a.Addr)
	}

	m = Reply(query(t, "ads.example.com.", wire.TypeAAAA), ModeNull)
	if len(m.Answers) != 1 {
		t.Fatalf("AAAA answer count = %d, want 1", len(m.Answers))
	}
	q, ok := m.Answers[0].Data.(wire.AAAA)
	if !ok {
		t.Fatalf("AAAA answer rdata is %T, want wire.AAAA", m.Answers[0].Data)
	}
	if q.Addr.String() != "::" {
		t.Errorf("AAAA = %s, want ::", q.Addr)
	}

	// Every other type is NODATA, never NXDOMAIN, because the A answer above
	// already asserted the name exists.
	m = Reply(query(t, "ads.example.com.", wire.TypeMX), ModeNull)
	if m.Header.Rcode != wire.RcodeSuccess {
		t.Errorf("MX rcode = %d, want 0", m.Header.Rcode)
	}
	if len(m.Answers) != 0 {
		t.Errorf("MX answer count = %d, want 0", len(m.Answers))
	}
}

func TestNegativeAnswersCarryAnSOASoTheyCanBeCached(t *testing.T) {
	// Without it a resolver downstream has nothing to cache the negative answer
	// against and asks again for every query, RFC 2308 section 5.
	for _, tc := range []struct {
		mode  Mode
		typ   wire.Type
		rcode uint8
	}{
		{ModeNXDomain, wire.TypeA, wire.RcodeNXDomain},
		{ModeNoData, wire.TypeA, wire.RcodeSuccess},
		{ModeNull, wire.TypeMX, wire.RcodeSuccess},
	} {
		t.Run(tc.mode.String(), func(t *testing.T) {
			m := Reply(query(t, "ads.example.com.", tc.typ), tc.mode)
			if m.Header.Rcode != tc.rcode {
				t.Errorf("rcode = %d, want %d", m.Header.Rcode, tc.rcode)
			}
			if len(m.Answers) != 0 {
				t.Errorf("answer count = %d, want 0", len(m.Answers))
			}
			if len(m.Authority) != 1 {
				t.Fatalf("authority count = %d, want 1", len(m.Authority))
			}
			soa, ok := m.Authority[0].Data.(wire.SOA)
			if !ok {
				t.Fatalf("authority rdata is %T, want wire.SOA", m.Authority[0].Data)
			}
			if soa.Minimum != blockTTL || m.Authority[0].TTL != blockTTL {
				t.Errorf("SOA minimum %d and TTL %d, want %d for both", soa.Minimum, m.Authority[0].TTL, blockTTL)
			}
			if m.Authority[0].Name != name(t, "ads.example.com.") {
				t.Errorf("SOA owner = %s, want the query name", m.Authority[0].Name)
			}
		})
	}
}

func TestABlockedReplyIsAWellFormedResponseToThisQuery(t *testing.T) {
	// The header fields a client checks before it reads a single record. Getting
	// the ID or the question wrong makes the answer invisible rather than wrong.
	for _, mode := range []Mode{ModeNXDomain, ModeNull, ModeNoData} {
		t.Run(mode.String(), func(t *testing.T) {
			q := query(t, "ads.example.com.", wire.TypeA)
			m := Reply(q, mode)

			if m.Header.ID != q.Header.ID {
				t.Errorf("ID = %d, want %d", m.Header.ID, q.Header.ID)
			}
			if !m.Header.Response {
				t.Error("QR is not set")
			}
			if !m.Header.RecursionDesired {
				t.Error("RD was not copied from the query")
			}
			if !m.Header.RecursionAvailable {
				t.Error("RA is not set, so a client may decide this is a stub")
			}
			if !m.Header.Authoritative {
				t.Error("AA is not set; nothing else in the world holds this answer")
			}
			if len(m.Questions) != 1 || m.Questions[0] != q.Questions[0] {
				t.Errorf("questions = %v, want the query's", m.Questions)
			}
			if _, ok, err := m.EDNS(); err != nil || !ok {
				t.Errorf("EDNS present = %v, err = %v; want true and nil", ok, err)
			}

			// And it survives the wire, which is the only thing the client sees.
			raw, err := m.Pack()
			if err != nil {
				t.Fatalf("Pack: %v", err)
			}
			back, err := wire.Unpack(raw)
			if err != nil {
				t.Fatalf("Unpack: %v", err)
			}
			if back.Header.Rcode != m.Header.Rcode || len(back.Answers) != len(m.Answers) {
				t.Errorf("round trip changed the answer: rcode %d, %d answers", back.Header.Rcode, len(back.Answers))
			}
		})
	}
}

func TestAQueryWithNoQuestionGetsNoAssertionAboutAName(t *testing.T) {
	m := Reply(&wire.Message{Header: wire.Header{ID: 7}}, ModeNull)
	if len(m.Answers) != 0 || len(m.Authority) != 0 {
		t.Errorf("a question-less query produced %d answers and %d authority records", len(m.Answers), len(m.Authority))
	}
	if m.Header.Rcode != wire.RcodeNXDomain {
		t.Errorf("rcode = %d, want %d", m.Header.Rcode, wire.RcodeNXDomain)
	}
}

func TestParseModeRoundTripsWithString(t *testing.T) {
	for _, mode := range []Mode{ModeNXDomain, ModeNull, ModeNoData} {
		got, err := ParseMode(mode.String())
		if err != nil || got != mode {
			t.Errorf("ParseMode(%q) = %v, %v; want %v and nil", mode.String(), got, err, mode)
		}
	}
	if _, err := ParseMode("refused"); err == nil {
		t.Error("ParseMode accepted a mode that does not exist")
	}
	if s := Mode(99).String(); s != "Mode(99)" {
		t.Errorf("Mode(99).String() = %q", s)
	}
}
