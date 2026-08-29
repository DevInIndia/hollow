package roothints

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/DevInIndia/hollow/internal/wire"
)

func TestBuiltinShape(t *testing.T) {
	got := Builtin()
	if len(got) != 13 {
		t.Fatalf("Builtin() has %d servers, want the 13 letters a through m", len(got))
	}
	seen := make(map[wire.Name]bool)
	for i, s := range got {
		if !strings.HasSuffix(string(s.Name), ".root-servers.net.") {
			t.Errorf("server %d name = %q, want a .root-servers.net. name", i, s.Name)
		}
		if seen[s.Name] {
			t.Errorf("server %d name %q appears twice", i, s.Name)
		}
		seen[s.Name] = true

		// Every root answers on both families. A zero address here means a
		// transcription slip, and it would show up as a dial to 0.0.0.0.
		if !s.V4.IsValid() || !s.V4.Is4() {
			t.Errorf("%s V4 = %v, want a valid IPv4 address", s.Name, s.V4)
		}
		if !s.V6.IsValid() || !s.V6.Is6() || s.V6.Is4In6() {
			t.Errorf("%s V6 = %v, want a valid IPv6 address", s.Name, s.V6)
		}
	}
}

// The addresses are data, and data copied by hand is data that can be copied
// wrong. These are the three that a stale source is most likely to get wrong,
// pinned against the IANA table verified 2026-08-27.
func TestBuiltinAddresses(t *testing.T) {
	byName := make(map[wire.Name]Server)
	for _, s := range Builtin() {
		byName[s.Name] = s
	}
	for _, tc := range []struct {
		name wire.Name
		v4   string
	}{
		// b moved here in 2023. Copies predating that carry 192.228.79.201,
		// which is the single most common way this table goes stale.
		{"b.root-servers.net.", "170.247.170.2"},
		{"a.root-servers.net.", "198.41.0.4"},
		{"m.root-servers.net.", "202.12.27.33"},
	} {
		if got := byName[tc.name].V4; got != netip.MustParseAddr(tc.v4) {
			t.Errorf("%s V4 = %v, want %s", tc.name, got, tc.v4)
		}
	}
}

func TestBuiltinIsACopy(t *testing.T) {
	first := Builtin()
	first[0].V4 = netip.MustParseAddr("127.0.0.1")
	if second := Builtin(); second[0].V4 == first[0].V4 {
		t.Fatal("mutating the result of Builtin() changed what the next call returns")
	}
}

// The real named.root, abridged, with the shapes that actually appear in it:
// an NS record to ignore, a comment, mixed case, and A and AAAA lines that are
// not adjacent.
const namedRoot = `
;       This file holds the information on root name servers.
;
.                        3600000      NS    A.ROOT-SERVERS.NET.
A.ROOT-SERVERS.NET.      3600000      A     198.41.0.4
.                        3600000      NS    B.ROOT-SERVERS.NET.
B.ROOT-SERVERS.NET.      3600000      A     170.247.170.2
A.ROOT-SERVERS.NET.      3600000      AAAA  2001:503:ba3e::2:30
B.ROOT-SERVERS.NET.      3600000      AAAA  2801:1b8:10::b
`

func TestParse(t *testing.T) {
	got, err := Parse(strings.NewReader(namedRoot))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("Parse() returned %d servers, want 2", len(got))
	}
	// Lowercased on the way in, so a hints file shouting does not produce a
	// name that fails to match the one a referral hands back.
	if got[0].Name != "a.root-servers.net." {
		t.Errorf("server 0 name = %q, want it folded to lower case", got[0].Name)
	}
	// The AAAA line sits four lines below the A line, so this fails if the
	// parser keys on adjacency rather than on the owner name.
	if got[0].V4 != netip.MustParseAddr("198.41.0.4") || got[0].V6 != netip.MustParseAddr("2001:503:ba3e::2:30") {
		t.Errorf("server 0 = %v / %v, want both families joined by owner name", got[0].V4, got[0].V6)
	}
	if got[1].V4 != netip.MustParseAddr("170.247.170.2") {
		t.Errorf("server 1 V4 = %v, want 170.247.170.2", got[1].V4)
	}
}

func TestParseAcceptsExplicitClass(t *testing.T) {
	// A zone file may or may not spell the class. Both are legal and both
	// appear in the wild, so the type is not at a fixed field index.
	got, err := Parse(strings.NewReader("a.root-servers.net. 3600000 IN A 198.41.0.4\n"))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(got) != 1 || got[0].V4 != netip.MustParseAddr("198.41.0.4") {
		t.Fatalf("Parse() = %+v, want the address read past the IN class", got)
	}
}

func TestParseRejections(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want error
	}{
		{"empty", "", ErrNoServers},
		{"only NS records", ".  3600000  NS  A.ROOT-SERVERS.NET.\n", ErrNoServers},
		{"only comments", "; nothing here\n; nor here\n", ErrNoServers},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(tc.in)); !errors.Is(err, tc.want) {
				t.Fatalf("Parse() error = %v, want %v", err, tc.want)
			}
		})
	}
}

// A hints file that files an IPv6 address under A describes a server that
// cannot be reached the way the record says to reach it. Taking the address at
// face value would build a Server whose V4 field is not v4, and the dial would
// fail somewhere with much less context than this.
func TestParseRejectsFamilyMismatch(t *testing.T) {
	for _, in := range []string{
		"a.root-servers.net. 3600000 A 2001:503:ba3e::2:30\n",
		"a.root-servers.net. 3600000 AAAA 198.41.0.4\n",
	} {
		if _, err := Parse(strings.NewReader(in)); err == nil {
			t.Errorf("Parse(%q) succeeded, want a family mismatch rejected", in)
		}
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	for _, in := range []string{
		"a.root-servers.net. 3600000 A 198.41.0.999\n",
		"a.root-servers.net. 3600000 A not-an-address\n",
	} {
		if _, err := Parse(strings.NewReader(in)); err == nil {
			t.Errorf("Parse(%q) succeeded, want a malformed address rejected", in)
		}
	}
}

func TestAddrsPrefersIPv4(t *testing.T) {
	in := []Server{
		{Name: "a.", V4: netip.MustParseAddr("198.41.0.4"), V6: netip.MustParseAddr("2001:503:ba3e::2:30")},
		{Name: "b.", V6: netip.MustParseAddr("2801:1b8:10::b")},
		{Name: "c.", V4: netip.MustParseAddr("192.33.4.12")},
	}
	got := Addrs(in, 53)
	if len(got) != 4 {
		t.Fatalf("Addrs() returned %d addresses, want 4", len(got))
	}
	// Every v4 address must precede every v6 one, since the ordering is the
	// whole point: v6 is a fallback, not an equal choice.
	for i, ap := range got {
		if i < 2 != ap.Addr().Is4() {
			t.Fatalf("Addrs() = %v, want both IPv4 addresses before either IPv6 one", got)
		}
	}
	if got[0].Port() != 53 {
		t.Errorf("port = %d, want 53", got[0].Port())
	}
}

func TestAddrsSkipsZeroValues(t *testing.T) {
	// A Server with neither family is what a hints file with an NS record and
	// no glue produces. It must contribute nothing rather than 0.0.0.0:53.
	if got := Addrs([]Server{{Name: "a."}}, 53); len(got) != 0 {
		t.Fatalf("Addrs() = %v, want nothing for a server with no addresses", got)
	}
}
