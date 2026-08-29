package cli

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/DevInIndia/hollow/internal/resolver"
	"github.com/DevInIndia/hollow/internal/wire"
)

func TestRdataText(t *testing.T) {
	tests := map[string]struct {
		data wire.RData
		want string
	}{
		"A":     {wire.A{Addr: netip.MustParseAddr("192.0.2.1")}, "192.0.2.1"},
		"AAAA":  {wire.AAAA{Addr: netip.MustParseAddr("2001:db8::1")}, "2001:db8::1"},
		"NS":    {wire.NS{Host: "ns1.example.com."}, "ns1.example.com."},
		"CNAME": {wire.CNAME{Target: "www.example.com."}, "www.example.com."},
		"PTR":   {wire.PTR{Target: "host.example.com."}, "host.example.com."},
		"MX":    {wire.MX{Preference: 10, Exchange: "mail.example.com."}, "10 mail.example.com."},
		"SRV":   {wire.SRV{Priority: 1, Weight: 5, Port: 443, Target: "svc.example.com."}, "1 5 443 svc.example.com."},
		"SOA": {
			wire.SOA{Primary: "ns1.example.com.", Mailbox: "hostmaster.example.com.", Serial: 7, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 300},
			"ns1.example.com. hostmaster.example.com. 7 3600 600 604800 300",
		},
		// The boundary between character-strings is what SPF and DKIM parse on,
		// so it has to survive into the output as two quoted strings.
		"TXT with two strings": {wire.TXT{Strings: []string{"v=spf1", "-all"}}, `"v=spf1" "-all"`},
		// RFC 3597 syntax, so an unfamiliar record comes out in a form a zone
		// file would accept rather than as a placeholder.
		"unknown type": {wire.Unknown{Kind: 99, Data: []byte{0xde, 0xad, 0xbe, 0xef}}, `\# 4 deadbeef`},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := rdataText(tc.data); got != tc.want {
				t.Errorf("rdataText() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestQuote(t *testing.T) {
	tests := map[string]string{
		"plain":              `"plain"`,
		`say "hi"`:           `"say \"hi\""`,
		`back\slash`:         `"back\\slash"`,
		"tab\there":          `"tab\009here"`,
		"caf\xc3\xa9":        `"caf\195\169"`,
		"\x00at the front":   `"\000at the front"`,
		"":                   `""`,
		"~ is the last one ": `"~ is the last one "`,
	}
	for in, want := range tests {
		if got := quote(in); got != want {
			t.Errorf("quote(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestFlagNames(t *testing.T) {
	tests := map[string]struct {
		h    wire.Header
		want string
	}{
		"a typical recursive answer": {
			wire.Header{Response: true, RecursionDesired: true, RecursionAvailable: true},
			" qr rd ra",
		},
		"a truncated authoritative answer": {
			wire.Header{Response: true, Authoritative: true, Truncated: true},
			" qr aa tc",
		},
		"a query": {wire.Header{}, ""},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := flagNames(tc.h); got != tc.want {
				t.Errorf("flagNames() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRcodeName(t *testing.T) {
	tests := map[uint8]string{
		wire.RcodeSuccess:  "NOERROR",
		wire.RcodeNXDomain: "NXDOMAIN",
		wire.RcodeRefused:  "REFUSED",
		11:                 "RCODE11",
	}
	for in, want := range tests {
		if got := rcodeName(in); got != want {
			t.Errorf("rcodeName(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestWriteDig(t *testing.T) {
	q := wire.Question{Name: "example.com.", Type: wire.TypeA, Class: wire.ClassIN}
	m := &wire.Message{
		Header: wire.Header{
			ID:                 0x2a2a,
			Response:           true,
			RecursionDesired:   true,
			RecursionAvailable: true,
		},
		Questions: []wire.Question{q},
		Answers: []wire.RR{{
			Name: "example.com.", Type: wire.TypeA, Class: wire.ClassIN, TTL: 300,
			Data: wire.A{Addr: netip.MustParseAddr("192.0.2.1")},
		}},
	}
	m.SetEDNS(wire.EDNS{UDPSize: wire.DefaultUDPSize})

	var out strings.Builder
	reply := &resolver.Reply{
		Msg:      m,
		Server:   netip.MustParseAddrPort("192.0.2.53:53"),
		Protocol: "udp",
		Size:     61,
		RTT:      24 * time.Millisecond,
	}
	if err := writeDig(&out, reply, q); err != nil {
		t.Fatalf("writeDig() = %v", err)
	}
	got := out.String()

	// Asserting on the whole rendering would break on every spacing change and
	// teach nothing. These are the lines that carry meaning.
	want := []string{
		"; <<>> hollow <<>> example.com. A",
		";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 10794",
		";; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1",
		"; EDNS: version: 0, flags:; udp: 1232",
		";; ANSWER SECTION:",
		";; Query time: 24 ms",
		";; SERVER: 192.0.2.53#53 (udp)",
		";; MSG SIZE  rcvd: 61",
	}
	for _, line := range want {
		if !strings.Contains(got, line) {
			t.Errorf("output is missing %q\n%s", line, got)
		}
	}

	// The OPT record belongs in the pseudo-section and nowhere else: its class
	// and TTL fields hold a payload size and a version, so rendering it as an
	// ordinary record would print two numbers that mean something else.
	if strings.Contains(got, "ADDITIONAL SECTION:") {
		t.Errorf("the OPT record was printed as an ordinary record\n%s", got)
	}
	if !strings.Contains(got, "OPT PSEUDOSECTION:") {
		t.Errorf("the OPT record was not printed at all\n%s", got)
	}
}

func TestWriteJSON(t *testing.T) {
	q := wire.Question{Name: "example.com.", Type: wire.TypeA, Class: wire.ClassIN}
	m := &wire.Message{
		Header: wire.Header{
			ID:                 0x1234,
			Response:           true,
			RecursionDesired:   true,
			RecursionAvailable: true,
		},
		Questions: []wire.Question{q},
		Answers: []wire.RR{{
			Name: "example.com.", Type: wire.TypeA, Class: wire.ClassIN, TTL: 300,
			Data: wire.A{Addr: netip.MustParseAddr("192.0.2.1")},
		}},
	}
	var out strings.Builder
	reply := &resolver.Reply{
		Msg:      m,
		Server:   netip.MustParseAddrPort("192.0.2.53:53"),
		Protocol: "udp",
		Size:     61,
		RTT:      20 * time.Millisecond,
	}
	if err := writeJSON(&out, reply, q); err != nil {
		t.Fatalf("writeJSON() = %v", err)
	}
	got := out.String()
	for _, expectedKey := range []string{`"header":`, `"question":`, `"answers":`, `"queryTimeMs":`, `"192.0.2.1"`} {
		if !strings.Contains(got, expectedKey) {
			t.Errorf("JSON output missing %s\n%s", expectedKey, got)
		}
	}
}
