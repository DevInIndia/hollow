package wire

import (
	"bytes"
	"os"
	"reflect"
	"strings"
	"testing"
)

// Two real captures, taken from this machine before kickoff and described in
// testdata/PROVENANCE.md. Hand-built messages only prove the decoder agrees
// with the encoder; these prove it agrees with the servers actually in use.
//
// Assertions are on structure, never on addresses. example.com resolves to
// Cloudflare now rather than the long-standing 93.184.216.34, so an
// address-based assertion would rot on its own.

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	return b
}

// Fixture 1: example.com A, answered by 8.8.8.8 with RD set.
func TestGoldenExampleComA(t *testing.T) {
	raw := readFixture(t, "example-com-a.bin")
	if len(raw) != 61 {
		t.Fatalf("fixture is %d octets, want 61", len(raw))
	}

	m, err := Unpack(raw)
	if err != nil {
		t.Fatalf("Unpack() = %v", err)
	}

	if !m.Header.Response || !m.Header.RecursionDesired || !m.Header.RecursionAvailable {
		t.Errorf("flags = %+v, want QR RD RA", m.Header)
	}
	if m.Header.Truncated || m.Header.Rcode != RcodeSuccess {
		t.Errorf("TC = %v, rcode = %d; want false, 0", m.Header.Truncated, m.Header.Rcode)
	}
	if len(m.Questions) != 1 || len(m.Answers) != 2 {
		t.Fatalf("counts: QD %d AN %d, want 1 and 2", len(m.Questions), len(m.Answers))
	}
	if len(m.Authority) != 0 || len(m.Additional) != 0 {
		t.Errorf("counts: NS %d AR %d, want 0 and 0", len(m.Authority), len(m.Additional))
	}
	if q := m.Questions[0]; q.Name != "example.com." || q.Type != TypeA || q.Class != ClassIN {
		t.Errorf("question = %q %v %v, want example.com. A IN", q.Name, q.Type, q.Class)
	}

	for i, rr := range m.Answers {
		if rr.Name != "example.com." || rr.Type != TypeA || rr.TTL != 300 {
			t.Errorf("answer %d = %q %v ttl %d, want example.com. A 300", i, rr.Name, rr.Type, rr.TTL)
		}
		a, ok := rr.Data.(A)
		if !ok {
			t.Fatalf("answer %d rdata is %T, want A", i, rr.Data)
		}
		if !a.Addr.Is4() {
			t.Errorf("answer %d holds %v, want an IPv4 address", i, a.Addr)
		}
	}

	// The answer names are the simplest possible compression pointer, back to
	// the question name at offset 12. Our encoder chooses the same target, so
	// this capture re-encodes to the octets it arrived as.
	again, err := m.Pack()
	if err != nil {
		t.Fatalf("Pack() = %v", err)
	}
	if !bytes.Equal(raw, again) {
		t.Fatalf("re-encode differs from the capture\n got % x\nwant % x", again, raw)
	}
}

// Fixture 2: com. NS asked of a.root-servers.net with RD clear. Structurally
// valid but truncated, which is what makes it worth keeping.
func TestGoldenComNSReferral(t *testing.T) {
	raw := readFixture(t, "com-ns-referral.bin")
	if len(raw) != 509 {
		t.Fatalf("fixture is %d octets, want 509", len(raw))
	}

	m, err := Unpack(raw)
	if err != nil {
		t.Fatalf("Unpack() = %v", err)
	}

	// TC set with RCODE 0: the server cut the response to fit 512 octets
	// rather than failing. Reading this as an error would be wrong.
	if !m.Header.Response || !m.Header.Truncated {
		t.Errorf("flags = %+v, want QR and TC", m.Header)
	}
	if m.Header.RecursionDesired || m.Header.Authoritative {
		t.Errorf("RD = %v, AA = %v; a root referral has neither",
			m.Header.RecursionDesired, m.Header.Authoritative)
	}
	if m.Header.Rcode != RcodeSuccess {
		t.Errorf("rcode = %d, want 0", m.Header.Rcode)
	}
	if len(m.Questions) != 1 || len(m.Answers) != 0 {
		t.Fatalf("counts: QD %d AN %d, want 1 and 0", len(m.Questions), len(m.Answers))
	}
	if len(m.Authority) != 13 || len(m.Additional) != 12 {
		t.Fatalf("counts: NS %d AR %d, want 13 and 12", len(m.Authority), len(m.Additional))
	}
	if q := m.Questions[0]; q.Name != "com." || q.Type != TypeNS {
		t.Errorf("question = %q %v, want com. NS", q.Name, q.Type)
	}

	// No answer section and no OPT: the query carried no EDNS0, which is
	// exactly why the response had to be truncated at 512 octets.
	if _, ok, err := m.EDNS(); err != nil || ok {
		t.Errorf("EDNS() = %v, %v; the query carried no OPT record", ok, err)
	}

	for i, rr := range m.Authority {
		if rr.Name != "com." || rr.Type != TypeNS || rr.TTL != 172800 {
			t.Errorf("authority %d = %q %v ttl %d, want com. NS 172800", i, rr.Name, rr.Type, rr.TTL)
		}
		ns, ok := rr.Data.(NS)
		if !ok {
			t.Fatalf("authority %d rdata is %T, want NS", i, rr.Data)
		}
		if !strings.HasSuffix(string(ns.Host), ".gtld-servers.net.") {
			t.Errorf("authority %d host = %q, want a gtld-servers.net name", i, ns.Host)
		}
	}

	var v4, v6 int
	for i, rr := range m.Additional {
		switch d := rr.Data.(type) {
		case A:
			v4++
			if !d.Addr.Is4() {
				t.Errorf("additional %d holds %v under an A record", i, d.Addr)
			}
		case AAAA:
			v6++
			if !d.Addr.Is6() {
				t.Errorf("additional %d holds %v under an AAAA record", i, d.Addr)
			}
		default:
			t.Errorf("additional %d rdata is %T, want glue", i, rr.Data)
		}
	}
	if v4 == 0 || v6 == 0 {
		t.Errorf("glue: %d A and %d AAAA, want both families", v4, v6)
	}
}

// The single highest-value case in the fixture set: a fresh one-octet label
// followed by a pointer into the middle of a name that was itself reached by an
// earlier pointer. A resolver that expands only one level of pointer gets this
// wrong, and it is silent when it does.
func TestGoldenSuffixSharingAcrossCompressedName(t *testing.T) {
	raw := readFixture(t, "com-ns-referral.bin")
	if !bytes.Contains(raw, []byte{0x01, 0x6a, 0xc0, 0x23}) {
		t.Fatal("fixture no longer holds the 01 6a c0 23 sequence this test exists for")
	}

	m, err := Unpack(raw)
	if err != nil {
		t.Fatalf("Unpack() = %v", err)
	}
	var found bool
	for _, rr := range m.Authority {
		if ns, ok := rr.Data.(NS); ok && ns.Host == "j.gtld-servers.net." {
			found = true
		}
	}
	if !found {
		var got []Name
		for _, rr := range m.Authority {
			got = append(got, rr.Data.(NS).Host)
		}
		t.Fatalf("j.gtld-servers.net. did not decode; authority holds %q", got)
	}
}

// A captured message survives a decode and re-encode with its meaning intact.
// The octets are allowed to differ, because our encoder picks its own
// compression targets, but nothing may be lost or invented.
func TestGoldenReencodeIsStable(t *testing.T) {
	for _, name := range []string{"example-com-a.bin", "com-ns-referral.bin"} {
		t.Run(name, func(t *testing.T) {
			first, err := Unpack(readFixture(t, name))
			if err != nil {
				t.Fatalf("Unpack() = %v", err)
			}
			buf, err := first.Pack()
			if err != nil {
				t.Fatalf("Pack() = %v", err)
			}
			second, err := Unpack(buf)
			if err != nil {
				t.Fatalf("Unpack() after re-encode = %v", err)
			}
			if !reflect.DeepEqual(first, second) {
				t.Error("re-encoding changed the message")
			}
			// And the second encode is a fixed point of the first.
			again, err := second.Pack()
			if err != nil {
				t.Fatalf("re-Pack() = %v", err)
			}
			if !bytes.Equal(buf, again) {
				t.Errorf("encoding is not stable\n got % x\nwant % x", again, buf)
			}
		})
	}
}
