package cache

import (
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/DevInIndia/hollow/internal/wire"
)

func addrs(ss ...string) []netip.AddrPort {
	out := make([]netip.AddrPort, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddrPort(s)
	}
	return out
}

func TestDelegationReturnsTheDeepestCut(t *testing.T) {
	c := New(Config{})
	c.StoreDelegation("com.", addrs("192.0.2.1:53"), 172800)
	c.StoreDelegation("example.com.", addrs("192.0.2.2:53", "192.0.2.3:53"), 3600)

	cases := []struct {
		name string
		want wire.Name
	}{
		{"www.example.com.", "example.com."},
		{"a.b.c.example.com.", "example.com."},
		{"example.com.", "example.com."},
		{"other.com.", "com."},
		{"com.", "com."},
	}
	for _, tc := range cases {
		zone, servers, ok := c.Delegation(wire.Name(tc.name))
		if !ok {
			t.Errorf("%s: no delegation found, want %s", tc.name, tc.want)
			continue
		}
		if zone != tc.want {
			t.Errorf("%s: resumed at %s, want %s", tc.name, zone, tc.want)
		}
		if len(servers) == 0 {
			t.Errorf("%s: delegation carried no servers", tc.name)
		}
	}

	if _, _, ok := c.Delegation("example.org."); ok {
		t.Error("found a delegation for a zone that was never stored")
	}
}

// A dot inside a label is escaped, so this single-label name ends in the bytes
// "com." without being inside com. Matching on bytes would hand an attacker's
// name the delegation for a real zone, which is a persistent redirection of
// every query under it rather than one wrong answer.
func TestDelegationDoesNotMatchAnEscapedDot(t *testing.T) {
	c := New(Config{})
	c.StoreDelegation("com.", addrs("192.0.2.1:53"), 172800)

	if zone, _, ok := c.Delegation(`evil\.com.`); ok {
		t.Errorf(`evil\.com. matched the delegation for %s`, zone)
	}
	// The same name with a real parent resolves to that parent and no further.
	c.StoreDelegation(`www.evil\.com.`, addrs("192.0.2.9:53"), 3600)
	if zone, _, ok := c.Delegation(`www.evil\.com.`); !ok || zone != `www.evil\.com.` {
		t.Errorf(`www.evil\.com. resumed at %q (found=%v), want itself`, zone, ok)
	}
}

func TestDelegationExpires(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := New(Config{})
		c.StoreDelegation("com.", addrs("192.0.2.1:53"), 172800)
		c.StoreDelegation("example.com.", addrs("192.0.2.2:53"), 3600)

		time.Sleep(3601 * time.Second)
		// The child's cut has expired, so the walk falls back to the parent's
		// rather than to the root.
		zone, _, ok := c.Delegation("www.example.com.")
		if !ok || zone != "com." {
			t.Errorf("after the child expired: resumed at %q (found=%v), want com.", zone, ok)
		}

		time.Sleep(172800 * time.Second)
		if _, _, ok := c.Delegation("www.example.com."); ok {
			t.Error("a delegation outlived its TTL")
		}
	})
}

func TestDelegationCaseFoldsTheKeyAndKeepsTheName(t *testing.T) {
	c := New(Config{})
	c.StoreDelegation("ExAmPlE.CoM.", addrs("192.0.2.1:53"), 3600)

	zone, _, ok := c.Delegation("www.example.com.")
	if !ok {
		t.Fatal("a differently cased zone name missed the delegation cache")
	}
	if zone != "ExAmPlE.CoM." {
		t.Errorf("zone came back as %q, want the case it was stored with", zone)
	}
}

// The resolver reorders the candidates it is handed, so a shared backing array
// would let one resolution shuffle the addresses every later one reads.
func TestDelegationServersAreCopiedOut(t *testing.T) {
	c := New(Config{})
	original := addrs("192.0.2.1:53", "192.0.2.2:53")
	c.StoreDelegation("example.com.", original, 3600)

	// Mutating what the caller passed in must not reach the cache either.
	original[0] = netip.MustParseAddrPort("203.0.113.99:53")

	_, first, _ := c.Delegation("example.com.")
	first[0] = netip.MustParseAddrPort("198.51.100.1:53")

	_, second, ok := c.Delegation("example.com.")
	if !ok {
		t.Fatal("delegation missing")
	}
	if second[0] != netip.MustParseAddrPort("192.0.2.1:53") {
		t.Errorf("cached servers start with %v, want 192.0.2.1:53 unchanged by either mutation", second[0])
	}
}

func TestDelegationRejectsWhatCannotBeUseful(t *testing.T) {
	cases := []struct {
		name    string
		zone    wire.Name
		servers []netip.AddrPort
		ttl     uint32
		why     string
	}{
		{"no servers", "example.com.", nil, 3600, "there is nowhere to resume from"},
		{"zero TTL", "example.com.", addrs("192.0.2.1:53"), 0, "use once and forget"},
		{"the root", wire.Root, addrs("192.0.2.1:53"), 3600, "the root comes from the hints"},
		{"empty name", "", addrs("192.0.2.1:53"), 3600, "it is not a name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := New(Config{})
			c.StoreDelegation(tc.zone, tc.servers, tc.ttl)
			if n := c.Stats().Delegations; n != 0 {
				t.Errorf("stored a delegation with %s, but %s", tc.name, tc.why)
			}
		})
	}
}
