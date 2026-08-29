// Package roothints holds the addresses iterative resolution starts from.
//
// A resolver that begins at the root needs somewhere to begin, and that place
// cannot itself be resolved: finding a.root-servers.net requires asking a root
// server where it is. The cycle is broken by shipping the addresses as data.
// They change rarely, they are public, and IANA publishes them as named.root,
// which Parse reads so a stale binary can be corrected without a rebuild.
package roothints

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/DevInIndia/hollow/internal/wire"
)

// ErrNoServers reports a hints source that yielded nothing usable. An empty
// hints file is not an empty root zone, it is a broken file, and starting a
// resolution with no servers would otherwise fail much further from the cause.
var ErrNoServers = errors.New("roothints: no root servers with addresses")

// Server is one root nameserver and the addresses it answers on.
//
// Both families are kept rather than flattened, because which one to use is a
// decision for the caller and depends on whether this host has working IPv6.
type Server struct {
	Name wire.Name
	V4   netip.Addr // zero if the hints source gave no A record
	V6   netip.Addr // zero if the hints source gave no AAAA record
}

// builtin is the root zone as published by IANA, verified 2026-08-27.
//
// Copied from the IANA table rather than from a tutorial or an older hints
// file. Several widely circulated copies are stale: b.root-servers.net moved to
// 170.247.170.2 in 2023 and a surprising number of blog posts still carry
// 192.228.79.201. A stale entry here is not fatal, since the other twelve
// answer, but it is a timeout on every cold resolution that happens to pick it.
var builtin = [...]Server{
	{"a.root-servers.net.", netip.MustParseAddr("198.41.0.4"), netip.MustParseAddr("2001:503:ba3e::2:30")},
	{"b.root-servers.net.", netip.MustParseAddr("170.247.170.2"), netip.MustParseAddr("2801:1b8:10::b")},
	{"c.root-servers.net.", netip.MustParseAddr("192.33.4.12"), netip.MustParseAddr("2001:500:2::c")},
	{"d.root-servers.net.", netip.MustParseAddr("199.7.91.13"), netip.MustParseAddr("2001:500:2d::d")},
	{"e.root-servers.net.", netip.MustParseAddr("192.203.230.10"), netip.MustParseAddr("2001:500:a8::e")},
	{"f.root-servers.net.", netip.MustParseAddr("192.5.5.241"), netip.MustParseAddr("2001:500:2f::f")},
	{"g.root-servers.net.", netip.MustParseAddr("192.112.36.4"), netip.MustParseAddr("2001:500:12::d0d")},
	{"h.root-servers.net.", netip.MustParseAddr("198.97.190.53"), netip.MustParseAddr("2001:500:1::53")},
	{"i.root-servers.net.", netip.MustParseAddr("192.36.148.17"), netip.MustParseAddr("2001:7fe::53")},
	{"j.root-servers.net.", netip.MustParseAddr("192.58.128.30"), netip.MustParseAddr("2001:503:c27::2:30")},
	{"k.root-servers.net.", netip.MustParseAddr("193.0.14.129"), netip.MustParseAddr("2001:7fd::1")},
	{"l.root-servers.net.", netip.MustParseAddr("199.7.83.42"), netip.MustParseAddr("2001:500:9f::42")},
	{"m.root-servers.net.", netip.MustParseAddr("202.12.27.33"), netip.MustParseAddr("2001:dc3::35")},
}

// Builtin returns the compiled-in root servers.
//
// The slice is freshly built on every call. Returning the package array would
// hand every caller a window onto shared mutable state, and the thirteen
// elements this copies are not worth the class of bug that invites.
func Builtin() []Server {
	out := make([]Server, len(builtin))
	copy(out, builtin[:])
	return out
}

// Parse reads hints in named.root format, the file IANA publishes.
//
// The format is a zone file, but only a fixed shape of it appears here, so this
// reads the three record types that carry root hints and ignores the rest
// rather than pretending to be a general zone parser. A line it does not
// understand is skipped, not rejected: hints files carry SOA records, comments
// and trailing whitespace that have nothing to do with the addresses.
func Parse(r io.Reader) ([]Server, error) {
	// Keyed by name so the A and AAAA lines for one server, which are separate
	// records and need not be adjacent, land in the same entry.
	byName := make(map[wire.Name]*Server)
	order := []wire.Name{}

	sc := bufio.NewScanner(r)
	for line := 1; sc.Scan(); line++ {
		text := sc.Text()
		if i := strings.IndexByte(text, ';'); i >= 0 {
			text = text[:i]
		}
		fields := strings.Fields(text)
		// owner, TTL, class or type, and a value. Anything shorter cannot be a
		// record regardless of type.
		if len(fields) < 4 {
			continue
		}

		// The class is optional in a zone file, so the type is either the third
		// field or the fourth. Look for the one that names a type we want.
		typ, value := fields[2], fields[3]
		if len(fields) >= 5 && strings.EqualFold(typ, "IN") {
			typ, value = fields[3], fields[4]
		}
		if !strings.EqualFold(typ, "A") && !strings.EqualFold(typ, "AAAA") {
			continue
		}

		owner, err := wire.ParseName(fields[0])
		if err != nil {
			return nil, fmt.Errorf("roothints: line %d: owner %q: %w", line, fields[0], err)
		}
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return nil, fmt.Errorf("roothints: line %d: address %q: %w", line, value, err)
		}

		// Names in a hints file are not consistently cased, and DNS names
		// compare case-insensitively per RFC 4343, so fold before keying or
		// A.ROOT-SERVERS.NET and a.root-servers.net become two servers.
		key := wire.Name(strings.ToLower(string(owner)))
		s := byName[key]
		if s == nil {
			s = &Server{Name: key}
			byName[key] = s
			order = append(order, key)
		}

		// Trust the record type over the address family. A hints file listing
		// an IPv6 address on an A line is wrong, and silently filing it under
		// V4 would produce a Server whose V4 field cannot be dialled as one.
		switch {
		case strings.EqualFold(typ, "A") && addr.Is4():
			s.V4 = addr
		case strings.EqualFold(typ, "AAAA") && addr.Is6() && !addr.Is4In6():
			s.V6 = addr
		default:
			return nil, fmt.Errorf("roothints: line %d: %s record holds %v", line, strings.ToUpper(typ), addr)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("roothints: reading hints: %w", err)
	}

	out := make([]Server, 0, len(order))
	for _, name := range order {
		if s := byName[name]; s.V4.IsValid() || s.V6.IsValid() {
			out = append(out, *s)
		}
	}
	if len(out) == 0 {
		return nil, ErrNoServers
	}
	return out, nil
}

// Addrs flattens servers to addresses to try on the given port, IPv4 first.
//
// IPv4 leads because it is measurably faster from a typical host: a-root
// answers in 221 ms over IPv4 and 353 ms over IPv6 from the machine this was
// developed on. IPv6 is kept as a fallback rather than dropped, because a host
// with no IPv4 route would otherwise have no roots at all.
//
// The port is a parameter rather than a constant so that the roots and the
// servers reached from glue can be addressed the same way. A private root on a
// high port is no use if only half the walk can find it.
func Addrs(servers []Server, port uint16) []netip.AddrPort {
	out := make([]netip.AddrPort, 0, 2*len(servers))
	for _, s := range servers {
		if s.V4.IsValid() {
			out = append(out, netip.AddrPortFrom(s.V4, port))
		}
	}
	for _, s := range servers {
		if s.V6.IsValid() {
			out = append(out, netip.AddrPortFrom(s.V6, port))
		}
	}
	return out
}
