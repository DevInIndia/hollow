package blocklist

import (
	"net/netip"
	"strings"

	"github.com/DevInIndia/hollow/internal/wire"
)

// preamble is the set of names that open a hosts file and that must never be
// blocked.
//
// This is the trap in the whole feature and it is the first thing in the file.
// The StevenBlack list, which is the one nearly everybody loads, begins:
//
//	127.0.0.1 localhost
//	127.0.0.1 localhost.localdomain
//	127.0.0.1 local
//	255.255.255.255 broadcasthost
//	::1 localhost
//
// A parser that takes field two ingests every one of them, and a resolver that
// blocks localhost breaks the machine it is running on. Filtering the literal
// string "localhost" is not enough, since localhost.localdomain, local and
// broadcasthost all get past it.
//
// The ip6- names are here for the same reason. They are not in the StevenBlack
// preamble but they are in the default /etc/hosts on Debian and Ubuntu, and
// pointing --block at /etc/hosts is a thing a person will try.
var preamble = map[string]struct{}{
	"localhost.":             {},
	"localhost.localdomain.": {},
	"local.":                 {},
	"broadcasthost.":         {},
	"ip6-localhost.":         {},
	"ip6-loopback.":          {},
	"ip6-localnet.":          {},
	"ip6-mcastprefix.":       {},
	"ip6-allnodes.":          {},
	"ip6-allrouters.":        {},
	"ip6-allhosts.":          {},
}

// entry is one parsed rule.
type entry struct {
	name     wire.Name // folded, canonical, trailing dot
	wildcard bool      // the name and everything under it
}

// parseLine turns one line of a list into zero or more rules.
//
// Zero is the ordinary case for comments, blank lines and the preamble, and is
// not an error. The bool reports whether the line was understood at all, which
// is what separates "nothing to add" from "this line was not in any format I
// know", so that only the second is counted as skipped.
func parseLine(line string) ([]entry, bool) {
	line = strip(line)
	if line == "" {
		return nil, true
	}

	if rest, ok := strings.CutPrefix(line, "||"); ok {
		return parseABP(rest)
	}

	fields := strings.Fields(line)
	switch {
	case len(fields) == 1:
		// Domain-only format.
		return collect(fields[0:1], false)
	case len(fields) > 1:
		// Hosts format. Field one is an address and the rest are names for it.
		//
		// It is parsed as an address rather than matched against "0.0.0.0" and
		// "127.0.0.1", because the preamble's last line is an IPv6 literal and
		// anything assuming a dotted quad there mis-reads it. What the address
		// actually is does not matter: a list saying a name resolves to a null
		// route and a list saying it resolves to loopback are both saying the
		// name should not resolve.
		if _, err := netip.ParseAddr(fields[0]); err != nil {
			return nil, false
		}
		return collect(fields[1:], false)
	}
	return nil, false
}

// parseABP handles the adblock form, which is "||domain^" and blocks the domain
// with everything under it.
//
// The wider adblock syntax is deliberately not implemented. Element hiding,
// regular expression rules, the @@ exception form and the option suffixes after
// $ all mean things a DNS resolver cannot express, and a half-honoured filter
// rule is worse than one that was visibly skipped. The StevenBlack list contains
// no adblock lines at all, so this path exists for user-supplied lists rather
// than for the common case.
func parseABP(rest string) ([]entry, bool) {
	name, _, ok := strings.Cut(rest, "^")
	if !ok {
		// "||example.com" without the separator. Rejected rather than guessed
		// at, because in adblock syntax the caret is what ends the domain, and a
		// line missing it may be a rule whose meaning is not what it looks like.
		return nil, false
	}
	if name == "" {
		return nil, false
	}
	return collect([]string{name}, true)
}

// collect normalises candidate names into rules, dropping the ones that must
// never become rules.
func collect(names []string, wildcard bool) ([]entry, bool) {
	var out []entry
	for _, raw := range names {
		// An address in the name position. Hosts files contain lines like
		// "0.0.0.0 0.0.0.0", and a name that is an address is not a name.
		if _, err := netip.ParseAddr(raw); err == nil {
			continue
		}

		n, err := wire.ParseName(raw)
		if err != nil {
			return nil, false
		}
		if n == wire.Root {
			// A rule on the root blocks every name there is. Whatever the line
			// meant, it did not mean that.
			continue
		}
		n = n.Fold()
		if _, bad := preamble[string(n)]; bad {
			continue
		}
		out = append(out, entry{name: n, wildcard: wildcard})
	}
	return out, true
}

// strip removes comments and surrounding space.
//
// A '#' cannot appear in a domain name in any of these formats, so cutting at
// the first one is safe wherever it appears. '!' is an adblock comment marker
// and is only a comment at the start of a line.
func strip(line string) string {
	if before, _, ok := strings.Cut(line, "#"); ok {
		line = before
	}
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "!") {
		return ""
	}
	return line
}
