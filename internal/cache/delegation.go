package cache

import (
	"net/netip"
	"time"

	"github.com/DevInIndia/hollow/internal/wire"
)

// delegationEntries is the delegation cache's capacity, sized separately from
// the answer cache because the two hold different populations. Answers are as
// many as there are names asked for; delegations are as many as there are zones
// on the path to them, which is a far smaller and far more reused set. Ten
// thousand covers every top-level domain several times over.
const delegationEntries = 10000

// delegationEntry is a zone cut and the addresses that answer for the child.
type delegationEntry struct {
	// zone is the child zone name with the case it arrived in. The map key is
	// the folded form; this is what gets handed back, so that a walk resumed
	// from the cache carries the same name a walk from the root would have.
	zone wire.Name

	servers []netip.AddrPort
}

// StoreDelegation records that zone is served by servers, for ttl seconds.
//
// Only pass a delegation that has already been checked for bailiwick. This is
// the sharpest edge in the package: a cached delegation redirects every future
// query for the whole subtree, so a referral that was accepted without
// verification here is not one wrong answer, it is a persistent redirection of a
// zone. The check runs at the referral, not at the read, so what is stored must
// already have passed it.
func (c *Cache) StoreDelegation(zone wire.Name, servers []netip.AddrPort, ttl uint32) {
	if len(servers) == 0 || ttl == 0 || zone == "" || zone == wire.Root {
		return
	}
	ttl = c.clamp(ttl)
	e := &delegationEntry{zone: zone, servers: append([]netip.AddrPort(nil), servers...)}
	now := time.Now()
	c.delegations.put(zone.Fold(), e, now, now.Add(time.Duration(ttl)*time.Second))
}

// Delegation returns the deepest cached zone cut enclosing name, along with the
// servers that answer for it.
//
// This is what turns the cache from a lookup table into a shortcut. A resolver
// that caches only answers still starts every unseen name at the root, so a
// thousand hosts under one zone cost a thousand walks through root and com. With
// the cuts remembered, the second name under a zone starts at that zone.
//
// The walk is over labels rather than string suffixes, which Name.Suffixes
// guarantees. The distinction is a security one and not a nicety: a dot inside a
// label is escaped, so the single-label name "evil\.com." ends in the bytes
// "com." without being inside com, and a match on bytes would hand an attacker's
// name the delegation for a real zone.
func (c *Cache) Delegation(name wire.Name) (wire.Name, []netip.AddrPort, bool) {
	now := time.Now()
	// Suffixes runs from the name itself outward, so the first hit is the
	// deepest one and the walk stops as soon as it finds anything.
	for _, suffix := range name.Suffixes() {
		sl, ok := c.delegations.get(suffix.Fold())
		if !ok || !now.Before(sl.expires) {
			continue
		}
		// Copied because the resolver reorders the candidates it is given, and
		// a shared backing array would let one resolution shuffle the addresses
		// every later resolution reads.
		return sl.value.zone, append([]netip.AddrPort(nil), sl.value.servers...), true
	}
	return "", nil, false
}
