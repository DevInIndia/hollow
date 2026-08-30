package resolver

import (
	"crypto/rand"
	"net/netip"
	"sync"

	"github.com/DevInIndia/hollow/internal/wire"
)

// Casing is the DNS 0x20 defence: the case of each letter in the outgoing name
// is randomised, and a reply whose question does not echo that case exactly is
// refused.
//
// The mechanism, from draft-vixie-dnsext-dns0x20-00, works because names match
// case-insensitively while conforming servers echo the question section
// verbatim. The case pattern is therefore a nonce that an off-path attacker
// cannot see and has to guess, on top of the transaction ID and the source
// port. It never became a standard, and it is implemented by Google Public DNS
// and by c-ares, which is the company it keeps.
//
// What it buys, measured in bits an attacker must guess at once: 16 from the
// transaction ID, about 15 from the ephemeral source port the kernel picks, and
// one per letter in the name. That is 41 bits for example.com and 44 for
// www.example.com, against the roughly 32 available without it. A short name is
// the weak case and stays weak: a.io reaches 34.
//
// Not every server conforms. Some echo the question lowercased, and a hard
// refusal with no way back would make this resolver fail against real
// infrastructure. Such a server is recorded here after one clean attempt and
// asked without randomisation from then on.
//
// The zero value is not usable; New builds one. A Casing is shared by every
// copy of a Transport that was made from the one holding it, which is how a
// server learned to be non-conforming during one resolution stays learned for
// the next.
type Casing struct {
	mu     sync.RWMutex
	broken map[netip.AddrPort]bool
}

// NewCasing returns a Casing with nothing yet known about any server.
func NewCasing() *Casing {
	return &Casing{broken: make(map[netip.AddrPort]bool)}
}

// use reports whether this server should be asked with randomised case.
func (c *Casing) use(server netip.AddrPort) bool {
	if c == nil {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return !c.broken[server]
}

// nonconforming records a server that answered with the case it liked rather
// than the case it was sent.
func (c *Casing) nonconforming(server netip.AddrPort) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.broken[server] = true
}

// Nonconforming reports how many servers have been found not to preserve case.
// It exists so a caller can say so rather than the number being invisible.
func (c *Casing) Nonconforming() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.broken)
}

// randomCase flips the case of each ASCII letter in a name at random.
//
// crypto/rand, never math/rand: the case pattern is a nonce, and a nonce an
// attacker can predict is not one. Read cannot fail as of Go 1.24.
//
// Only ASCII letters move. Digits, hyphens, dots and the backslashes of an
// escape all pass through untouched, because the question section is compared
// octet for octet on the way back and anything else changed would make a
// conforming server look non-conforming. A letter never appears inside an
// escape sequence: the encoder escapes only '.', '\\' and octets outside the
// printable range, and those take the three-digit form, so flipping letters in
// the presentation string cannot corrupt one.
func randomCase(n wire.Name) wire.Name {
	b := []byte(n)

	// One bit per letter, taken from as few octets as that needs.
	letters := 0
	for _, c := range b {
		if isASCIILetter(c) {
			letters++
		}
	}
	if letters == 0 {
		return n
	}
	bits := make([]byte, (letters+7)/8)
	rand.Read(bits)

	i := 0
	for j, c := range b {
		if !isASCIILetter(c) {
			continue
		}
		// 0x20 is the bit that separates 'a' from 'A', which is where the
		// mechanism gets its name. Setting or clearing it, rather than flipping
		// it, is what makes the outgoing case independent of the case that came
		// in: XOR against a name that is already lowercase produces uppercase
		// either way, which is one pattern rather than 2^letters of them.
		if bits[i/8]&(1<<(i%8)) != 0 {
			b[j] = c | 0x20
		} else {
			b[j] = c &^ 0x20
		}
		i++
	}
	return wire.Name(b)
}

func isASCIILetter(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// restoreCase puts back the case the caller asked about, everywhere the reply
// echoed the case that went out instead.
//
// Without this the randomisation leaks out of the resolver. The nonce comes
// back in more than the question section: a referral for com. arrives owned by
// whatever case com. was sent in, and any name compressed against the question
// inherits it too, pointer by pointer. A client that asked about example.com
// would be shown records owned by eXaMPle.CoM, a delegation to CoM, and a CNAME
// target ending in .NeT. All of that is legal, all of it is confusing, and it
// would be cached under those spellings and handed to somebody else.
//
// The rule is that any name matching a whole-label suffix of what was sent is
// rewritten to that suffix of what was asked. Case is the only thing that
// changes, so this can never alter which name a record is about.
func restoreCase(m *wire.Message, sent, original wire.Name) {
	if sent == original {
		return
	}
	// Every whole-label suffix of the name, longest first, computed once for
	// the message rather than once per record.
	sufs := original.Suffixes()

	for i := range m.Questions {
		m.Questions[i].Name = restoreName(m.Questions[i].Name, sufs)
	}
	for _, section := range [][]wire.RR{m.Answers, m.Authority, m.Additional} {
		for i := range section {
			section[i].Name = restoreName(section[i].Name, sufs)
			section[i].Data = restoreRData(section[i].Data, sufs)
		}
	}
}

// restoreName rewrites the tail of n that echoes one of the sent name's
// suffixes, and leaves the rest of it alone.
//
// The tail is the part that has to move: a referral's glue for dns2.nic.uk
// arrives with uk spelled the way uk was asked about, because that label was a
// compression pointer into the question. Only the suffix carries the nonce, and
// only the suffix is put back.
func restoreName(n wire.Name, sufs []wire.Name) wire.Name {
	for _, suf := range sufs {
		if len(n) < len(suf) {
			continue
		}
		head := len(n) - len(suf)
		if !n[head:].EqualFold(suf) {
			continue
		}
		// The match has to begin where a label begins. A dot that is itself
		// escaped is part of a label and does not count as one.
		if head > 0 && (n[head-1] != '.' || (head > 1 && n[head-2] == '\\')) {
			continue
		}
		if n[head:] == suf {
			return n
		}
		return n[:head] + suf
	}
	return n
}

// restoreRData rewrites the names carried inside an rdata. They are subject to
// the same leak by the same route: a target compressed against the question
// decodes with the question's case.
func restoreRData(d wire.RData, sufs []wire.Name) wire.RData {
	switch v := d.(type) {
	case wire.NS:
		v.Host = restoreName(v.Host, sufs)
		return v
	case wire.CNAME:
		v.Target = restoreName(v.Target, sufs)
		return v
	case wire.PTR:
		v.Target = restoreName(v.Target, sufs)
		return v
	case wire.MX:
		v.Exchange = restoreName(v.Exchange, sufs)
		return v
	case wire.SRV:
		v.Target = restoreName(v.Target, sufs)
		return v
	case wire.SOA:
		v.Primary = restoreName(v.Primary, sufs)
		v.Mailbox = restoreName(v.Mailbox, sufs)
		return v
	}
	return d
}
