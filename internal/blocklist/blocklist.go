// Package blocklist decides which names are refused.
//
// The data structure is two maps and it is that way on purpose. The measurement
// that settled it: the StevenBlack list, the one nearly everybody loads, is
// 79,746 entries and 5.5 MB of heap, 72 bytes each. Ten of those concatenated
// would still be around 55 MB. TestTheRealList is the measurement.
//
// A trie, a radix tree, a bloom filter or interned strings would each save some
// part of six megabytes and would each be a hand-rolled structure sitting on the
// path of every query. Optimising a 6 MB problem by hand is a good way to put
// bugs in a feature that already works. A lookup here is one map access, and on
// a miss a walk of at most a handful of parent names, with no tree to traverse
// and no pointers to chase.
package blocklist

import (
	"bufio"
	"fmt"
	"io"
	"os"

	"github.com/DevInIndia/hollow/internal/wire"
)

// List answers whether a name is blocked. It is immutable once built, which is
// what makes it safe to share across every worker without a lock.
type List struct {
	// Keys are folded names in canonical presentation form, trailing dot
	// included, which is exactly what wire.Name.Fold produces for a query.
	// Normalising both sides through wire.ParseName is what lets a list written
	// as "Example.COM" match a query for "example.com."
	exact    map[wire.Name]struct{}
	wildcard map[wire.Name]struct{}

	allowExact    map[wire.Name]struct{}
	allowWildcard map[wire.Name]struct{}

	skipped int
}

// Counts reports the size of each set and how many lines were not understood.
// A nil List is all zeros, matching the nil List that blocks nothing.
func (l *List) Counts() (exact, wildcard, allowed, skipped int) {
	if l == nil {
		return 0, 0, 0, 0
	}
	return len(l.exact), len(l.wildcard), len(l.allowExact) + len(l.allowWildcard), l.skipped
}

// Load reads block and allow lists from files.
//
// A file that cannot be opened or read is an error, because an operator who
// named a file expects that file to be in effect and a resolver that quietly
// blocks nothing looks identical to one that is working. A line inside a file
// that cannot be parsed is not an error; it is counted and skipped.
func Load(block, allow []string) (*List, error) {
	open := func(paths []string) ([]io.Reader, []io.Closer, error) {
		var readers []io.Reader
		var closers []io.Closer
		for _, p := range paths {
			f, err := os.Open(p)
			if err != nil {
				for _, c := range closers {
					c.Close()
				}
				return nil, nil, fmt.Errorf("blocklist: %w", err)
			}
			readers = append(readers, f)
			closers = append(closers, f)
		}
		return readers, closers, nil
	}

	blockR, blockC, err := open(block)
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, c := range blockC {
			c.Close()
		}
	}()

	allowR, allowC, err := open(allow)
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, c := range allowC {
			c.Close()
		}
	}()

	return Parse(blockR, allowR)
}

// Parse builds a list from already-open sources. Load is a thin wrapper over it,
// and tests use it directly rather than writing temporary files.
func Parse(block, allow []io.Reader) (*List, error) {
	l := &List{
		exact:         make(map[wire.Name]struct{}),
		wildcard:      make(map[wire.Name]struct{}),
		allowExact:    make(map[wire.Name]struct{}),
		allowWildcard: make(map[wire.Name]struct{}),
	}

	for _, r := range block {
		if err := l.read(r, l.exact, l.wildcard); err != nil {
			return nil, err
		}
	}
	for _, r := range allow {
		if err := l.read(r, l.allowExact, l.allowWildcard); err != nil {
			return nil, err
		}
	}
	return l, nil
}

// maxLineLen is the longest line that could possibly hold a rule. A name is at
// most 255 octets on the wire and a hosts line carries a handful of them, so
// eight kilobytes is far past generous and anything beyond it is not a rule.
const maxLineLen = 8192

func (l *List) read(r io.Reader, exact, wildcard map[wire.Name]struct{}) error {
	br := bufio.NewReader(r)
	for {
		line, long, err := readLine(br)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("blocklist: reading: %w", err)
		}

		entries, ok := parseLine(line)
		if long || !ok {
			// Counted rather than fatal. A list that silently half-loads is
			// worse than one that says it skipped four thousand entries, and
			// public lists routinely carry a few lines in a syntax their own
			// tooling ignores.
			l.skipped++
			continue
		}
		for _, e := range entries {
			if e.wildcard {
				wildcard[e.name] = struct{}{}
			} else {
				exact[e.name] = struct{}{}
			}
		}
	}
}

// readLine reads one line, reporting separately that it was too long to be a
// rule rather than returning an error for it.
//
// bufio.Scanner is the obvious choice here and it is the wrong one. Past its
// buffer limit a Scanner returns an error and will not continue, so one absurd
// line in a generated list would end the read there and leave the rest of the
// file unloaded while the load reported success. Half a blocklist that says it
// is whole is precisely the failure this package is built not to have. A dozen
// lines by hand turn that case into one counted skip.
func readLine(br *bufio.Reader) (line string, long bool, err error) {
	var b []byte
	for {
		chunk, err := br.ReadSlice('\n')
		if len(b)+len(chunk) > maxLineLen {
			// Past the cap the content is discarded rather than accumulated.
			// The line is already known to be unusable and buffering it would
			// let a hostile list decide how much memory this takes.
			long = true
		} else {
			b = append(b, chunk...)
		}
		switch err {
		case bufio.ErrBufferFull:
			continue
		case nil:
			return string(b), long, nil
		case io.EOF:
			if len(b) == 0 && !long {
				return "", false, io.EOF
			}
			return string(b), long, nil
		default:
			return "", false, err
		}
	}
}

// Blocked reports whether name should be refused.
//
// A nil List blocks nothing, which is what makes the whole feature optional
// without a flag check at the call site.
func (l *List) Blocked(name wire.Name) bool {
	if l == nil || name == "" {
		return false
	}
	folded := name.Fold()

	// The allowlist is consulted first and wins outright. An entry there is an
	// operator saying they know this name is on a list and they want it anyway,
	// which is a statement about intent that no amount of matching on the block
	// side should be able to overrule.
	if l.matches(folded, l.allowExact, l.allowWildcard) {
		return false
	}
	return l.matches(folded, l.exact, l.wildcard)
}

// matches tests one exact set and one wildcard set against an already folded
// name.
func (l *List) matches(folded wire.Name, exact, wildcard map[wire.Name]struct{}) bool {
	if _, ok := exact[folded]; ok {
		return true
	}
	if len(wildcard) == 0 {
		// Worth the branch: the StevenBlack list contains no adblock lines at
		// all, so for the common configuration this skips the suffix walk and
		// the one allocation it makes, on every query.
		return false
	}

	// Suffixes walks label boundaries. strings.HasSuffix is the obvious
	// implementation and it is wrong in the direction that matters: it would
	// have "notexample.com." match a rule for "example.com.", and it would have
	// "evil\.com." match one for "com." even though the escaped dot makes that a
	// single label rather than a name under com.
	for _, suffix := range folded.Suffixes() {
		if _, ok := wildcard[suffix]; ok {
			return true
		}
	}
	return false
}
