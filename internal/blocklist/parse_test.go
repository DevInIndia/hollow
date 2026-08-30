package blocklist

import (
	"strings"
	"testing"
)

// stevenBlackPreamble is the head of the list verbatim, which is the input that
// breaks a naive parser. Every line here has a name in field two and none of
// them may become a rule.
const stevenBlackPreamble = `# Title: StevenBlack/hosts
#
# This hosts file is a merged collection of hosts from reputable sources.
# ===============================================================

127.0.0.1 localhost
127.0.0.1 localhost.localdomain
127.0.0.1 local
255.255.255.255 broadcasthost
::1 localhost
::1 ip6-localhost
::1 ip6-loopback
fe80::1%lo0 localhost
ff00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
ff02::3 ip6-allhosts
0.0.0.0 0.0.0.0

# Start of the block list
0.0.0.0 ads.example.
`

func TestTheHostsPreambleNeverBecomesARule(t *testing.T) {
	l := parse(t, stevenBlackPreamble, "")

	// Blocking localhost breaks the machine the resolver runs on, which is the
	// single worst thing this package could do.
	for _, n := range []string{
		"localhost.", "localhost.localdomain.", "local.", "broadcasthost.",
		"ip6-localhost.", "ip6-loopback.", "ip6-localnet.", "ip6-mcastprefix.",
		"ip6-allnodes.", "ip6-allrouters.", "ip6-allhosts.",
	} {
		if l.Blocked(name(t, n)) {
			t.Errorf("%s is blocked; the preamble was ingested as rules", n)
		}
	}

	// And the one real entry after it did load, so the preamble is being
	// filtered rather than the whole file being thrown away.
	if !l.Blocked(name(t, "ads.example.")) {
		t.Error("ads.example. is not blocked; nothing loaded at all")
	}
	if exact, _, _, skipped := l.Counts(); exact != 1 || skipped != 0 {
		t.Errorf("counts: exact %d skipped %d, want 1 and 0", exact, skipped)
	}
}

func TestAnIPv6LiteralInFieldOneIsAnAddressNotAName(t *testing.T) {
	// "::1 tracker.example" is a legitimate hosts line and a parser that
	// expects a dotted quad in field one either drops it or, worse, keeps "::1"
	// as a name.
	l := parse(t, "::1 tracker.example\n", "")
	if !l.Blocked(name(t, "tracker.example.")) {
		t.Error("tracker.example. not blocked from an IPv6 hosts line")
	}
	if _, _, _, skipped := l.Counts(); skipped != 0 {
		t.Errorf("skipped %d lines, want 0", skipped)
	}
}

func TestEveryFormatTheListsActuallyUse(t *testing.T) {
	const list = `# a comment
! an adblock comment

0.0.0.0 hosts-null.example
127.0.0.1 hosts-loopback.example
0.0.0.0 two-names-a.example two-names-b.example
domain-only.example
trailing.example # blocked because of a thing
||wildcard.example^
||with-modifiers.example^$third-party
`
	l := parse(t, list, "")

	for _, want := range []string{
		"hosts-null.example.", "hosts-loopback.example.",
		"two-names-a.example.", "two-names-b.example.",
		"domain-only.example.", "trailing.example.",
		"wildcard.example.", "with-modifiers.example.",
	} {
		if !l.Blocked(name(t, want)) {
			t.Errorf("%s is not blocked", want)
		}
	}
	if exact, wildcard, _, skipped := l.Counts(); exact != 6 || wildcard != 2 || skipped != 0 {
		t.Errorf("counts: exact %d wildcard %d skipped %d, want 6, 2 and 0", exact, wildcard, skipped)
	}
}

func TestUnparseableLinesAreCountedAndTheRestStillLoads(t *testing.T) {
	// A list that silently half-loads is worse than one that says how much it
	// dropped, so the count is part of the contract and is asserted here.
	const list = `good-one.example
not an address and not a name either
||missing-the-caret.example
||^
0.0.0.0 empty..label.example
good-two.example
`
	l := parse(t, list, "")

	if !l.Blocked(name(t, "good-one.example.")) || !l.Blocked(name(t, "good-two.example.")) {
		t.Error("a bad line stopped the good ones after it from loading")
	}
	exact, _, _, skipped := l.Counts()
	if exact != 2 {
		t.Errorf("exact = %d, want 2", exact)
	}
	if skipped != 4 {
		t.Errorf("skipped = %d, want 4", skipped)
	}
}

func TestCommentsAreStrippedWhereverTheyAppear(t *testing.T) {
	tests := []struct {
		name string
		line string
		want []entry
	}{
		{"whole line", "# 0.0.0.0 nope.example", nil},
		{"adblock comment", "! ||nope.example^", nil},
		{"trailing on a hosts line", "0.0.0.0 yes.example # why", []entry{{name: "yes.example."}}},
		{"trailing on a domain line", "yes.example #why", []entry{{name: "yes.example."}}},
		{"blank", "   ", nil},
		{"empty", "", nil},
		{"carriage return from a windows-authored list", "0.0.0.0 crlf.example\r", []entry{{name: "crlf.example."}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseLine(tt.line)
			if !ok {
				t.Fatalf("parseLine(%q) reported the line not understood", tt.line)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("parseLine(%q) = %v, want %v", tt.line, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("entry %d = %v, want %v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestNamesAreFoldedAndCanonicalisedOnTheWayIn(t *testing.T) {
	// The list is written in mixed case with no trailing dot and the query
	// arrives in a different case with one. Both go through wire.ParseName and
	// Fold, so they meet.
	l := parse(t, "0.0.0.0 Ads.EXAMPLE\n", "")
	if !l.Blocked(name(t, "aDs.ExAmPlE.")) {
		t.Error("case folding does not reach across the list and the query")
	}
}

func TestARuleOnTheRootIsDropped(t *testing.T) {
	// Whatever a line like this meant, it did not mean "block every name".
	l := parse(t, "0.0.0.0 .\n.\n", "")
	if l.Blocked(name(t, "example.com.")) {
		t.Fatal("a rule on the root blocked an unrelated name")
	}
	if exact, wildcard, _, _ := l.Counts(); exact != 0 || wildcard != 0 {
		t.Errorf("counts: exact %d wildcard %d, want 0 and 0", exact, wildcard)
	}
}

func TestAnAddressInTheNamePositionIsNotAName(t *testing.T) {
	// "0.0.0.0 0.0.0.0" is in the StevenBlack preamble and parses fine as a
	// name, which is why it needs rejecting explicitly.
	l := parse(t, "0.0.0.0 0.0.0.0\n::1 ::1\n", "")
	if exact, _, _, skipped := l.Counts(); exact != 0 || skipped != 0 {
		t.Errorf("counts: exact %d skipped %d, want 0 and 0", exact, skipped)
	}
	if l.Blocked(name(t, "0.0.0.0.")) {
		t.Error("an address was stored as a name")
	}
}

func TestASingleLineWithManyNamesBlocksAllOfThem(t *testing.T) {
	l := parse(t, "0.0.0.0 a.example b.example c.example\n", "")
	for _, n := range []string{"a.example.", "b.example.", "c.example."} {
		if !l.Blocked(name(t, n)) {
			t.Errorf("%s is not blocked", n)
		}
	}
}

func TestANameTooLongForTheWireIsNotARule(t *testing.T) {
	long := "0.0.0.0 " + strings.Repeat("a", 300) + ".example"
	if _, ok := parseLine(long); ok {
		t.Error("a label well over the 63 octet wire limit was accepted")
	}
}

func TestAnAbsurdlyLongLineIsOneSkipAndNotTheEndOfTheFile(t *testing.T) {
	// The reason this package reads lines by hand rather than with
	// bufio.Scanner: a Scanner past its buffer limit returns an error and stops,
	// so a single generated monster line would truncate the rest of the list
	// while reporting success.
	var b strings.Builder
	b.WriteString("before.example\n")
	b.WriteString("0.0.0.0 ")
	for b.Len() < 4*maxLineLen {
		b.WriteString("padding.example ")
	}
	b.WriteString("\nafter.example\n")

	l := parse(t, b.String(), "")
	if !l.Blocked(name(t, "before.example.")) {
		t.Error("before.example. is not blocked")
	}
	if !l.Blocked(name(t, "after.example.")) {
		t.Error("after.example. is not blocked; the long line ended the file")
	}
	if _, _, _, skipped := l.Counts(); skipped != 1 {
		t.Errorf("skipped = %d, want 1", skipped)
	}
}
