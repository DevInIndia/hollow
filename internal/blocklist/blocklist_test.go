package blocklist

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DevInIndia/hollow/internal/wire"
)

// parse builds a List from two literal list bodies. Tests use it instead of
// writing temporary files, which is what Parse exists for.
func parse(t *testing.T, block, allow string) *List {
	t.Helper()
	var b, a []io.Reader
	if block != "" {
		b = append(b, strings.NewReader(block))
	}
	if allow != "" {
		a = append(a, strings.NewReader(allow))
	}
	l, err := Parse(b, a)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return l
}

// name parses a query name the way the server would.
func name(t *testing.T, s string) wire.Name {
	t.Helper()
	n, err := wire.ParseName(s)
	if err != nil {
		t.Fatalf("ParseName(%q): %v", s, err)
	}
	return n
}

func TestWildcardMatchingWalksLabelsAndNotBytes(t *testing.T) {
	l := parse(t, "||example.com^\n", "")

	blocked := []string{
		"example.com.",       // the name itself
		"ads.example.com.",   // one label under
		"a.b.c.example.com.", // several
	}
	for _, n := range blocked {
		if !l.Blocked(name(t, n)) {
			t.Errorf("%s is not blocked by ||example.com^", n)
		}
	}

	allowed := []string{
		// The whole reason Suffixes exists. A byte-wise suffix test matches
		// every one of these and each one is a different site.
		"notexample.com.",
		"myexample.com.",
		"example.com.evil.net.", // the name only contains the rule
		"com.",                  // a parent, not a child
		"example.org.",
	}
	for _, n := range allowed {
		if l.Blocked(name(t, n)) {
			t.Errorf("%s is blocked by ||example.com^ and must not be", n)
		}
	}
}

func TestAnEscapedDotIsOneLabelAndNotADelegation(t *testing.T) {
	// "evil\.com" is a single label whose octets happen to end in "com". Under
	// a byte-wise suffix test it sits inside a rule for com, which is the exact
	// input that makes strings.HasSuffix unsafe rather than merely sloppy.
	l := parse(t, "||com^\n", "")

	if !l.Blocked(name(t, "under.com.")) {
		t.Fatal("under.com. is not blocked by ||com^, the rule did not load")
	}
	if l.Blocked(name(t, `evil\.com.`)) {
		t.Error(`evil\.com. is blocked by ||com^; the escaped dot was read as a label boundary`)
	}
}

func TestAnExactRuleDoesNotReachSubdomains(t *testing.T) {
	// A hosts line names one host. Treating it as a wildcard would have a
	// single "0.0.0.0 example.com" entry take out the whole domain, which is
	// not what the list said.
	l := parse(t, "0.0.0.0 example.com\n", "")

	if !l.Blocked(name(t, "example.com.")) {
		t.Error("example.com. is not blocked")
	}
	if l.Blocked(name(t, "www.example.com.")) {
		t.Error("www.example.com. is blocked by an exact rule on its parent")
	}
}

func TestTheAllowlistWinsOverEveryKindOfBlock(t *testing.T) {
	// An allowlist entry is an operator saying they know the name is on a list
	// and want it anyway. Nothing on the block side gets to overrule that.
	tests := []struct {
		name  string
		block string
		allow string
		query string
	}{
		{"exact over exact", "0.0.0.0 a.example\n", "a.example\n", "a.example."},
		{"exact over wildcard", "||example.com^\n", "safe.example.com\n", "safe.example.com."},
		{"wildcard over wildcard", "||example.com^\n", "||safe.example.com^\n", "deep.safe.example.com."},
		{"wildcard over exact", "0.0.0.0 a.example.com\n", "||example.com^\n", "a.example.com."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := parse(t, tt.block, tt.allow)
			if l.Blocked(name(t, tt.query)) {
				t.Errorf("%s is blocked despite the allowlist", tt.query)
			}
		})
	}

	// And the allowlist is narrow: it exempts what it names, not everything.
	l := parse(t, "||example.com^\n", "safe.example.com\n")
	if !l.Blocked(name(t, "ads.example.com.")) {
		t.Error("an allowlist entry exempted a sibling name")
	}
}

func TestANilListBlocksNothing(t *testing.T) {
	// The whole feature is optional and this is what makes it optional without
	// a nil check at the call site in the server.
	var l *List
	if l.Blocked(name(t, "anything.example.")) {
		t.Error("a nil List blocked a name")
	}
	if exact, wildcard, allowed, skipped := l.Counts(); exact|wildcard|allowed|skipped != 0 {
		t.Errorf("Counts on a nil List = %d %d %d %d, want zeros", exact, wildcard, allowed, skipped)
	}
}

func TestAnEmptyNameIsNotBlocked(t *testing.T) {
	l := parse(t, "0.0.0.0 a.example\n", "")
	if l.Blocked("") {
		t.Error("the empty name is blocked")
	}
}

func TestAListWithNoWildcardRulesSkipsTheSuffixWalk(t *testing.T) {
	// Behavioural cover for the short circuit in matches. The observable part
	// is only that the answers stay right; the point of the branch is that the
	// common configuration, which is a hosts-format list with no adblock lines
	// in it at all, does one map lookup per query and no allocation.
	l := parse(t, "0.0.0.0 a.example\n", "")
	if !l.Blocked(name(t, "a.example.")) {
		t.Error("a.example. is not blocked")
	}
	if l.Blocked(name(t, "b.a.example.")) {
		t.Error("b.a.example. is blocked with no wildcard rule loaded")
	}
}

func TestLoadReadsFilesAndCountsWhatItBuilt(t *testing.T) {
	dir := t.TempDir()
	write := func(base, body string) string {
		p := filepath.Join(dir, base)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatalf("writing %s: %v", p, err)
		}
		return p
	}
	block := write("block.txt", "0.0.0.0 a.example\n0.0.0.0 b.example\n||c.example^\ngarbage line here\n")
	allow := write("allow.txt", "b.example\n")

	l, err := Load([]string{block}, []string{allow})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	exact, wildcard, allowed, skipped := l.Counts()
	if exact != 2 || wildcard != 1 || allowed != 1 || skipped != 1 {
		t.Errorf("Counts = %d %d %d %d, want 2 1 1 1", exact, wildcard, allowed, skipped)
	}
	if !l.Blocked(name(t, "a.example.")) || l.Blocked(name(t, "b.example.")) {
		t.Error("the loaded files do not block what they say they block")
	}
}

func TestAMissingFileIsFatalWhereABadLineIsNot(t *testing.T) {
	// The asymmetry is deliberate. An operator who named a file expects that
	// file to be in effect, and a resolver that blocks nothing looks exactly
	// like one that is working.
	missing := filepath.Join(t.TempDir(), "nope.txt")

	if _, err := Load([]string{missing}, nil); err == nil {
		t.Error("Load with a missing block file returned no error")
	}
	if _, err := Load(nil, []string{missing}); err == nil {
		t.Error("Load with a missing allow file returned no error")
	}
}

// failingReader returns one good line and then an error, which is what a read
// from a truncated file or a dying pipe looks like.
type failingReader struct{ done bool }

func (f *failingReader) Read(p []byte) (int, error) {
	if f.done {
		return 0, io.ErrUnexpectedEOF
	}
	f.done = true
	return copy(p, "a.example\n"), nil
}

func TestAReadErrorIsReportedRatherThanTreatedAsEndOfFile(t *testing.T) {
	if _, err := Parse([]io.Reader{&failingReader{}}, nil); err == nil {
		t.Error("Parse returned no error on a failing reader")
	}
	if _, err := Parse(nil, []io.Reader{&failingReader{}}); err == nil {
		t.Error("Parse returned no error on a failing allow reader")
	}
}

func TestAFileWithNoTrailingNewlineKeepsItsLastRule(t *testing.T) {
	l := parse(t, "a.example\nb.example", "")
	if !l.Blocked(name(t, "b.example.")) {
		t.Error("the last line was dropped because the file did not end in a newline")
	}
}
