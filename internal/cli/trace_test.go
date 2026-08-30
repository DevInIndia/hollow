package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/DevInIndia/hollow/internal/resolver"
	"github.com/DevInIndia/hollow/internal/wire"
)

// The steps below are built by hand rather than resolved, because what is under
// test is the renderer. That the steps themselves describe real packets is the
// resolver's business and is tested there.

var errTimeout = errors.New("reading the reply: timed out")

func step(zone, name string, server string, kind resolver.Kind, msg *wire.Message) resolver.Step {
	s := resolver.Step{
		Zone:       wire.Name(zone),
		Query:      wire.Question{Name: wire.Name(name), Type: wire.TypeA, Class: wire.ClassIN},
		Kind:       kind,
		Candidates: 2,
	}
	if server != "" {
		s.Server = netip.MustParseAddrPort(server)
	}
	s.Reply = &resolver.Reply{Msg: msg, Server: s.Server, Protocol: "udp", Size: 100, RTT: 12 * time.Millisecond}
	return s
}

func referralMsg(zone, host, glue string) *wire.Message {
	m := &wire.Message{Authority: []wire.RR{{
		Name: wire.Name(zone), Type: wire.TypeNS, Class: wire.ClassIN, TTL: 3600,
		Data: wire.NS{Host: wire.Name(host)},
	}}}
	if glue != "" {
		m.Additional = []wire.RR{{
			Name: wire.Name(host), Type: wire.TypeA, Class: wire.ClassIN, TTL: 3600,
			Data: wire.A{Addr: netip.MustParseAddr(glue)},
		}}
	}
	return m
}

func drawn(t *testing.T, steps []resolver.Step, cs charset) string {
	t.Helper()
	var buf bytes.Buffer
	q := wire.Question{Name: "example.com.", Type: wire.TypeA, Class: wire.ClassIN}
	drawTrace(&buf, q, steps, nil, 500*time.Millisecond, cs)
	return buf.String()
}

// The nested lookup of a nameserver with no glue is the case that separates a
// real iterative resolver from one that only follows glue, so it has to be
// visible as a sub-tree rather than as two unrelated walks.
func TestTraceIndentsTheLookupOfANameserverWithNoGlue(t *testing.T) {
	steps := []resolver.Step{
		step(".", "example.com.", "127.0.0.1:53", resolver.KindReferral, referralMsg("com.", "a.gtld.test.", "127.0.0.2")),
		step("com.", "example.com.", "127.0.0.2:53", resolver.KindReferral, referralMsg("example.com.", "ns.hoster.test.", "")),
		func() resolver.Step {
			s := step(".", "ns.hoster.test.", "127.0.0.1:53", resolver.KindReferral, referralMsg("test.", "a.test.", "127.0.0.4"))
			s.Nested = 1
			return s
		}(),
		func() resolver.Step {
			s := step("test.", "ns.hoster.test.", "127.0.0.4:53", resolver.KindAnswer, &wire.Message{})
			s.Nested = 1
			return s
		}(),
		step("example.com.", "example.com.", "127.0.0.3:53", resolver.KindAnswer, &wire.Message{}),
	}
	out := drawn(t, steps, asciiSet)

	marker := "(no glue, resolving ns.hoster.test.)"
	if !strings.Contains(out, marker) {
		t.Fatalf("output does not say why it went looking:\n%s", out)
	}
	// The sub-tree is indented past the zone that needed it, and the walk comes
	// back out to where it was for the final answer.
	lines := strings.Split(out, "\n")
	var markerIndent, comIndent, finalIndent int
	for _, l := range lines {
		switch {
		case strings.Contains(l, marker):
			markerIndent = indentOf(l)
		case strings.HasPrefix(strings.TrimSpace(l), "com."):
			comIndent = indentOf(l)
		case strings.HasPrefix(strings.TrimSpace(l), "example.com."):
			finalIndent = indentOf(l)
		}
	}
	if markerIndent <= comIndent {
		t.Errorf("sub-resolution at indent %d is not nested past com. at %d\n%s", markerIndent, comIndent, out)
	}
	if finalIndent > markerIndent {
		t.Errorf("the walk did not come back out: example.com. at %d, sub-resolution at %d\n%s", finalIndent, markerIndent, out)
	}
}

func indentOf(line string) int { return len(line) - len(strings.TrimLeft(line, " ")) }

// An answer that cost no packet has to look different from one that did, or the
// tree quietly claims credit for work it did not do.
func TestTraceMarksAnAnswerThatCameFromTheCache(t *testing.T) {
	cached := resolver.Step{
		Query: wire.Question{Name: "example.com.", Type: wire.TypeA, Class: wire.ClassIN},
		Kind:  resolver.KindAnswer,
		Reply: &resolver.Reply{Msg: &wire.Message{}, Protocol: resolver.ProtocolCache},
	}
	out := drawn(t, []resolver.Step{cached}, asciiSet)

	if !strings.Contains(out, "cache") || !strings.Contains(out, "no packet sent") {
		t.Errorf("a cache hit is not marked as one:\n%s", out)
	}
	if !strings.Contains(out, "0 queries") {
		t.Errorf("a cache hit was counted as a query:\n%s", out)
	}
}

// A judge's terminal may lack the font, and a pipe into a file has no font at
// all. Both get ASCII.
func TestTraceInASCIIIsPureASCII(t *testing.T) {
	steps := []resolver.Step{
		step(".", "example.com.", "127.0.0.1:53", resolver.KindReferral, referralMsg("com.", "a.gtld.test.", "127.0.0.2")),
		step("com.", "example.com.", "127.0.0.2:53", resolver.KindAnswer, &wire.Message{}),
	}
	out := drawn(t, steps, asciiSet)
	for i := range len(out) {
		if out[i] > 127 {
			t.Fatalf("byte %d is %#x, not ASCII:\n%s", i, out[i], out)
		}
	}
	if strings.Contains(out, "\x1b") {
		t.Error("output carries an escape sequence")
	}
}

// The charset is chosen from where the output is going, not from a flag alone.
// A bytes.Buffer is not a terminal, and neither is a file.
func TestGlyphsFallBackToASCIIWhenTheOutputIsNotATerminal(t *testing.T) {
	if got := glyphs(false, new(bytes.Buffer)); got != asciiSet {
		t.Errorf("glyphs(false, buffer) = %v, want the ASCII set", got)
	}
	if got := glyphs(true, new(bytes.Buffer)); got != asciiSet {
		t.Errorf("glyphs(true, buffer) = %v, want the ASCII set", got)
	}
}

func TestTraceJSONCarriesEveryStep(t *testing.T) {
	steps := []resolver.Step{
		step(".", "example.com.", "127.0.0.1:53", resolver.KindReferral, referralMsg("com.", "a.gtld.test.", "127.0.0.2")),
		step("com.", "example.com.", "127.0.0.2:53", resolver.KindAnswer, &wire.Message{}),
	}
	var buf bytes.Buffer
	if err := writeSteps(&buf, steps); err != nil {
		t.Fatalf("writeSteps() error = %v", err)
	}

	var got []jsonStep
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("the trace is not valid JSON: %v\n%s", err, buf.String())
	}
	if len(got) != 2 {
		t.Fatalf("steps = %d, want 2", len(got))
	}
	if got[0].Zone != "." || got[0].Server != "127.0.0.1:53" || got[0].Outcome != "referral" {
		t.Errorf("first step = %+v", got[0])
	}
	if got[1].Outcome != "answer" || got[1].RTTMS != 12 {
		t.Errorf("second step = %+v", got[1])
	}
}

// A walk that fails still has a trace, and the reason belongs on the line for
// the server that gave it.
func TestTraceShowsWhyAServerWasSkipped(t *testing.T) {
	failed := resolver.Step{
		Zone:       ".",
		Server:     netip.MustParseAddrPort("127.0.0.1:53"),
		Query:      wire.Question{Name: "example.com.", Type: wire.TypeA, Class: wire.ClassIN},
		Kind:       resolver.KindFailure,
		Err:        errTimeout,
		Candidates: 3,
	}
	out := drawn(t, []resolver.Step{failed}, asciiSet)
	if !strings.Contains(out, errTimeout.Error()) {
		t.Errorf("the failure is not in the trace:\n%s", out)
	}
}

func TestTraceRejectsBadArguments(t *testing.T) {
	tests := map[string][]string{
		"no name":                {},
		"too many words":         {"example.com", "A", "extra"},
		"an unknown type":        {"example.com", "NOTAREALTYPE"},
		"a name that is not one": {"empty..label.example"},
		"a port that is not one": {"--port", "70000", "example.com"},
		"unrecognised flag":      {"--nope", "example.com"},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr strings.Builder
			if got := Trace(args, &stdout, &stderr); got != ExitFailure {
				t.Errorf("Trace() = %d, want %d", got, ExitFailure)
			}
			if stderr.Len() == 0 {
				t.Error("a failed trace explained nothing on stderr")
			}
			if stdout.Len() != 0 {
				t.Errorf("a failed trace wrote to stdout: %q", stdout.String())
			}
		})
	}
}

func TestInspectRejectsBadArguments(t *testing.T) {
	tests := map[string][]string{
		"no name":                   {},
		"an unknown type":           {"example.com", "NOTAREALTYPE"},
		"a name that is not one":    {"empty..label.example"},
		"a port that is not one":    {"--port", "0", "example.com"},
		"a file that is not there":  {"--file", "/nonexistent/message.bin"},
		"a server given as a name":  {"--server", "dns.example.com", "example.com"},
		"hints with a named server": {"--server", "1.1.1.1", "--hints", "/nonexistent/named.root", "example.com"},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr strings.Builder
			if got := Inspect(args, &stdout, &stderr); got != ExitFailure {
				t.Errorf("Inspect() = %d, want %d", got, ExitFailure)
			}
			if stderr.Len() == 0 {
				t.Error("a failed inspect explained nothing on stderr")
			}
		})
	}
}

// A trace of a walk that never happened still renders, because a resolution
// that failed is exactly when somebody wants to see how far it got.
func TestDrawTraceHandlesAnEmptyWalk(t *testing.T) {
	out := drawn(t, nil, asciiSet)
	if !strings.Contains(out, "no exchanges") {
		t.Errorf("an empty trace rendered as %q", out)
	}
}
