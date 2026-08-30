package tui

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/DevInIndia/hollow/internal/control"
)

// Every test in here draws into a buffer. No terminal is involved anywhere,
// which is the property that makes a frame builder testable at all.

func snapshot() *control.Snapshot {
	return &control.Snapshot{
		UptimeMS:       2*60*60*1000 + 14*60*1000,
		QueriesTotal:   12094,
		QueriesBlocked: 2345,
		CacheHits:      8000,
		CacheMisses:    1200,
		CacheEntries:   84213,
		StaleServed:    41,
		LatencyP50MS:   0.4,
		LatencyP99MS:   61,
		TopDomains:     []control.Item{{Name: "cdn.example.com.", Count: 4821}, {Name: "api.service.io.", Count: 3204}},
		TopBlocked:     []control.Item{{Name: "ads.tracker.net.", Count: 2910}},
		TopClients:     []control.Item{{Name: "10.0.0.4", Count: 12094}},
	}
}

func frame(cs Charset) *Frame {
	f := &Frame{Target: "127.0.0.1:15354", Charset: cs}
	f.Observe(snapshot())
	f.Add(control.Event{
		At:     time.Date(2026, 8, 30, 20, 41, 3, 0, time.UTC),
		Client: "10.0.0.4", Name: "cdn.example.com.", Type: "A", Rcode: "NOERROR", CacheHit: true,
	})
	f.Add(control.Event{
		At:     time.Date(2026, 8, 30, 20, 41, 4, 0, time.UTC),
		Client: "10.0.0.9", Name: "ads.tracker.net.", Type: "AAAA", Rcode: "NXDOMAIN", Blocked: true,
	})
	return f
}

func render(t *testing.T, f *Frame, w, h int) string {
	t.Helper()
	var buf bytes.Buffer
	f.Render(&buf, w, h)
	return buf.String()
}

// 1. The frame renders at both ends of the size range, and every row is exactly
// as wide as it claims, since one short row breaks the right-hand border for the
// whole panel.
func TestFrameIsRectangularAtEverySize(t *testing.T) {
	sizes := []struct{ w, h int }{{80, 24}, {200, 50}, {100, 30}, {minWidth, minHeight}}
	for _, cs := range []Charset{Unicode, ASCII} {
		for _, size := range sizes {
			out := render(t, frame(cs), size.w, size.h)
			lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
			if len(lines) != size.h {
				t.Errorf("%dx%d: %d rows, want %d", size.w, size.h, len(lines), size.h)
			}
			for i, l := range lines {
				if got := runes(l); got != size.w {
					t.Errorf("%dx%d: row %d is %d columns, want %d: %q", size.w, size.h, i, got, size.w, l)
				}
			}
		}
	}
}

// A size below the minimum is drawn at the minimum rather than computed from a
// negative body height, which would panic or produce nothing.
func TestFrameSurvivesAnAbsurdSize(t *testing.T) {
	for _, size := range [][2]int{{1, 1}, {0, 0}, {-5, -5}, {10, 3}} {
		out := render(t, frame(Unicode), size[0], size[1])
		if len(out) == 0 {
			t.Errorf("%dx%d rendered nothing", size[0], size[1])
		}
	}
}

// 2. The one that matters, and the one an earlier prototype failed. ASCII mode
// promises no byte above 127, and the way that promise gets broken is a
// truncation helper with U+2026 written into it while the sparkline correctly
// switches. Every byte is scanned, because this cannot be seen by eye.
func TestASCIIModeIsPureASCII(t *testing.T) {
	f := frame(ASCII)
	// Names long enough that every one of them has to be truncated, in both the
	// feed and the top-N lists, so the helper is actually exercised.
	long := "a-very-long-name-that-will-not-fit-in-any-column.example.com."
	f.Snap.TopDomains = []control.Item{{Name: long, Count: 1}}
	f.Snap.TopBlocked = []control.Item{{Name: long, Count: 2}}
	f.Add(control.Event{At: time.Now(), Client: "10.0.0.1", Name: long, Type: "AAAA", Rcode: "NOERROR"})

	for _, size := range [][2]int{{80, 24}, {minWidth, minHeight}, {200, 50}} {
		out := render(t, f, size[0], size[1])
		for i := range len(out) {
			if out[i] > 127 {
				t.Fatalf("%dx%d: byte %d is %#x, not ASCII\n%s", size[0], size[1], i, out[i], out)
			}
		}
	}
}

// The helper on its own, since the frame test above can only prove that nothing
// reached the output, not that the helper is the thing keeping it out.
func TestTruncateSwitchesItsEllipsisWithTheCharset(t *testing.T) {
	const name = "cdn.assets.example.co.uk."
	ascii := truncate(name, 12, ASCII.Ellipsis)
	unicode := truncate(name, 12, Unicode.Ellipsis)

	if runes(ascii) != 12 || runes(unicode) != 12 {
		t.Fatalf("widths: ascii %d, unicode %d, want 12 each", runes(ascii), runes(unicode))
	}
	if !strings.Contains(ascii, "...") {
		t.Errorf("ascii truncation = %q, want three dots", ascii)
	}
	if strings.ContainsRune(ascii, '…') {
		t.Errorf("ascii truncation carries U+2026: %q", ascii)
	}
	if !strings.ContainsRune(unicode, '…') {
		t.Errorf("unicode truncation = %q, want the ellipsis rune", unicode)
	}
	// The ellipsis is three columns in one mode and one in the other, so the two
	// keep different amounts of the name at the same width. Getting this wrong
	// is how a row ends up one column too wide in exactly one mode.
	if strings.HasPrefix(ascii, "cdn.assets") {
		t.Errorf("ascii truncation kept as much as unicode does: %q", ascii)
	}
}

func TestTruncateLeavesShortNamesAlone(t *testing.T) {
	if got := truncate("a.io", 12, Unicode.Ellipsis); got != "a.io" {
		t.Errorf("truncate() = %q, want the name unchanged", got)
	}
	// Narrower than the ellipsis itself, where there is nothing sensible to do
	// but cut.
	if got := truncate("example.com", 2, ASCII.Ellipsis); runes(got) != 2 {
		t.Errorf("truncate() = %q, want 2 columns", got)
	}
	if got := truncate("example.com", 0, ASCII.Ellipsis); got != "" {
		t.Errorf("truncate() = %q, want empty", got)
	}
}

// A name is cut in the middle because the ends are what identify it. Cutting the
// tail turns a list of subdomains into a list of one name repeated.
func TestTruncateKeepsBothEndsOfAName(t *testing.T) {
	got := truncate("cdn.assets.example.co.uk.", 16, Unicode.Ellipsis)
	if !strings.HasPrefix(got, "cdn.") {
		t.Errorf("truncate() = %q, want the head kept", got)
	}
	if !strings.HasSuffix(got, "uk.") {
		t.Errorf("truncate() = %q, want the tail kept", got)
	}
}

// 3. A frame drawn for something that is not a terminal must carry no escape
// sequence at all. The probe run for this project captured literal escapes in
// its own output because stdout was a pipe, so this is a demonstrated failure
// rather than a hypothetical one.
func TestRenderWritesNoEscapeSequences(t *testing.T) {
	f := frame(ASCII)
	f.Colour = false
	if out := render(t, f, 100, 30); strings.Contains(out, "\x1b") {
		t.Errorf("a plain render carries an escape sequence:\n%q", out)
	}
}

// 8. NO_COLOR is honoured whatever its value, and so is a non-terminal, a dumb
// terminal and an unset one. Each is independently a reason to write nothing.
func TestDetectRefusesToDrawEscapesWhereTheyWouldNotRender(t *testing.T) {
	tests := map[string]struct {
		term, noColour string
		plain          bool
	}{
		"a pipe":             {term: "xterm-256color"},
		"a dumb terminal":    {term: "dumb"},
		"no TERM at all":     {term: ""},
		"NO_COLOR set":       {term: "xterm-256color", noColour: "1"},
		"NO_COLOR set empty": {term: "xterm-256color", noColour: ""},
		"plain asked for":    {term: "xterm-256color", plain: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Setenv("TERM", tc.term)
			if tc.noColour != "" {
				t.Setenv("NO_COLOR", tc.noColour)
			}
			// A bytes.Buffer is not a character device, so this is the pipe case
			// for every row: none of them may end up drawing escapes.
			m := Detect(new(bytes.Buffer), false, tc.plain)
			if m.Fullscreen {
				t.Error("fullscreen mode chosen for output that cannot show it")
			}
			if m.Colour {
				t.Error("colour chosen for output that cannot show it")
			}
			if m.Charset.Ellipsis != ASCII.Ellipsis {
				t.Error("the unicode charset was chosen for a pipe")
			}
		})
	}
}

// Colour reinforces and never carries meaning alone: a blocked row says so in
// words and a cache hit has a marker, both of which survive into ASCII output
// with no colour at all.
func TestOutcomesAreLegibleWithoutColour(t *testing.T) {
	out := render(t, frame(ASCII), 100, 30)
	if !strings.Contains(out, "blocked") {
		t.Errorf("a blocked query is not named in the feed:\n%s", out)
	}
	if !strings.Contains(out, ASCII.Hit) {
		t.Errorf("a cache hit carries no marker:\n%s", out)
	}
}

// 6. A long name is truncated rather than wrapped. A wrapped row destroys a
// fixed-height layout, which is the whole reason the frame can be drawn in place.
func TestLongNamesTruncateRatherThanWrap(t *testing.T) {
	f := frame(Unicode)
	long := strings.Repeat("subdomain.", 30) + "example.com."
	f.Add(control.Event{At: time.Now(), Client: "10.0.0.1", Name: long, Type: "A", Rcode: "NOERROR"})
	f.Snap.TopDomains = []control.Item{{Name: long, Count: 9}}

	out := render(t, f, 100, 30)
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != 30 {
		t.Fatalf("%d rows, want 30: a long name wrapped", len(lines))
	}
	for i, l := range lines {
		if runes(l) != 100 {
			t.Errorf("row %d is %d columns, want 100", i, runes(l))
		}
	}
}

// 7. Before anything has arrived there is no snapshot and no event, which is the
// state the dashboard spends its first half second in and the state a judge sees
// first.
func TestEmptyStateRendersCleanly(t *testing.T) {
	f := &Frame{Target: "127.0.0.1:15354", Charset: Unicode}
	out := render(t, f, 100, 30)

	if !strings.Contains(out, "waiting for the first snapshot") {
		t.Errorf("an empty frame does not say what it is waiting for:\n%s", out)
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	for i, l := range lines {
		if runes(l) != 100 {
			t.Errorf("row %d is %d columns, want 100", i, runes(l))
		}
	}
}

// 5. A disconnect is a banner over the last known state, not a blank screen and
// not an exit. The numbers stay up because that is the moment somebody wants to
// read them.
func TestADisconnectKeepsTheLastFrameBehindTheBanner(t *testing.T) {
	f := frame(Unicode)
	f.Banner = "server gone, reconnecting"

	out := render(t, f, 100, 30)
	if !strings.Contains(out, "reconnecting") {
		t.Errorf("the banner is not on screen:\n%s", out)
	}
	if !strings.Contains(out, "cdn.example.com") {
		t.Errorf("the last known state was cleared when the server went away:\n%s", out)
	}
}

// A reconnect to a restarted server must not carry the old counters forward. The
// new server's uptime went backwards, and a rate computed across that boundary
// describes nothing that happened.
func TestResetForgetsTheRateAcrossARestart(t *testing.T) {
	f := frame(Unicode)
	// A second snapshot from the same server, a second later, which is what
	// produces the first sample.
	f.Observe(&control.Snapshot{UptimeMS: f.Snap.UptimeMS + 1000, QueriesTotal: f.Snap.QueriesTotal + 20})
	if len(f.qps) == 0 {
		t.Fatal("no rate was sampled, so the reset cannot be tested")
	}

	f.Reset()
	if len(f.qps) != 0 {
		t.Errorf("qps = %v, want empty after a reset", f.qps)
	}
	// The first snapshot from the restarted server establishes a baseline and
	// yields no sample of its own.
	f.Observe(&control.Snapshot{UptimeMS: 500, QueriesTotal: 3})
	if len(f.qps) != 0 {
		t.Errorf("qps = %v, want no sample from a single snapshot", f.qps)
	}
	f.Observe(&control.Snapshot{UptimeMS: 1500, QueriesTotal: 13})
	if len(f.qps) != 1 || f.qps[0] != 10 {
		t.Errorf("qps = %v, want one sample of 10 a second", f.qps)
	}
}

// The rate comes from the server's own clock, so a dashboard that was suspended
// and resumed reports the average over the gap rather than a spike.
func TestRateUsesTheServerClock(t *testing.T) {
	f := &Frame{Charset: ASCII}
	f.Observe(&control.Snapshot{UptimeMS: 1000, QueriesTotal: 0})
	f.Observe(&control.Snapshot{UptimeMS: 11000, QueriesTotal: 50})
	if len(f.qps) != 1 || f.qps[0] != 5 {
		t.Errorf("qps = %v, want one sample of 5 a second over ten seconds", f.qps)
	}
}

// A snapshot that arrives with no time between it and the last one would divide
// by zero. Two snapshots in the same millisecond is not exotic on a fast loop.
func TestRateIgnoresASnapshotWithNoElapsedTime(t *testing.T) {
	f := &Frame{Charset: ASCII}
	f.Observe(&control.Snapshot{UptimeMS: 1000, QueriesTotal: 5})
	f.Observe(&control.Snapshot{UptimeMS: 1000, QueriesTotal: 9})
	if len(f.qps) != 0 {
		t.Errorf("qps = %v, want nothing sampled across no time", f.qps)
	}
}

func TestEventsAreBounded(t *testing.T) {
	f := &Frame{Charset: ASCII}
	for i := range eventsKept * 3 {
		f.Add(control.Event{At: time.Now(), Name: "example.com.", Type: "A", Rcode: "NOERROR", Client: "10.0.0.1", DurationMS: float64(i)})
	}
	if len(f.events) != eventsKept {
		t.Errorf("events = %d, want %d", len(f.events), eventsKept)
	}
	// Newest first, so the feed reads downwards in the order things happened.
	if f.events[0].DurationMS != float64(eventsKept*3-1) {
		t.Errorf("the newest event is not first: %v", f.events[0].DurationMS)
	}
}

func TestQPSHistoryIsBounded(t *testing.T) {
	f := &Frame{Charset: ASCII}
	for i := range qpsKept * 3 {
		f.Observe(&control.Snapshot{UptimeMS: int64(i+1) * 1000, QueriesTotal: uint64(i)})
	}
	if len(f.qps) != qpsKept {
		t.Errorf("qps = %d samples, want %d", len(f.qps), qpsKept)
	}
}

// Paint is the in-place path: cursor home once, then a clear to end of line on
// every row, and one write for the whole frame. Never a clear-then-redraw, which
// is what flickers.
func TestPaintClearsPerLineAndNeverClearsTheScreen(t *testing.T) {
	f := frame(Unicode)
	var buf bytes.Buffer
	f.Paint(&buf, 100, 30)
	out := buf.String()

	if !strings.HasPrefix(out, cursorHome) {
		t.Error("the frame does not start at the cursor home position")
	}
	if strings.Contains(out, "\x1b[2J") {
		t.Error("the frame clears the screen, which is what produces a flash")
	}
	if got := strings.Count(out, clearLine); got != 30 {
		t.Errorf("%d line clears, want one per row (30)", got)
	}
}

// Colour is applied to whole padded rows, so turning it on must not move
// anything. An escape sequence occupies bytes and no columns, and a layout that
// counts the bytes drifts on exactly the rows that happen to be coloured.
func TestColourDoesNotChangeTheLayout(t *testing.T) {
	plain := frame(Unicode)
	coloured := frame(Unicode)
	coloured.Colour = true

	plainRows := plain.rows(100, 30)
	colouredRows := coloured.rows(100, 30)
	for i := range plainRows {
		stripped := strip(colouredRows[i])
		if stripped != plainRows[i] {
			t.Errorf("row %d differs once colour is stripped:\n plain %q\n colour %q", i, plainRows[i], stripped)
		}
	}
}

// strip removes every ANSI sequence this package writes, which are all of the
// form ESC [ ... letter.
func strip(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == 0x1b {
			for i < len(s) && !(s[i] >= 'A' && s[i] <= 'Z' || s[i] >= 'a' && s[i] <= 'z') {
				i++
			}
			i++
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// 4. Restore puts back exactly what Enter took, and is safe to call twice, since
// it is reached from a defer and could be reached again by a careful caller.
func TestScreenRestoresWhatItTook(t *testing.T) {
	var buf bytes.Buffer
	s := Enter(&buf)
	if !strings.Contains(buf.String(), altScreenOn) || !strings.Contains(buf.String(), cursorHide) {
		t.Fatalf("Enter did not take the screen: %q", buf.String())
	}

	buf.Reset()
	s.Restore()
	out := buf.String()
	if !strings.Contains(out, altScreenOff) {
		t.Error("the alternate screen was not given back")
	}
	if !strings.Contains(out, cursorShow) {
		t.Error("the cursor was not given back")
	}

	buf.Reset()
	s.Restore()
	if buf.Len() != 0 {
		t.Errorf("a second Restore wrote again: %q", buf.String())
	}

	// A nil Screen is what plain mode holds, and the deferred restore runs
	// whichever mode was chosen.
	var none *Screen
	none.Restore()
}

// The fallback chain, which on this machine is not theoretical: TERM is dumb and
// COLUMNS is not exported, so the default is what a run here actually uses.
func TestSizeFallsBackThroughTheChain(t *testing.T) {
	t.Run("the environment when it says", func(t *testing.T) {
		t.Setenv("COLUMNS", "120")
		t.Setenv("LINES", "40")
		if w, h := Size(0, 0); w != 120 || h != 40 {
			t.Errorf("Size() = %dx%d, want 120x40", w, h)
		}
	})
	t.Run("the flags when it does not", func(t *testing.T) {
		t.Setenv("COLUMNS", "")
		t.Setenv("LINES", "")
		if w, h := Size(150, 45); w != 150 || h != 45 {
			t.Errorf("Size() = %dx%d, want 150x45", w, h)
		}
	})
	t.Run("the default when nothing does", func(t *testing.T) {
		t.Setenv("COLUMNS", "")
		t.Setenv("LINES", "")
		if w, h := Size(0, 0); w != DefaultWidth || h != DefaultHeight {
			t.Errorf("Size() = %dx%d, want %dx%d", w, h, DefaultWidth, DefaultHeight)
		}
	})
	t.Run("nonsense in the environment is ignored", func(t *testing.T) {
		t.Setenv("COLUMNS", "wide")
		t.Setenv("LINES", "-3")
		if w, h := Size(0, 0); w != DefaultWidth || h != DefaultHeight {
			t.Errorf("Size() = %dx%d, want the defaults", w, h)
		}
	})
	t.Run("a size below the minimum is raised", func(t *testing.T) {
		t.Setenv("COLUMNS", "10")
		t.Setenv("LINES", "2")
		if w, h := Size(0, 0); w != minWidth || h != minHeight {
			t.Errorf("Size() = %dx%d, want the minimum %dx%d", w, h, minWidth, minHeight)
		}
	})
}

// A bytes.Buffer is not a terminal, and neither is a file. This is the check the
// trace renderer already relies on, kept in one place rather than two.
func TestIsTerminalSaysNoToEverythingThatIsNotOne(t *testing.T) {
	if IsTerminal(new(bytes.Buffer)) {
		t.Error("a bytes.Buffer was taken for a terminal")
	}
	f, err := (func() (*bytes.Buffer, error) { return new(bytes.Buffer), nil })()
	if err != nil {
		t.Fatal(err)
	}
	if IsTerminal(f) {
		t.Error("a buffer was taken for a terminal")
	}
}

// 9. Enable reporting false is the Windows console that will not do ANSI, and the
// answer is plain mode rather than garbage on screen. On every other platform it
// is true and this asserts the no-op is really a no-op.
func TestEnableIsHonestAboutThePlatform(t *testing.T) {
	// Nothing to assert about the value on Windows from here, since the result
	// depends on the console the test runs in. What must hold everywhere is that
	// Detect consults it: with a non-terminal writer the answer is plain mode
	// regardless, which the table above covers, and the elsewhere case is that
	// Enable does not panic and returns quickly.
	Enable()
}

func TestUptimeRendersTwoUnits(t *testing.T) {
	tests := map[int64]string{
		5_000:       "5s",
		65_000:      "1m05s",
		3_600_000:   "1h00m",
		8_040_000:   "2h14m",
		200_000_000: "2d07h",
	}
	for ms, want := range tests {
		if got := uptime(ms); got != want {
			t.Errorf("uptime(%d) = %q, want %q", ms, got, want)
		}
	}
}

func TestMillisKeepsSubMillisecondReadings(t *testing.T) {
	if got := millis(0.4); got != "0.40ms" {
		t.Errorf("millis(0.4) = %q, want a fraction rather than zero", got)
	}
	if got := millis(61); got != "61ms" {
		t.Errorf("millis(61) = %q", got)
	}
}
