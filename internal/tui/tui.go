// Package tui draws a dashboard over a running server, using nothing but bytes
// on stdout.
//
// There is no raw mode anywhere in here, and that is the decision the package is
// arranged around rather than a corner that was cut. Raw mode means the TCGETS
// and TCSETS ioctls on Linux, TIOCGETA and TIOCSETA with different constants on
// macOS, and SetConsoleMode through kernel32 on Windows: three implementations
// of a thing that exists to read a keypress. A dashboard is an observability
// surface, not an editor. It redraws on a timer and quits on Ctrl-C, which needs
// no terminal state on any platform, and the terminal is therefore never left in
// a state this program has to remember to undo.
//
// The one platform-specific call left is ANSI processing on the Windows console,
// isolated in console_windows.go and console_other.go, and it is the only build
// tag in this repository.
//
// Rendering is a pure function of a Frame. Every test in this package draws into
// a bytes.Buffer and asserts on the bytes, because a frame builder that needs a
// terminal to be tested is a frame builder nobody tests.
package tui

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/DevInIndia/hollow/internal/control"
)

// The escape sequences this package uses, in full. Anything not on this list is
// not written, which is what makes the plain-mode promise checkable.
const (
	altScreenOn  = "\x1b[?1049h"
	altScreenOff = "\x1b[?1049l"
	cursorHide   = "\x1b[?25l"
	cursorShow   = "\x1b[?25h"
	cursorHome   = "\x1b[H"
	clearLine    = "\x1b[K"
	reset        = "\x1b[0m"
)

// Sixteen-colour foregrounds only. No 256-colour assumptions, because the
// terminals that do not have them are exactly the ones that would render the
// escape as text.
const (
	colBold  = "\x1b[1m"
	colDim   = "\x1b[90m"
	colLabel = "\x1b[36m"
	colGood  = "\x1b[32m"
	colWarn  = "\x1b[33m"
	colAlert = "\x1b[31m"
)

// Defaults for the frame when nothing better is known. See Size.
const (
	DefaultWidth  = 100
	DefaultHeight = 30

	// Below these the layout stops being a layout. A frame smaller than this is
	// drawn at this size and allowed to overflow the terminal, which is ugly and
	// legible, where a frame computed from a negative body height is neither.
	minWidth  = 40
	minHeight = 12
)

// eventsKept bounds the live feed. The tail of it is never drawn, so keeping
// more than a tall terminal can show is only a way to hold memory.
const eventsKept = 64

// qpsKept is how many per-second samples the sparkline remembers.
const qpsKept = 120

// Charset is the vocabulary a frame is drawn with.
//
// The same shape as the charset in the trace renderer, and for the same reason:
// the choice between box drawing and ASCII is one decision made once at the top,
// not a conditional at every place a line is drawn. Every glyph in here occupies
// one terminal column, which is what lets width be counted in runes.
type Charset struct {
	TopLeft, TopRight       string
	BottomLeft, BottomRight string
	Horizontal, Vertical    string
	TeeDown, TeeUp          string
	TeeLeft, TeeRight       string

	// Ellipsis is the middle of a truncated name. It must travel with the rest
	// of the set: a renderer that switches the sparkline to ASCII and leaves
	// U+2026 in the truncation helper passes every test a person runs by eye and
	// fails the one that counts bytes.
	Ellipsis string

	// Spark is eight levels, lowest first.
	Spark []string

	// Markers, which carry meaning on their own so that colour never has to.
	Hit, Stale string
}

// Unicode is the set for a terminal with the font.
var Unicode = Charset{
	TopLeft: "┌", TopRight: "┐", BottomLeft: "└", BottomRight: "┘",
	Horizontal: "─", Vertical: "│",
	TeeDown: "┬", TeeUp: "┴", TeeLeft: "┤", TeeRight: "├",
	Ellipsis: "…",
	Spark:    []string{"▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"},
	Hit:      "+", Stale: "~",
}

// ASCII is the set for a pipe, a file, or a console without the font.
var ASCII = Charset{
	TopLeft: "+", TopRight: "+", BottomLeft: "+", BottomRight: "+",
	Horizontal: "-", Vertical: "|",
	TeeDown: "+", TeeUp: "+",
	TeeLeft: "+", TeeRight: "+",
	Ellipsis: "...",
	Spark:    []string{".", ".", ":", ":", "-", "=", "+", "#"},
	Hit:      "+", Stale: "~",
}

// Frame is everything on screen, and the state needed to work out the parts that
// are not in any single snapshot.
type Frame struct {
	// Target is the control address, shown in the header so that two dashboards
	// side by side are told apart.
	Target string

	// Charset and Colour are the rendering mode, decided once by Detect.
	Charset Charset
	Colour  bool

	// Snap is the most recent snapshot, or nil before the first one arrives.
	// It is deliberately kept through a disconnect, so the last known state
	// stays on screen behind the banner rather than the screen going blank at
	// the moment somebody wants to read it.
	Snap *control.Snapshot

	// Banner is shown when it is not empty, and means the server is not there.
	Banner string

	events []control.Event
	qps    []float64

	// Carried between snapshots to turn a counter into a rate. The server's own
	// uptime is the clock, so a slow or paused dashboard does not invent a spike
	// out of its own scheduling.
	lastTotal  uint64
	lastUptime int64
	haveLast   bool
}

// Observe takes a snapshot and updates the derived state.
func (f *Frame) Observe(s *control.Snapshot) {
	f.Snap = s
	if f.haveLast {
		if elapsed := float64(s.UptimeMS-f.lastUptime) / 1000; elapsed > 0 {
			rate := float64(s.QueriesTotal-f.lastTotal) / elapsed
			f.qps = append(f.qps, rate)
			if len(f.qps) > qpsKept {
				f.qps = f.qps[len(f.qps)-qpsKept:]
			}
		}
	}
	f.lastTotal, f.lastUptime, f.haveLast = s.QueriesTotal, s.UptimeMS, true
}

// Reset forgets the derived state, which is what a reconnect needs.
//
// Without it the first snapshot from a restarted server reads as a huge negative
// interval, because its uptime went backwards, and the sparkline would carry a
// spike that describes nothing that happened.
func (f *Frame) Reset() {
	f.haveLast = false
	f.qps = nil
}

// Add records one answered query for the live feed, newest first.
func (f *Frame) Add(e control.Event) {
	f.events = append([]control.Event{e}, f.events...)
	if len(f.events) > eventsKept {
		f.events = f.events[:eventsKept]
	}
}

// Render writes the frame as plain text, one row per line and no escape
// sequences at all. This is what plain mode appends and what the tests read.
func (f *Frame) Render(w io.Writer, width, height int) {
	io.WriteString(w, strings.Join(f.rows(width, height), "\n")+"\n")
}

// Paint writes the frame in place: cursor home, then every row followed by a
// clear to end of line.
//
// One Write for the whole frame. Clearing the screen and then drawing produces a
// visible flash on every refresh, and writing line by line lets the terminal
// render a half-updated frame. The per-line clear is what makes the redraw safe
// without the clear: a row that got shorter has its tail removed as it is
// rewritten.
func (f *Frame) Paint(w io.Writer, width, height int) {
	var b bytes.Buffer
	b.WriteString(cursorHome)
	for _, row := range f.rows(width, height) {
		b.WriteString(row)
		b.WriteString(clearLine)
		b.WriteByte('\n')
	}
	w.Write(b.Bytes())
}

// rows builds the frame, every row exactly width columns wide.
func (f *Frame) rows(width, height int) []string {
	width = max(width, minWidth)
	height = max(height, minHeight)
	cs := f.Charset
	if cs.Vertical == "" {
		cs = ASCII
	}

	// Two vertical borders, so the drawable interior is width-2. The interior is
	// split into two columns with a single divider between them; the live feed
	// gets the larger share because its rows are the ones that carry a name, an
	// address and a verdict at once.
	inner := width - 2
	leftW := inner * 3 / 5
	rightW := inner - leftW - 1

	// Chrome is the seven rows that are not the body: the two borders, the two
	// separators, the two summary lines and the footer.
	body := height - 7

	// Every cell below arrives already padded to exactly its column width, which
	// is what lets this function do nothing but put borders between them. See
	// cell for why the padding cannot happen out here.
	out := make([]string, 0, height)
	out = append(out, f.header(cs, width))
	out = append(out, f.bar(cs, f.summary(inner)))
	out = append(out, f.bar(cs, f.sparkline(cs, inner)))
	out = append(out, f.split(cs, leftW, rightW, cs.TeeDown))

	left := f.feed(cs, leftW, body)
	right := f.panels(cs, rightW, body)
	for i := range body {
		out = append(out, cs.Vertical+left[i]+cs.Vertical+right[i]+cs.Vertical)
	}

	out = append(out, f.split(cs, leftW, rightW, cs.TeeUp))
	out = append(out, f.bar(cs, f.footer(inner)))
	out = append(out, cs.BottomLeft+strings.Repeat(cs.Horizontal, inner)+cs.BottomRight)
	return out
}

// cell renders one column of one row: cut to fit, padded to exactly w columns,
// and only then coloured.
//
// The order is the whole point and getting it wrong is a bug the eye cannot see.
// An escape sequence is several bytes and no columns, so padding a string that
// already carries one computes the width from the escape as well and pads short
// by exactly its length. The result is a layout that drifts on precisely the rows
// that happen to be coloured, which is why a test compares a coloured frame
// against a plain one with the sequences stripped rather than trusting this
// comment.
func (f *Frame) cell(text string, w int, colour string) string {
	return f.paint(pad(truncate(text, w, f.Charset.Ellipsis), w), colour)
}

// header is the top border with the title written into it.
func (f *Frame) header(cs Charset, width int) string {
	title := " hollow "
	right := " " + f.Target + " "
	if f.Snap != nil {
		right = fmt.Sprintf(" %s  up %s ", f.Target, uptime(f.Snap.UptimeMS))
	}

	// The rule between the two, computed from what is left. Two dashes on each
	// side of the title keep it from touching the corner.
	fill := width - 2 - runes(title) - runes(right) - 2
	if fill < 0 {
		// Too narrow for both. The address is what gets dropped, since the title
		// is the only thing that says which program this is.
		right, fill = "", width-2-runes(title)-2
	}
	line := cs.TopLeft + cs.Horizontal + title + strings.Repeat(cs.Horizontal, max(fill, 0)) + right + cs.Horizontal + cs.TopRight
	return f.paint(pad(line, width), colBold)
}

// bar wraps one already-padded full-width line in the side borders.
func (f *Frame) bar(cs Charset, content string) string {
	return cs.Vertical + content + cs.Vertical
}

// split is a separator carrying the column divider, so the two halves line up
// with the body rows between them.
func (f *Frame) split(cs Charset, leftW, rightW int, tee string) string {
	return cs.TeeRight + strings.Repeat(cs.Horizontal, leftW) + tee +
		strings.Repeat(cs.Horizontal, rightW) + cs.TeeLeft
}

// summary is the headline row of live figures.
func (f *Frame) summary(w int) string {
	if f.Snap == nil {
		return f.cell(" waiting for the first snapshot", w, colDim)
	}
	s := f.Snap
	cache := "cache n/a"
	if lookups := s.CacheHits + s.CacheMisses; lookups > 0 {
		cache = fmt.Sprintf("cache %.1f%%", 100*float64(s.CacheHits)/float64(lookups))
	}
	blocked := "blocked 0.0%"
	if s.QueriesTotal > 0 {
		blocked = fmt.Sprintf("blocked %.1f%%", 100*float64(s.QueriesBlocked)/float64(s.QueriesTotal))
	}
	return f.cell(fmt.Sprintf(" qps %-7s %-13s %-15s p50 %-9s p99 %s",
		trim(f.currentQPS()), cache, blocked, millis(s.LatencyP50MS), millis(s.LatencyP99MS)), w, "")
}

// sparkline draws the recent query rate, or says there is nothing yet.
func (f *Frame) sparkline(cs Charset, w int) string {
	if len(f.qps) == 0 {
		return f.cell(" no rate yet, two snapshots are needed for one interval", w, colDim)
	}

	// The most recent samples, right-aligned, so the newest reading is always at
	// the same place on screen rather than wandering as history accumulates.
	show := f.qps
	if len(show) > w-2 {
		show = show[len(show)-(w-2):]
	}
	high := 0.0
	for _, v := range show {
		high = max(high, v)
	}

	var b strings.Builder
	b.WriteByte(' ')
	for _, v := range show {
		level := 0
		if high > 0 {
			// Scaled against the tallest sample on screen rather than an absolute
			// rate, because the shape over time is the thing worth seeing and no
			// fixed ceiling suits both a laptop and a busy resolver.
			level = int(v / high * float64(len(cs.Spark)-1))
		}
		b.WriteString(cs.Spark[min(max(level, 0), len(cs.Spark)-1)])
	}
	return f.cell(b.String(), w, colGood)
}

// feed builds the left column: a header and then the most recent queries.
func (f *Frame) feed(cs Charset, w, height int) []string {
	rows := make([]string, 0, height)
	rows = append(rows, f.cell(" LIVE", w, colLabel))

	for _, e := range f.events {
		if len(rows) >= height {
			break
		}
		verdict := e.Rcode
		mark := " "
		switch {
		case e.Blocked:
			verdict = "blocked"
		case e.Stale:
			mark = cs.Stale
		case e.CacheHit:
			mark = cs.Hit
		}

		// The name takes whatever the fixed columns leave, because everything
		// else on the row has a bounded width and a name does not. The count is
		// the separators and the five fixed fields, marker included.
		const fixed = 1 + 8 + 1 + 15 + 1 + 5 + 1 + 8 + 1 + 1 + 1 + 1
		nameW := max(w-fixed, 8)
		row := fmt.Sprintf(" %-8s %-15s %-5s %-8s %-*s %s ",
			e.At.Format("15:04:05"),
			truncate(e.Client, 15, cs.Ellipsis),
			truncate(e.Type, 5, cs.Ellipsis),
			truncate(verdict, 8, cs.Ellipsis),
			nameW, truncate(e.Name, nameW, cs.Ellipsis),
			mark)
		rows = append(rows, f.cell(row, w, f.outcomeColour(e)))
	}

	if len(f.events) == 0 && len(rows) < height {
		rows = append(rows, f.cell(" nothing answered yet", w, colDim))
	}
	for len(rows) < height {
		rows = append(rows, f.cell("", w, ""))
	}
	return rows
}

// rowFixed is everything on a top-N row that is not the name or the count: the
// leading space, the two-column rank, and the three separating spaces. The rank
// is two columns because a list of ten reaches double figures on its last row,
// and a row that widens there would be the only crooked one on screen.
const rowFixed = 1 + 2 + 1 + 1 + 1

// panels builds the right column: three top-N lists stacked with a blank line
// between them.
func (f *Frame) panels(cs Charset, w, height int) []string {
	rows := make([]string, 0, height)
	blank := f.cell("", w, "")
	if f.Snap == nil {
		for len(rows) < height {
			rows = append(rows, blank)
		}
		return rows
	}

	add := func(label string, items []control.Item) {
		if len(rows) >= height {
			return
		}
		if len(rows) > 0 {
			rows = append(rows, blank)
		}
		rows = append(rows, f.cell(" "+label, w, colLabel))
		for i, it := range items {
			if len(rows) >= height {
				return
			}
			// The count is right-aligned against the edge so two rows can be
			// compared without reading either number, and the name takes what is
			// left, since a count has a bounded width and a name does not. The
			// arithmetic has to come out at exactly w: a row one column too wide
			// is truncated by cell, which puts an ellipsis through the middle of
			// a name that fitted perfectly well.
			count := strconv.FormatUint(it.Count, 10)
			nameW := max(w-len(count)-rowFixed, 6)
			rows = append(rows, f.cell(fmt.Sprintf(" %2d %-*s %s ",
				i+1, nameW, truncate(it.Name, nameW, cs.Ellipsis), count), w, ""))
		}
	}
	add("TOP NAMES", f.Snap.TopDomains)
	add("TOP BLOCKED", f.Snap.TopBlocked)
	add("CLIENTS", f.Snap.TopClients)

	for len(rows) < height {
		rows = append(rows, blank)
	}
	return rows[:height]
}

// footer carries the numbers that describe the server rather than the traffic,
// and the one instruction this program has.
func (f *Frame) footer(w int) string {
	if f.Banner != "" {
		return f.cell(" "+f.Banner+"   ^C quit", w, colAlert)
	}
	if f.Snap == nil {
		return f.cell(" connecting   ^C quit", w, colDim)
	}
	s := f.Snap
	line := fmt.Sprintf(" cache %d entries   stale %d   dropped %d   ^C quit",
		s.CacheEntries, s.StaleServed, s.EventsDropped)

	// Dropped events are the visible proof that the non-blocking broadcast is
	// working, so the number is always on screen and turns colour when it moves
	// rather than being hidden until it matters.
	if s.EventsDropped > 0 {
		return f.cell(line, w, colWarn)
	}
	return f.cell(line, w, "")
}

// currentQPS is the most recent sample.
func (f *Frame) currentQPS() float64 {
	if len(f.qps) == 0 {
		return 0
	}
	return f.qps[len(f.qps)-1]
}

// paint wraps an already-padded string in a colour, when colour is on. Callers
// go through cell rather than calling this directly; see cell for why.
func (f *Frame) paint(s, colour string) string {
	if !f.Colour || colour == "" {
		return s
	}
	return colour + s + reset
}

// outcomeColour picks the colour for a feed row. The marker and the word already
// say which outcome it is, so this only makes a row easier to find and carries
// nothing that is lost without it.
func (f *Frame) outcomeColour(e control.Event) string {
	switch {
	case e.Blocked:
		return colAlert
	case e.Rcode != "NOERROR":
		return colWarn
	}
	return ""
}

// runes counts display columns.
//
// Every glyph this package writes is one column wide: ASCII, box drawing, the
// block elements and U+2026 are all single-width. That is what makes a rune
// count the right answer here, and it is why a wide CJK glyph would not be.
func runes(s string) int { return utf8.RuneCountInString(s) }

// pad fixes s to exactly w columns, cutting if it is too long.
func pad(s string, w int) string {
	if n := runes(s); n < w {
		return s + strings.Repeat(" ", w-n)
	} else if n > w {
		return string([]rune(s)[:w])
	}
	return s
}

// truncate shortens s to w columns by removing the middle.
//
// The middle rather than the tail because the ends of a domain name are the
// parts that identify it: a list of names all cut to "cdn.assets.exam…" is a
// list of one name.
//
// The ellipsis is a parameter rather than a constant, which is the entire point
// of this function. A helper that hardcodes U+2026 passes every review by eye
// and then puts a three-byte rune into output that promised to be ASCII.
func truncate(s string, w int, ellipsis string) string {
	r := []rune(s)
	if len(r) <= w {
		return s
	}
	if w <= 0 {
		return ""
	}
	e := runes(ellipsis)
	if w <= e {
		return string(r[:w])
	}
	keep := w - e
	head := (keep + 1) / 2
	return string(r[:head]) + ellipsis + string(r[len(r)-(keep-head):])
}

// trim renders a rate without trailing noise. A rate of 12 is 12, not 12.00.
func trim(v float64) string {
	if v >= 100 || v == float64(int64(v)) {
		return strconv.FormatInt(int64(v), 10)
	}
	return strconv.FormatFloat(v, 'f', 1, 64)
}

// millis renders a millisecond figure at a precision that suits its size, so a
// p50 of 0.4 ms and a p99 of 61 ms are both readable in one format.
func millis(v float64) string {
	if v < 10 {
		return fmt.Sprintf("%.2fms", v)
	}
	return fmt.Sprintf("%.0fms", v)
}

// uptime renders a duration the way a status line should: the two largest units
// and nothing else.
func uptime(ms int64) string {
	d := time.Duration(ms) * time.Millisecond
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd%02dh", int(d.Hours())/24, int(d.Hours())%24)
}

// Size decides the frame size.
//
// Getting the real size means TIOCGWINSZ on Unix and GetConsoleScreenBufferInfo
// on Windows, which is the platform problem this package exists without. The
// chain here costs nothing and is honest about what it is: an environment that
// says, a flag that overrides, and a default that fits a normal terminal. It is
// documented in the README as a limitation rather than presented as a feature.
//
// The environment is consulted first because it is the terminal describing
// itself, and the flags are the answer for the common case where it does not:
// most shells set COLUMNS without exporting it, so a child process usually sees
// nothing at all.
func Size(widthFlag, heightFlag int) (int, int) {
	w := envInt("COLUMNS")
	h := envInt("LINES")
	if w == 0 {
		w = widthFlag
	}
	if h == 0 {
		h = heightFlag
	}
	if w == 0 {
		w = DefaultWidth
	}
	if h == 0 {
		h = DefaultHeight
	}
	return max(w, minWidth), max(h, minHeight)
}

func envInt(name string) int {
	n, err := strconv.Atoi(os.Getenv(name))
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

// Mode is how a dashboard should draw itself.
type Mode struct {
	// Fullscreen means the alternate screen and in-place redraws. False means
	// plain mode: a frame appended per interval, with no escape sequence written
	// anywhere.
	Fullscreen bool
	Colour     bool
	Charset    Charset
}

// Detect works out how to draw, from where the output is going and what the
// caller asked for.
//
// Escape sequences going somewhere that cannot interpret them is the failure
// that looks worst and is easiest to avoid: a pipe captures them as literal
// text, and a console without ANSI processing prints them. Every one of the
// signals below is therefore a reason to stop writing them entirely rather than
// a reason to write fewer.
func Detect(w io.Writer, ascii, plain bool) Mode {
	term := os.Getenv("TERM")
	capable := IsTerminal(w) && term != "" && term != "dumb" && Enable()

	m := Mode{
		Fullscreen: capable && !plain,
		// NO_COLOR is honoured whatever its value, per the convention: the
		// variable being present is the instruction.
		Colour:  capable && !plain && os.Getenv("NO_COLOR") == "",
		Charset: Unicode,
	}
	if ascii || !m.Fullscreen {
		m.Charset = ASCII
	}
	return m
}

// IsTerminal reports whether w is a character device.
//
// The standard library answer to a question that is normally an import, and one
// of the few places where it is also the shorter one. Anything that is not an
// *os.File, which is every buffer a test draws into, is not a terminal.
func IsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// Screen owns the terminal state a fullscreen dashboard takes.
//
// The whole of that state is: the alternate screen, and the cursor. Restore puts
// both back and may be called more than once, because it is called from a defer
// and could be reached twice by a caller that is being careful.
type Screen struct {
	w        io.Writer
	entered  bool
	restored bool
}

// Enter switches to the alternate screen and hides the cursor.
func Enter(w io.Writer) *Screen {
	s := &Screen{w: w, entered: true}
	io.WriteString(w, altScreenOn+cursorHide+cursorHome)
	return s
}

// Restore puts the terminal back as it was found.
//
// A tool that leaves a terminal with no scrollback and no cursor is remembered
// for that and for nothing else, so this runs from a defer, and the signal
// handler is deliberately left installed until after it has: a second Ctrl-C
// arriving during shutdown would otherwise be handled by the default disposition
// and kill the process between the last frame and this.
func (s *Screen) Restore() {
	if s == nil || !s.entered || s.restored {
		return
	}
	s.restored = true
	io.WriteString(s.w, cursorShow+altScreenOff)
}
