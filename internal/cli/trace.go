package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/DevInIndia/hollow/internal/cache"
	"github.com/DevInIndia/hollow/internal/resolver"
	"github.com/DevInIndia/hollow/internal/tui"
	"github.com/DevInIndia/hollow/internal/wire"
)

// Trace runs the trace verb and returns the process exit code.
//
// It resolves the name through the same code path as resolve, with the same
// resolver, and renders the delegation chain that walk actually took. Nothing
// here simulates or replays anything: every line comes from a Step the resolver
// emitted as it sent the packet, which is why a trace and a resolve can never
// disagree about what happened.
func Trace(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("hollow trace", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		port    = fs.Uint("port", 53, "port to query")
		timeout = fs.Duration("timeout", resolver.DefaultTimeout, "deadline for one exchange with one server")
		hints   = fs.String("hints", "", "root hints in named.root format; default is the compiled-in list")
		asJSON  = fs.Bool("json", false, "output the steps as JSON")
		ascii   = fs.Bool("ascii", false, "draw the tree with ASCII instead of box-drawing characters")
		mixed   = fs.Bool("dns0x20", true, "randomise the case of the query name, and refuse a reply that does not echo it")
		cached  = fs.Bool("cache", false, "cache within this one walk, so a CNAME chain reuses the delegations it already found")
	)
	fs.Usage = func() {
		fmt.Fprint(stderr, "usage: hollow trace [flags] <name> [type]\n\nflags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return ExitFailure
	}

	if fs.NArg() < 1 || fs.NArg() > 2 {
		fs.Usage()
		return ExitFailure
	}
	name, err := wire.ParseName(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "hollow: %v\n", err)
		return ExitFailure
	}
	qtype := wire.TypeA
	if fs.NArg() == 2 {
		if qtype, err = wire.ParseType(fs.Arg(1)); err != nil {
			fmt.Fprintf(stderr, "hollow: %v\n", err)
			return ExitFailure
		}
	}
	if *port == 0 || *port > 65535 {
		fmt.Fprintf(stderr, "hollow: --port %d is not a port\n", *port)
		return ExitFailure
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The steps arrive on the resolving goroutine, which is this one, so a plain
	// slice needs no lock. Appending rather than rendering as they arrive is what
	// lets the tree know how wide its columns are before it draws anything.
	var steps []resolver.Step
	collect := func(s resolver.Step) { steps = append(steps, s) }

	q := wire.Question{Name: name, Type: qtype, Class: wire.ClassIN}
	tr := resolver.Transport{Timeout: *timeout}
	if *mixed {
		tr.Case = resolver.NewCasing()
	}

	r, err := newResolver(tr, *hints, uint16(*port), collect)
	if err != nil {
		fmt.Fprintf(stderr, "hollow: %v\n", err)
		return ExitFailure
	}
	// Off by default, because a trace is a picture of a walk and a cache is a
	// way of not walking. Turned on, it shows the other half: a CNAME chain
	// that would restart at the root for every link instead picks up at the
	// deepest zone it already knows, and the tree shows that happening.
	if *cached {
		r.Cache = cache.New(cache.Config{Entries: 1024})
	}

	start := time.Now()
	res, resErr := r.Resolve(ctx, q)
	elapsed := time.Since(start)

	if *asJSON {
		if err := writeSteps(stdout, steps); err != nil {
			fmt.Fprintf(stderr, "hollow: writing the JSON trace: %v\n", err)
			return ExitFailure
		}
	} else {
		drawTrace(stdout, q, steps, res, elapsed, glyphs(*ascii, stdout))
	}

	// A failed walk still has a trace worth reading, and often the trace is the
	// answer to why it failed, so the render happens either way and the error
	// goes to stderr underneath it.
	if resErr != nil {
		fmt.Fprintf(stderr, "hollow: %v\n", resErr)
		return ExitFailure
	}
	switch res.Reply.Msg.Header.Rcode {
	case wire.RcodeSuccess:
		return ExitOK
	case wire.RcodeNXDomain:
		return ExitNXDomain
	default:
		return ExitFailure
	}
}

// charset is the set of characters the tree is drawn with. Box drawing is the
// default and ASCII is the fallback, because a Windows console without the font
// and a pipe into a file both turn U+2514 into noise.
//
// pad is a level of indentation and is the width of branch, so a server line
// hangs off its zone and the next zone starts where the connector ended.
type charset struct {
	branch string
	pad    string
}

var (
	unicodeSet = charset{branch: "└─ ", pad: "   "}
	asciiSet   = charset{branch: "+- ", pad: "   "}
)

// glyphs picks the character set: ASCII when asked for, and ASCII whenever the
// output is not a terminal. Detecting that with os.Stat rather than a terminal
// library is one of the few places where the standard library answer is also
// the shorter one.
func glyphs(ascii bool, w io.Writer) charset {
	if ascii || !isTerminal(w) {
		return asciiSet
	}
	return unicodeSet
}

// isTerminal reports whether w is a character device.
//
// The implementation lives in internal/tui, which needs the same answer for the
// same reason and is where the rest of the terminal knowledge in this project
// sits. Two copies of a six-line check is two places for it to be wrong.
func isTerminal(w io.Writer) bool { return tui.IsTerminal(w) }

// drawTrace renders the walk as a tree: a line per zone, and under it the
// server that was asked, with what it said.
func drawTrace(w io.Writer, q wire.Question, steps []resolver.Step, res *resolver.Result, elapsed time.Duration, cs charset) {
	fmt.Fprintf(w, "%s %s\n\n", q.Name, q.Type)

	// Servers arrive as addresses, because that is what glue carries and what
	// the packet was actually sent to. The name comes from the referral that
	// handed the address over, so labelling a server this way repeats what a
	// zone said rather than looking anything up.
	names := serverNames(steps)

	rows := make([]row, 0, len(steps)*2)
	var (
		// noZone is a name no zone can equal, so the first zone of a walk always
		// prints and always starts at the level the walk began on.
		cur     = state{zone: noZone}
		nested  int
		saved   []state
		cached  int
		queries int
		zones   int
	)
	for _, s := range steps {
		switch {
		case s.Nested > nested:
			// A referral arrived without glue, so the address of one of its
			// nameservers had to be resolved before the walk could continue.
			// That is the case that separates an iterative resolver from a
			// thing that follows glue, and it is worth seeing indented under
			// the referral that caused it.
			saved = append(saved, cur)
			cur = state{indent: cur.indent + 1, base: cur.indent + 1, zone: noZone, name: s.Query.Name}
			rows = append(rows, row{indent: cur.indent, left: fmt.Sprintf("(no glue, resolving %s)", s.Query.Name)})
		case s.Nested < nested:
			cur = saved[len(saved)-1]
			saved = saved[:len(saved)-1]
		case s.Query.Name != cur.name && cur.name != "":
			// Same walk, different name: the answer was a CNAME and the chain
			// moved on. That is a fresh walk from the root for the new name,
			// not a deeper step in the old one, so it goes back to the level
			// this walk started at instead of indenting further.
			cur = state{indent: cur.base, base: cur.base, zone: noZone, name: s.Query.Name}
			rows = append(rows, row{indent: cur.indent, left: fmt.Sprintf("(cname, now resolving %s)", s.Query.Name)})
		}
		nested = s.Nested
		cur.name = s.Query.Name

		if s.Cached() {
			cached++
			rows = append(rows, row{
				indent: cur.indent,
				branch: true,
				left:   "cache",
				detail: fmt.Sprintf("%s, no packet sent", s.Kind),
			})
			continue
		}
		queries++

		if !s.Zone.EqualFold(cur.zone) {
			// Every zone after the first sits one level deeper, which is what
			// makes the picture a delegation chain rather than a list.
			if cur.zone != noZone {
				cur.indent++
			}
			cur.zone = s.Zone
			zones++
			label := string(cur.zone)
			if cur.zone == wire.Root {
				label = ". (root)"
			}
			rows = append(rows, row{indent: cur.indent, left: label})
		}

		left := s.Server.String()
		if n, ok := names[s.Server.Addr()]; ok {
			left = fmt.Sprintf("%s (%s)", n, s.Server)
		}

		rows = append(rows, row{
			indent: cur.indent,
			branch: true,
			left:   left,
			rtt:    stepRTT(s),
			detail: stepDetail(s),
		})

		// The 0x20 nonce is shown rather than asserted. A reader can see that
		// the name on the wire was not the name asked about, and that the reply
		// echoed it and was accepted, which is the whole mechanism in one line.
		if sent := sentName(s); sent != "" {
			rows = append(rows, row{indent: cur.indent + 1, left: "asked as " + string(sent)})
		}
	}

	if len(rows) == 0 {
		fmt.Fprintln(w, "no exchanges: the resolver answered before it asked anyone")
	}
	writeRows(w, rows, cs)

	// The records go under the tree rather than inside it, because they are the
	// answer and the tree is how it was found.
	if res != nil && res.Reply != nil {
		fmt.Fprintln(w)
		for _, rr := range append(append([]wire.RR{}, res.CNAMEs...), res.Reply.Msg.Answers...) {
			fmt.Fprintf(w, "%s %d %s %s %s\n", rr.Name, rr.TTL, className(rr.Class), rr.Type, rdataText(rr.Data))
		}
	}

	fmt.Fprintf(w, "\n%s, %s, %s, %s\n",
		plural(queries, "query", "queries"),
		plural(zones, "zone", "zones"),
		plural(cached, "answer from cache", "answers from cache"),
		elapsed.Round(time.Millisecond))
}

// noZone is the sentinel for "no zone printed yet in this walk". It is not a
// name any zone can have, because a name always ends in a dot.
const noZone wire.Name = "\x00"

// state is where the renderer is inside one walk, and what it restores to when
// a sub-resolution finishes.
type state struct {
	indent int       // the level the next zone of this walk prints at
	base   int       // the level this walk started at, which a CNAME hop returns to
	zone   wire.Name // the zone last printed, or noZone
	name   wire.Name // the name being resolved, which changes when a CNAME is followed
}

// row is one rendered line, before the columns are aligned.
type row struct {
	indent int
	branch bool // draw the connector, meaning this line is a server rather than a zone
	left   string
	rtt    string
	detail string
}

// writeRows aligns the left column across the whole tree and then writes it. The
// width is measured rather than fixed because the widest line is a nameserver
// name nobody can predict, and a column that a long name overflows is worse than
// one that is wider than it needs to be.
func writeRows(w io.Writer, rows []row, cs charset) {
	width := 0
	for _, r := range rows {
		if n := len(prefix(r, cs)) + len(r.left); n > width {
			width = n
		}
	}
	for _, r := range rows {
		line := prefix(r, cs) + r.left
		if r.rtt == "" && r.detail == "" {
			fmt.Fprintln(w, line)
			continue
		}
		fmt.Fprintf(w, "%-*s  %8s  %s\n", width, line, r.rtt, r.detail)
	}
}

func prefix(r row, cs charset) string {
	if r.branch {
		return strings.Repeat(cs.pad, r.indent) + cs.branch
	}
	return strings.Repeat(cs.pad, r.indent)
}

// sentName is the name as it left, when that differs from the name asked
// about, and empty otherwise.
func sentName(s resolver.Step) wire.Name {
	if s.Reply == nil || s.Reply.Sent == "" || s.Reply.Sent == s.Query.Name {
		return ""
	}
	return s.Reply.Sent
}

func stepRTT(s resolver.Step) string {
	if s.Reply == nil {
		return ""
	}
	return s.Reply.RTT.Round(time.Millisecond).String()
}

// stepDetail is the right-hand column: what came back, how big it was, and how
// many servers this one was chosen from.
func stepDetail(s resolver.Step) string {
	if s.Err != nil {
		return fmt.Sprintf("%s (1 of %s)", s.Err, plural(s.Candidates, "server", "servers"))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s, %s, %d B", s.Reply.Protocol, s.Kind, s.Reply.Size)

	if s.Kind == resolver.KindReferral {
		ns, glue := referralSize(s.Reply.Msg)
		fmt.Fprintf(&b, ", %s", plural(ns, "NS", "NS"))
		if glue > 0 {
			fmt.Fprintf(&b, " + %d glue", glue)
		} else {
			b.WriteString(", no glue")
		}
	}
	if s.Candidates > 1 {
		fmt.Fprintf(&b, ", 1 of %d servers", s.Candidates)
	}
	return b.String()
}

// referralSize counts what a referral carried, which is the number that says
// whether the next step is one packet or three.
func referralSize(m *wire.Message) (ns, glue int) {
	for _, rr := range m.Authority {
		if rr.Type == wire.TypeNS {
			ns++
		}
	}
	for _, rr := range m.Additional {
		if rr.Type == wire.TypeA || rr.Type == wire.TypeAAAA {
			glue++
		}
	}
	return ns, glue
}

// serverNames maps each address that was asked back to the nameserver name that
// was published for it, taken from the glue in the referrals seen along the way.
func serverNames(steps []resolver.Step) map[netip.Addr]wire.Name {
	names := make(map[netip.Addr]wire.Name)
	for _, s := range steps {
		if s.Reply == nil || s.Reply.Msg == nil {
			continue
		}
		for _, rr := range s.Reply.Msg.Additional {
			switch d := rr.Data.(type) {
			case wire.A:
				names[d.Addr] = rr.Name
			case wire.AAAA:
				names[d.Addr] = rr.Name
			}
		}
	}
	return names
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// jsonStep is the machine-readable form of a Step. The wire types cannot be
// marshalled directly, since RData is an interface with an unexported method, so
// this is a view rather than the struct itself, which also keeps the JSON a
// deliberate contract instead of whatever the resolver's fields happen to be.
type jsonStep struct {
	Nested     int    `json:"nested"`
	Zone       string `json:"zone,omitempty"`
	Server     string `json:"server,omitempty"`
	Candidates int    `json:"candidates,omitempty"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	Outcome    string `json:"outcome"`
	Error      string `json:"error,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
	RTTMS      int64  `json:"rttMs"`
	Size       int    `json:"sizeBytes,omitempty"`
	Cached     bool   `json:"cached,omitempty"`
}

func writeSteps(w io.Writer, steps []resolver.Step) error {
	out := make([]jsonStep, 0, len(steps))
	for _, s := range steps {
		v := jsonStep{
			Nested:     s.Nested,
			Zone:       string(s.Zone),
			Candidates: s.Candidates,
			Name:       string(s.Query.Name),
			Type:       s.Query.Type.String(),
			Outcome:    s.Kind.String(),
			Cached:     s.Cached(),
		}
		if s.Server.IsValid() {
			v.Server = s.Server.String()
		}
		if s.Err != nil {
			v.Error = s.Err.Error()
		}
		if s.Reply != nil {
			v.Protocol = s.Reply.Protocol
			v.RTTMS = s.Reply.RTT.Milliseconds()
			v.Size = s.Reply.Size
		}
		out = append(out, v)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
