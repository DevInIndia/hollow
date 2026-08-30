package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/DevInIndia/hollow/internal/resolver"
	"github.com/DevInIndia/hollow/internal/wire"
)

// Inspect runs the inspect verb and returns the process exit code.
//
// It asks for a name and dumps the reply exactly as it arrived, annotated field
// by field. The annotation comes from the decoder itself rather than from a
// second reading of the bytes, so what the dump says is what the parser did.
func Inspect(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("hollow inspect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		server  = fs.String("server", "", "ask this server directly instead of resolving from the root")
		port    = fs.Uint("port", 53, "port to query")
		useTCP  = fs.Bool("tcp", false, "query over TCP instead of falling back to it")
		timeout = fs.Duration("timeout", resolver.DefaultTimeout, "deadline for one exchange with one server")
		hints   = fs.String("hints", "", "root hints in named.root format; default is the compiled-in list")
		file    = fs.String("file", "", "read the message from this file instead of sending a query")
	)
	fs.Usage = func() {
		fmt.Fprint(stderr, "usage: hollow inspect [flags] <name> [type]\n       hollow inspect --file <message>\n\nflags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return ExitFailure
	}

	var raw []byte
	if *file != "" {
		if fs.NArg() != 0 {
			fmt.Fprint(stderr, "hollow: --file reads a message from disk, so it takes no name\n")
			return ExitFailure
		}
		b, err := os.ReadFile(*file)
		if err != nil {
			fmt.Fprintf(stderr, "hollow: %v\n", err)
			return ExitFailure
		}
		raw = b
	} else {
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
		if *server != "" && *hints != "" {
			fmt.Fprint(stderr, "hollow: --hints applies to resolution from the root, so it cannot be used with --server\n")
			return ExitFailure
		}

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		// The whole point of this verb is the octets, so the transport is asked
		// to keep them. Nothing else in the program sets this.
		tr := resolver.Transport{Timeout: *timeout, ForceTCP: *useTCP, KeepWire: true}
		q := wire.Question{Name: name, Type: qtype, Class: wire.ClassIN}

		var reply *resolver.Reply
		if *server != "" {
			tr.RecursionDesired = true
			addr, err := netip.ParseAddr(*server)
			if err != nil {
				fmt.Fprintf(stderr, "hollow: --server takes an IP address, not a name: %v\n", err)
				return ExitFailure
			}
			if reply, err = tr.Exchange(ctx, netip.AddrPortFrom(addr, uint16(*port)), q); err != nil {
				fmt.Fprintf(stderr, "hollow: %v\n", err)
				return ExitFailure
			}
		} else {
			res, err := iterate(ctx, tr, q, *hints, uint16(*port), nil)
			if err != nil {
				fmt.Fprintf(stderr, "hollow: %v\n", err)
				return ExitFailure
			}
			reply = res.Reply
		}
		raw = reply.Wire
		fmt.Fprintf(stdout, ";; %d octets from %s over %s in %v\n\n", reply.Size, reply.Server, reply.Protocol, reply.RTT.Round(time.Microsecond))
	}

	spans, err := wire.Annotate(raw)
	writeDump(stdout, raw, spans)
	if err != nil {
		// The dump above stops at the field that failed, which is the useful
		// half of the answer, so it is printed before the complaint.
		fmt.Fprintf(stderr, "hollow: the message does not decode: %v\n", err)
		return ExitFailure
	}
	return ExitOK
}

// writeDump renders the message as hex with the annotation beside it: one row
// per field rather than per fixed-width line, so a field and its meaning stay on
// the same row and nothing is split across two.
//
// Octets are printed in rows of at most eight because a DNS field is rarely
// wider than that, and sixteen would put a name and the record after it on the
// same line.
func writeDump(w io.Writer, raw []byte, spans []wire.Span) {
	const perRow = 8
	for _, s := range spans {
		octets := raw[s.Offset:min(s.End(), len(raw))]
		label := fmt.Sprintf("%s %s", s.Field, s.Detail)

		for i := 0; i < len(octets); i += perRow {
			chunk := octets[i:min(i+perRow, len(octets))]
			text := ""
			if i == 0 {
				text = label
			}
			line := fmt.Sprintf("%04x  %-*s  %s", s.Offset+i, perRow*3-1, hexOctets(chunk), text)
			fmt.Fprintln(w, strings.TrimRight(line, " "))
		}
		if len(octets) == 0 {
			fmt.Fprintf(w, "%04x  %-*s  %s\n", s.Offset, perRow*3-1, "", label)
		}
	}
}

func hexOctets(b []byte) string {
	var sb strings.Builder
	for i, c := range b {
		if i > 0 {
			sb.WriteByte(' ')
		}
		fmt.Fprintf(&sb, "%02x", c)
	}
	return sb.String()
}
