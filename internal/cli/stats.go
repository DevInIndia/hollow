package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/DevInIndia/hollow/internal/control"
)

// Stats runs the stats verb and returns the process exit code.
//
// It asks a running server for one snapshot and prints it. Deliberately a
// one-shot rather than a follow: something that prints once and exits composes
// with watch, with a cron line and with a pipe into jq, and the thing that wants
// a continuous view is hollow dash.
func Stats(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("hollow stats", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		target  = fs.String("target", control.DefaultAddr, "control socket of the server to ask")
		asJSON  = fs.Bool("json", false, "print the snapshot as JSON")
		timeout = fs.Duration("timeout", 5*time.Second, "deadline for the whole exchange")
	)
	fs.Usage = func() {
		fmt.Fprint(stderr, "usage: hollow stats [flags]\n\nflags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return ExitFailure
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return ExitFailure
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	snap, err := control.Fetch(ctx, *target)
	if err != nil {
		fmt.Fprintf(stderr, "hollow: %v\n", err)
		if errors.Is(err, control.ErrNoServer) {
			// The single most likely first experience of this verb, and
			// "connection refused" alone does not tell anybody that the server
			// they are running needs a flag today that it did not need
			// yesterday.
			fmt.Fprintf(stderr, "hollow: the control socket is opt-in; start the server with --control %s\n", *target)
		}
		return ExitFailure
	}

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(snap); err != nil {
			fmt.Fprintf(stderr, "hollow: %v\n", err)
			return ExitFailure
		}
		return ExitOK
	}
	writeStats(stdout, snap)
	return ExitOK
}

// writeStats prints a snapshot for a person.
//
// The same shape as the block serve prints at shutdown, because they answer the
// same question and somebody who has read one should not have to learn the
// other.
func writeStats(w io.Writer, s *control.Snapshot) {
	up := (time.Duration(s.UptimeMS) * time.Millisecond).Round(time.Second)
	fmt.Fprintf(w, "up %v, %d queries, %d blocked, %d upstream failures\n",
		up, s.QueriesTotal, s.QueriesBlocked, s.UpstreamErrors)

	// Percentages are printed only when there is something to divide by. "0.0%
	// of 0" is not a reading, it is a division nobody performed.
	if lookups := s.CacheHits + s.CacheMisses; lookups > 0 {
		fmt.Fprintf(w, "cache: %d hits, %d misses, %.1f%% hit rate, %d entries, %d served stale\n",
			s.CacheHits, s.CacheMisses, 100*float64(s.CacheHits)/float64(lookups),
			s.CacheEntries, s.StaleServed)
	}
	fmt.Fprintf(w, "latency: p50 %s, p99 %s\n", ms(s.LatencyP50MS), ms(s.LatencyP99MS))

	writeTop(w, "top names", s.TopDomains)
	writeTop(w, "top blocked", s.TopBlocked)
	writeTop(w, "top clients", s.TopClients)

	// Both zero in ordinary operation, and printed only when they are not, for
	// the same reason the server does it: a line reading "0 dropped" every time
	// teaches an operator to stop reading it.
	if s.EventsDropped > 0 {
		fmt.Fprintf(w, "events: %d dropped, a consumer could not keep up\n", s.EventsDropped)
	}
	if s.NamesDropped > 0 {
		fmt.Fprintf(w, "names: %d sightings left out of the lists above, the counters are full\n", s.NamesDropped)
	}
}

func writeTop(w io.Writer, label string, items []control.Item) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(w, "%s:\n", label)
	for _, it := range items {
		fmt.Fprintf(w, "  %6d  %s\n", it.Count, it.Name)
	}
}

// ms renders a millisecond figure at a precision that suits its size. A p50 of
// 0.4 ms and a p99 of 61 ms are both worth reading, and one format cannot show
// both without either losing the first or padding the second with noise.
func ms(v float64) string {
	if v < 10 {
		return fmt.Sprintf("%.2fms", v)
	}
	return fmt.Sprintf("%.0fms", v)
}
