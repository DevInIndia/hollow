package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/DevInIndia/hollow/internal/resolver"
	"github.com/DevInIndia/hollow/internal/roothints"
	"github.com/DevInIndia/hollow/internal/wire"
)

// newResolver builds a resolver starting from the compiled-in root servers, or
// from a named.root file when one is given.
//
// A hints file that cannot be read is an error rather than a reason to fall back
// to the built-in list. Someone who names a file and gets the defaults has been
// told their private root works when it was never consulted.
func newResolver(tr resolver.Transport, hintsPath string, port uint16, trace func(resolver.Step)) (*resolver.Resolver, error) {
	servers := roothints.Builtin()
	if hintsPath != "" {
		f, err := os.Open(hintsPath)
		if err != nil {
			return nil, fmt.Errorf("reading root hints: %w", err)
		}
		defer f.Close()
		if servers, err = roothints.Parse(f); err != nil {
			return nil, err
		}
	}
	return &resolver.Resolver{
		Transport: tr,
		Hints:     roothints.Addrs(servers, port),
		Port:      port,
		Trace:     trace,
	}, nil
}

// iterate resolves a question from the root, with no upstream resolver.
func iterate(ctx context.Context, tr resolver.Transport, q wire.Question, hintsPath string, port uint16, trace func(resolver.Step)) (*resolver.Result, error) {
	r, err := newResolver(tr, hintsPath, port, trace)
	if err != nil {
		return nil, err
	}
	return r.Resolve(ctx, q)
}

// traceWriter renders the delegation path as it is walked, or returns nil when
// tracing is off so the resolver skips the call entirely.
//
// It writes to stderr rather than stdout, because the answer is the output and
// the path taken to it is diagnostics. Redirecting stdout to a file should
// capture the records and nothing else.
func traceWriter(on bool, w io.Writer) func(resolver.Step) {
	if !on {
		return nil
	}
	return func(s resolver.Step) {
		zone := s.Zone
		if zone == wire.Root {
			zone = "(root)"
		}
		if s.Err != nil {
			fmt.Fprintf(w, ";; %-24s %-24v %s\n", zone, s.Server, s.Err)
			return
		}
		fmt.Fprintf(w, ";; %-24s %-24v %s %s in %v\n",
			zone, s.Server, s.Reply.Protocol, s.Kind, s.Reply.RTT.Round(time.Millisecond))
	}
}
