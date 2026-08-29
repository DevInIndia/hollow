package cli

import (
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/DevInIndia/hollow/internal/wire"
)

func TestResolveRejectsBadArguments(t *testing.T) {
	tests := map[string][]string{
		"no name":                {},
		"too many positionals":   {"example.com", "A", "AAAA"},
		"unparseable name":       {"--server", "192.0.2.53", strings.Repeat("a", 64) + ".com"},
		"unknown type":           {"--server", "192.0.2.53", "example.com", "NOTATYPE"},
		"server given as a name": {"--server", "dns.example", "example.com"},
		"port out of range":      {"--server", "192.0.2.53", "--port", "70000", "example.com"},
		"unrecognised flag":      {"--nope", "example.com"},

		// --hints configures where iterative resolution starts, so pairing it
		// with --server names a starting point that is never used. Silently
		// ignoring one of two contradictory flags is how a person ends up
		// believing they tested something they did not.
		"hints with server": {"--server", "192.0.2.53", "--hints", "/dev/null", "example.com"},

		// A hints file that does not exist must fail before any packet is sent,
		// rather than falling back to the compiled-in roots and appearing to
		// work.
		"missing hints file": {"--hints", "/nonexistent/named.root", "example.com"},
	}

	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr strings.Builder
			if got := Resolve(args, &stdout, &stderr); got != ExitFailure {
				t.Errorf("Resolve() = %d, want %d", got, ExitFailure)
			}
			if stdout.Len() != 0 {
				t.Errorf("a failed resolve wrote to stdout: %q", stdout.String())
			}
			if stderr.Len() == 0 {
				t.Error("a failed resolve explained nothing on stderr")
			}
		})
	}
}

// The exit code is the only part of the output a script reads, so it is worth
// pinning against a server whose reply is under this test's control.
func TestResolveExitCodes(t *testing.T) {
	tests := map[string]struct {
		rcode uint8
		want  int
	}{
		"an answer":    {wire.RcodeSuccess, ExitOK},
		"no such name": {wire.RcodeNXDomain, ExitNXDomain},
		"servfail":     {wire.RcodeServFail, ExitFailure},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			addr := answerOnce(t, tc.rcode)

			var stdout, stderr strings.Builder
			args := []string{
				"--server", addr.Addr().String(),
				"--port", strconv.Itoa(int(addr.Port())),
				"example.com",
			}
			if got := Resolve(args, &stdout, &stderr); got != tc.want {
				t.Errorf("Resolve() = %d, want %d\nstderr: %s", got, tc.want, stderr.String())
			}
			// Every reply is rendered, including the ones that report a
			// failure: an NXDOMAIN carries the SOA that says how long to
			// believe it, and swallowing the output would hide that.
			if !strings.Contains(stdout.String(), "->>HEADER<<-") {
				t.Errorf("no reply was rendered\nstdout: %s", stdout.String())
			}
		})
	}
}

func TestResolveReportsTransportFailure(t *testing.T) {
	// A server that receives the query and says nothing, so the failure is the
	// deadline rather than a refused connection.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("binding udp: %v", err)
	}
	defer pc.Close()
	addr, err := netip.ParseAddrPort(pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("parsing the listener address: %v", err)
	}

	var stdout, stderr strings.Builder
	args := []string{
		"--server", addr.Addr().String(),
		"--port", strconv.Itoa(int(addr.Port())),
		"--timeout", "150ms",
		"example.com",
	}
	if got := Resolve(args, &stdout, &stderr); got != ExitFailure {
		t.Errorf("Resolve() = %d, want %d", got, ExitFailure)
	}
	if !strings.Contains(stderr.String(), "hollow:") {
		t.Errorf("stderr does not name the program: %q", stderr.String())
	}
}

// answerOnce serves a single UDP query with a reply carrying rcode, and returns
// the address to query.
func answerOnce(t *testing.T, rcode uint8) netip.AddrPort {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("binding udp: %v", err)
	}
	t.Cleanup(func() { pc.Close() })

	addr, err := netip.ParseAddrPort(pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("parsing the listener address: %v", err)
	}

	go func() {
		buf := make([]byte, 1500)
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		query, err := wire.Unpack(buf[:n])
		if err != nil {
			t.Errorf("the test server could not decode the query: %v", err)
			return
		}
		reply := &wire.Message{
			Header: wire.Header{
				ID:                 query.Header.ID,
				Response:           true,
				RecursionAvailable: true,
				Rcode:              rcode,
			},
			Questions: query.Questions,
		}
		if rcode == wire.RcodeSuccess {
			reply.Answers = []wire.RR{{
				Name: query.Questions[0].Name, Type: wire.TypeA, Class: wire.ClassIN, TTL: 300,
				Data: wire.A{Addr: netip.MustParseAddr("192.0.2.1")},
			}}
		}
		out, err := reply.Pack()
		if err != nil {
			t.Errorf("the test server could not encode its reply: %v", err)
			return
		}
		pc.WriteTo(out, from)
	}()

	return addr
}
