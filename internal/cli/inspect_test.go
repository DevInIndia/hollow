package cli

import (
	"bytes"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/DevInIndia/hollow/internal/wire"
)

// The dump has one job beyond looking right: every octet of the message has to
// appear in it, in order, exactly once. A hexdump that skips a byte is worse
// than no hexdump, because it looks authoritative.
func TestDumpPrintsEveryOctetInOrder(t *testing.T) {
	raw, err := os.ReadFile("../wire/testdata/example-com-a.bin")
	if err != nil {
		t.Fatalf("reading the fixture: %v", err)
	}
	spans, err := wire.Annotate(raw)
	if err != nil {
		t.Fatalf("Annotate() error = %v", err)
	}

	var buf bytes.Buffer
	writeDump(&buf, raw, spans)

	var got []byte
	prev := -1
	for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		fields := strings.Fields(line)
		off, err := strconv.ParseInt(fields[0], 16, 32)
		if err != nil {
			t.Fatalf("line %q does not start with an offset", line)
		}
		if int(off) <= prev {
			t.Errorf("offset %04x does not advance past %04x", off, prev)
		}
		prev = int(off)
		if int(off) != len(got) {
			t.Fatalf("row at %04x arrives after %d octets, so something was skipped", off, len(got))
		}
		for _, f := range fields[1:] {
			if len(f) != 2 {
				break // the annotation column has started
			}
			b, err := strconv.ParseUint(f, 16, 8)
			if err != nil {
				break
			}
			got = append(got, byte(b))
		}
	}

	if !bytes.Equal(got, raw) {
		t.Errorf("the dump reconstructs %d octets, the message is %d", len(got), len(raw))
	}
}

// The annotation sits on the first row of its field, so a field wider than one
// row is not repeated and a reader can see where each one begins.
func TestDumpLabelsTheFirstRowOfAField(t *testing.T) {
	raw := []byte{0xab, 0xcd}
	spans := []wire.Span{{Offset: 0, Length: 2, Section: "header", Field: "ID", Detail: "0xabcd"}}

	var buf bytes.Buffer
	writeDump(&buf, raw, spans)

	want := "0000  ab cd                    ID 0xabcd\n"
	if got := buf.String(); got != want {
		t.Errorf("dump =\n%q\nwant\n%q", got, want)
	}
}

// A field that spills over one row gets a continuation row with no annotation
// and no trailing whitespace, since a trailing run of spaces is what turns a
// clean diff of two dumps into a noisy one.
func TestDumpContinuationRowsCarryNoLabel(t *testing.T) {
	raw := make([]byte, 12)
	spans := []wire.Span{{Offset: 0, Length: 12, Section: "question", Field: "QNAME", Detail: "example.com."}}

	var buf bytes.Buffer
	writeDump(&buf, raw, spans)

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("rows = %d, want 2 for twelve octets at eight a row", len(lines))
	}
	if !strings.Contains(lines[0], "QNAME") {
		t.Errorf("first row has no label: %q", lines[0])
	}
	if strings.Contains(lines[1], "QNAME") {
		t.Errorf("the label is repeated on the continuation row: %q", lines[1])
	}
	if lines[1] != strings.TrimRight(lines[1], " ") {
		t.Errorf("continuation row has trailing whitespace: %q", lines[1])
	}
}

// Inspect reads a message from a file so that a captured packet can be examined
// without sending anything, which is also what makes this verb testable without
// a network.
func TestInspectReadsAMessageFromAFile(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Inspect([]string{"--file", "../wire/testdata/example-com-a.bin"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("Inspect() = %d, want %d: %s", code, ExitOK, stderr.String())
	}
	for _, want := range []string{"ID ", "QNAME example.com.", "pointer to 0x000c", "RDATA address"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("dump does not mention %q:\n%s", want, stdout.String())
		}
	}
}

// A message that does not decode still gets the dump for everything read before
// the field that broke, and an exit code that says it failed.
func TestInspectDumpsWhatItReadOfABrokenMessage(t *testing.T) {
	raw, err := os.ReadFile("../wire/testdata/example-com-a.bin")
	if err != nil {
		t.Fatalf("reading the fixture: %v", err)
	}
	path := t.TempDir() + "/truncated.bin"
	if err := os.WriteFile(path, raw[:18], 0o600); err != nil {
		t.Fatalf("writing the truncated message: %v", err)
	}

	var stdout, stderr bytes.Buffer
	if code := Inspect([]string{"--file", path}, &stdout, &stderr); code != ExitFailure {
		t.Fatalf("Inspect() = %d, want %d", code, ExitFailure)
	}
	if !strings.Contains(stdout.String(), "QDCOUNT") {
		t.Errorf("nothing was dumped before the failure:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "does not decode") {
		t.Errorf("stderr does not say what went wrong: %s", stderr.String())
	}
}

func TestInspectRefusesAFileAndANameTogether(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Inspect([]string{"--file", "../wire/testdata/example-com-a.bin", "example.com"}, &stdout, &stderr)
	if code != ExitFailure {
		t.Fatalf("Inspect() = %d, want %d", code, ExitFailure)
	}
	if !strings.Contains(stderr.String(), "takes no name") {
		t.Errorf("stderr = %q", stderr.String())
	}
}
