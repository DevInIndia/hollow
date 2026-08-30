package wire

import (
	"os"
	"strings"
	"testing"
)

// The promise Annotate makes is coverage: every octet of the message belongs to
// exactly one span, the spans meet exactly, and none of them overlap. An
// annotated dump with a gap in it is a dump claiming the parser read something
// it did not.
func TestAnnotateAccountsForEveryByte(t *testing.T) {
	for _, name := range []string{"example-com-a.bin", "com-ns-referral.bin"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile("testdata/" + name)
			if err != nil {
				t.Fatalf("reading %s: %v", name, err)
			}
			spans, err := Annotate(raw)
			if err != nil {
				t.Fatalf("Annotate() error = %v", err)
			}

			off := 0
			for i, s := range spans {
				if s.Offset != off {
					t.Fatalf("span %d (%s) starts at %d, want %d: a gap or an overlap",
						i, s.Field, s.Offset, off)
				}
				if s.Length <= 0 {
					t.Fatalf("span %d (%s) is %d octets long", i, s.Field, s.Length)
				}
				if s.Field == "" || s.Detail == "" {
					t.Errorf("span %d at offset %d has nothing to say: %+v", i, s.Offset, s)
				}
				off = s.End()
			}
			if off != len(raw) {
				t.Errorf("spans cover %d octets of %d", off, len(raw))
			}
		})
	}
}

// The compression pointer is the detail that proves the codec was implemented
// rather than wrapped, so it has to be resolved to its target and not merely
// noted as present. The captured answer compresses the record's owner name
// against the question, which is the textbook case.
func TestAnnotateResolvesACompressionPointer(t *testing.T) {
	raw, err := os.ReadFile("testdata/example-com-a.bin")
	if err != nil {
		t.Fatalf("reading the fixture: %v", err)
	}
	spans, err := Annotate(raw)
	if err != nil {
		t.Fatalf("Annotate() error = %v", err)
	}

	var found bool
	for _, s := range spans {
		if s.Section != "answer" || s.Field != "NAME" {
			continue
		}
		found = true
		if !strings.Contains(s.Detail, "pointer to 0x000c") {
			t.Errorf("answer NAME detail = %q, want the pointer resolved to offset 0x000c", s.Detail)
		}
		if !strings.Contains(s.Detail, "example.com.") {
			t.Errorf("answer NAME detail = %q, want the name the pointer expands to", s.Detail)
		}
		if s.Length != 2 {
			t.Errorf("a compressed name is %d octets, want 2", s.Length)
		}
	}
	if !found {
		t.Fatal("no answer record in the fixture")
	}
}

// The header is fixed at twelve octets and is the one part of a message whose
// layout can be asserted outright.
func TestAnnotateNamesTheHeaderFields(t *testing.T) {
	raw, err := os.ReadFile("testdata/example-com-a.bin")
	if err != nil {
		t.Fatalf("reading the fixture: %v", err)
	}
	spans, err := Annotate(raw)
	if err != nil {
		t.Fatalf("Annotate() error = %v", err)
	}

	want := []struct {
		field  string
		offset int
		length int
	}{
		{"ID", 0, 2},
		{"flags", 2, 2},
		{"QDCOUNT", 4, 2},
		{"ANCOUNT", 6, 2},
		{"NSCOUNT", 8, 2},
		{"ARCOUNT", 10, 2},
	}
	for i, w := range want {
		got := spans[i]
		if got.Field != w.field || got.Offset != w.offset || got.Length != w.length || got.Section != "header" {
			t.Errorf("span %d = %+v, want %s at %d for %d octets in the header",
				i, got, w.field, w.offset, w.length)
		}
	}
}

// A message that stops mid-field still has spans for everything read before it,
// because the field the parser stopped on is the answer to why it stopped.
func TestAnnotateKeepsWhatItReadBeforeATruncation(t *testing.T) {
	raw, err := os.ReadFile("testdata/example-com-a.bin")
	if err != nil {
		t.Fatalf("reading the fixture: %v", err)
	}
	spans, err := Annotate(raw[:20])
	if err == nil {
		t.Fatal("Annotate() of a truncated message returned no error")
	}
	if len(spans) < 6 {
		t.Errorf("spans = %d, want at least the six header fields", len(spans))
	}
	for _, s := range spans {
		if s.End() > 20 {
			t.Errorf("span %+v runs past the octets that were there", s)
		}
	}
}

// Octets after the end of a message are named rather than ignored. A padded
// datagram and two messages in one buffer look identical until something says
// how much was actually read.
func TestAnnotateNamesTrailingOctets(t *testing.T) {
	raw, err := os.ReadFile("testdata/example-com-a.bin")
	if err != nil {
		t.Fatalf("reading the fixture: %v", err)
	}
	spans, err := Annotate(append(raw, 0xde, 0xad))
	if err != nil {
		t.Fatalf("Annotate() error = %v", err)
	}
	last := spans[len(spans)-1]
	if last.Section != "trailing" || last.Length != 2 {
		t.Errorf("last span = %+v, want two trailing octets", last)
	}
}
