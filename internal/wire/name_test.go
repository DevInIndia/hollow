package wire

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// decodeNameAt decodes a name starting at off and reports where the cursor
// landed, which is where the record's next field would begin.
func decodeNameAt(t *testing.T, msg []byte, off int) (Name, int, error) {
	t.Helper()
	d := &decoder{msg: msg, off: off}
	n, err := d.name()
	return n, d.off, err
}

func TestNameDecode(t *testing.T) {
	// "example.com." laid out at offset 12, as it would be in a real message,
	// so that pointer targets below are the ones a real server would emit.
	//
	//   12: 07 e x a m p l e   20: 03 c o m   24: 00
	msg := make([]byte, 40)
	msg[12] = 7
	copy(msg[13:20], "example")
	msg[20] = 3
	copy(msg[21:24], "com")
	msg[24] = 0
	// 25: a fresh label "j" followed by a pointer to "com." at offset 20.
	// This is fixture 2's `01 6a c0 23` shape: a new label joined to a suffix
	// reached by pointer, which a one-level resolver gets wrong.
	msg[25], msg[26] = 1, 'j'
	msg[27], msg[28] = 0xC0, 20
	// 29: a pointer to the name at 25, which itself ends in a pointer.
	msg[29], msg[30] = 0xC0, 25

	tests := []struct {
		name    string
		off     int
		want    Name
		wantOff int
	}{
		{"uncompressed", 12, "example.com.", 25},
		{"label then pointer", 25, "j.com.", 29},
		{"pointer to a partially compressed name", 29, "j.com.", 31},
		{"suffix only", 20, "com.", 25},
		{"root", 24, ".", 25},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, off, err := decodeNameAt(t, msg, tt.off)
			if err != nil {
				t.Fatalf("name() = %v", err)
			}
			if got != tt.want {
				t.Errorf("name = %q, want %q", got, tt.want)
			}
			if off != tt.wantOff {
				t.Errorf("cursor = %d, want %d", off, tt.wantOff)
			}
		})
	}
}

// TestNameDecodeRejects covers the malformed-name half of the section 8 matrix.
// None of these may panic, hang, or allocate without bound.
func TestNameDecodeRejects(t *testing.T) {
	// A name whose labels walk forward into a pointer that jumps back to a
	// point from which the walk repeats. Every pointer here targets an offset
	// below its own position, so a resolver that only checks "points backwards
	// from here" accepts this and loops forever:
	//
	//   22: c0 05 -> 5    5: label(9) -> 15    15: label(4) -> 20
	//   20: c0 0f -> 15   and 15 walks to 20 again
	//
	// Comparing each target against the previous target instead rejects it,
	// because 15 is not below the first target of 5.
	labelCycle := make([]byte, 24)
	labelCycle[5] = 9
	copy(labelCycle[6:15], strings.Repeat("a", 9))
	labelCycle[15] = 4
	copy(labelCycle[16:20], "bbbb")
	labelCycle[20], labelCycle[21] = 0xC0, 15
	labelCycle[22], labelCycle[23] = 0xC0, 5

	// Two pointers that reference each other directly.
	twoPointer := []byte{0xC0, 0x02, 0xC0, 0x00}

	// A name of 5 labels of 63 octets plus a 4-octet label, which encodes to
	// 5*64 + 5 = 325 octets, past the 255 limit.
	tooLong := []byte{}
	for range 5 {
		tooLong = append(tooLong, 63)
		tooLong = append(tooLong, bytes.Repeat([]byte("a"), 63)...)
	}
	tooLong = append(tooLong, 4)
	tooLong = append(tooLong, "bbbb"...)
	tooLong = append(tooLong, 0)

	tests := []struct {
		name string
		msg  []byte
		off  int
		want error
	}{
		{"self pointer", []byte{0xC0, 0x00}, 0, ErrBadPointer},
		{"forward pointer", []byte{0xC0, 0x05, 0, 0, 0, 0}, 0, ErrBadPointer},
		{"two pointer cycle, entry at 0", twoPointer, 0, ErrBadPointer},
		{"two pointer cycle, entry at 2", twoPointer, 2, ErrBadPointer},
		{"label mediated cycle", labelCycle, 22, ErrBadPointer},
		{"pointer target past end of message", []byte{0, 0, 0xC0, 0xFF}, 2, ErrBadPointer},
		{"truncated pointer", []byte{0, 0xC0}, 1, ErrTruncated},
		{"no terminating zero", []byte{3, 'c', 'o', 'm'}, 0, ErrTruncated},
		{"label runs past end", []byte{9, 'c', 'o', 'm'}, 0, ErrTruncated},
		{"empty buffer", []byte{}, 0, ErrTruncated},
		{"label length 64", []byte{64, 'a', 0}, 0, ErrLabelType},
		{"reserved label type 0x80", []byte{0x80, 0}, 0, ErrLabelType},
		{"name longer than 255", tooLong, 0, ErrNameTooLong},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, err := decodeNameAt(t, tt.msg, tt.off)
			if !errors.Is(err, tt.want) {
				t.Fatalf("name() = %q, %v; want error %v", got, err, tt.want)
			}
		})
	}
}

// A pointer into the middle of a label's payload reinterprets whatever octet
// sits there as a length or label type. Both readings must fail cleanly rather
// than producing a plausible-looking name.
func TestNamePointerIntoLabelPayload(t *testing.T) {
	tests := []struct {
		name string
		msg  []byte
		want error
	}{
		// 'c' is 99, whose top two bits are 01, a reserved label type.
		{"payload octet is not a length", []byte{3, 'c', 'o', 'm', 0, 0xC0, 0x01}, ErrLabelType},
		// '1' is 49, a valid length, but 49 octets run past the buffer.
		{"payload octet is a length that overruns", []byte{3, '1', '2', '3', 0, 0xC0, 0x01}, ErrTruncated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _, err := decodeNameAt(t, tt.msg, 5); !errors.Is(err, tt.want) {
				t.Fatalf("name() = %q, %v; want error %v", got, err, tt.want)
			}
		})
	}
}

func TestNamePresentationRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want Name
	}{
		{"simple", "example.com", "example.com."},
		{"already qualified", "example.com.", "example.com."},
		{"root", ".", "."},
		{"empty means root", "", "."},
		{"case preserved", "eXaMpLe.CoM", "eXaMpLe.CoM."},
		{"single label", "localhost", "localhost."},
		{"escaped dot", `a\.b.com`, `a\.b.com.`},
		{"escaped backslash", `a\\b.com`, `a\\b.com.`},
		{"decimal escape of a space", `a\032b.com`, `a\032b.com.`},
		{"non printable is escaped", "a\x00b.com", `a\000b.com.`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseName(tt.in)
			if err != nil {
				t.Fatalf("ParseName(%q) = %v", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("ParseName(%q) = %q, want %q", tt.in, got, tt.want)
			}

			// Encoding then decoding must reproduce the name exactly,
			// including case.
			e := &encoder{ptrs: map[string]int{}}
			if err := e.name(got); err != nil {
				t.Fatalf("encode(%q) = %v", got, err)
			}
			back, off, err := decodeNameAt(t, e.buf, 0)
			if err != nil {
				t.Fatalf("decode(% x) = %v", e.buf, err)
			}
			if back != got {
				t.Errorf("round trip = %q, want %q", back, got)
			}
			if off != len(e.buf) {
				t.Errorf("cursor = %d, want %d", off, len(e.buf))
			}
		})
	}
}

func TestParseNameRejects(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want error
	}{
		{"label of 64", strings.Repeat("a", 64) + ".com", ErrLabelTooLong},
		{"empty interior label", "a..com", ErrNameSyntax},
		{"leading dot", ".com", ErrNameSyntax},
		{"trailing backslash", `a\`, ErrNameSyntax},
		{"short decimal escape", `a\09.com`, ErrNameSyntax},
		{"decimal escape above 255", `a\256.com`, ErrNameSyntax},
		{"name longer than 255", strings.Repeat("a63chars."+strings.Repeat("x", 55)+".", 5), ErrNameTooLong},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := ParseName(tt.in); !errors.Is(err, tt.want) {
				t.Fatalf("ParseName = %q, %v; want error %v", got, err, tt.want)
			}
		})
	}
}

func TestNameEqualFold(t *testing.T) {
	a, b := Name("eXaMpLe.CoM."), Name("example.com.")
	if !a.EqualFold(b) {
		t.Errorf("%q should fold-equal %q", a, b)
	}
	if a == b {
		t.Errorf("%q and %q should not be byte-equal, case must survive decode", a, b)
	}
	if a.EqualFold("example.org.") {
		t.Errorf("%q should not fold-equal example.org.", a)
	}
}

func TestNameCompression(t *testing.T) {
	e := &encoder{ptrs: map[string]int{}}
	for _, n := range []Name{"www.example.com.", "mail.example.com.", "example.com.", "com."} {
		if err := e.name(n); err != nil {
			t.Fatalf("encode(%q) = %v", n, err)
		}
	}

	// www.example.com. writes in full at offset 0, so example.com. sits at 4
	// and com. at 12. Every later name reuses those suffixes.
	want := []byte{
		3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		4, 'm', 'a', 'i', 'l', 0xC0, 4,
		0xC0, 4,
		0xC0, 12,
	}
	if !bytes.Equal(e.buf, want) {
		t.Fatalf("encoded\n got % x\nwant % x", e.buf, want)
	}

	var off int
	for _, want := range []Name{"www.example.com.", "mail.example.com.", "example.com.", "com."} {
		got, next, err := decodeNameAt(t, e.buf, off)
		if err != nil {
			t.Fatalf("decode at %d = %v", off, err)
		}
		if got != want {
			t.Errorf("decode at %d = %q, want %q", off, got, want)
		}
		off = next
	}
}

// Compression matches on exact octets, so two spellings of one name are written
// out separately. Pointing the second at the first would rewrite its case, and
// the 0x20 defence depends on case surviving encode.
func TestNameCompressionIsCaseSensitive(t *testing.T) {
	e := &encoder{ptrs: map[string]int{}}
	for _, n := range []Name{"example.com.", "ExAmPlE.cOm."} {
		if err := e.name(n); err != nil {
			t.Fatalf("encode(%q) = %v", n, err)
		}
	}
	if bytes.Contains(e.buf[13:], []byte{0xC0}) {
		t.Fatalf("second spelling was compressed: % x", e.buf)
	}

	second, _, err := decodeNameAt(t, e.buf, 13)
	if err != nil {
		t.Fatalf("decode = %v", err)
	}
	if second != "ExAmPlE.cOm." {
		t.Errorf("second name = %q, want ExAmPlE.cOm.", second)
	}
}

// The same property as above reached through label boundaries rather than case.
// A label may hold a '.' octet, so the one-label name "a.b" and the two-label
// name "a" "b" are different names that a separator-joined compression key
// cannot tell apart. Found by FuzzUnpack's round-trip property.
func TestNameCompressionRespectsLabelBoundaries(t *testing.T) {
	// Escaped in presentation form, so these are one label and two labels.
	const (
		oneLabel Name = "a\\.b."
		twoLabel Name = "a.b."
	)

	for _, order := range [][2]Name{{twoLabel, oneLabel}, {oneLabel, twoLabel}} {
		t.Run(string(order[0])+" then "+string(order[1]), func(t *testing.T) {
			e := &encoder{ptrs: map[string]int{}}
			for _, n := range order {
				if err := e.name(n); err != nil {
					t.Fatalf("encode(%q) = %v", n, err)
				}
			}
			// The first name occupies offset 0 and is 5 octets either way.
			if bytes.Contains(e.buf[5:], []byte{0xC0}) {
				t.Fatalf("second name was compressed against the first: % x", e.buf)
			}
			got, _, err := decodeNameAt(t, e.buf, 5)
			if err != nil {
				t.Fatalf("decode = %v", err)
			}
			if got != order[1] {
				t.Errorf("second name = %q, want %q", got, order[1])
			}
		})
	}
}

func TestWithin(t *testing.T) {
	for _, tc := range []struct {
		name, zone Name
		want       bool
	}{
		{"example.com.", "com.", true},
		{"www.example.com.", "com.", true},
		{"example.com.", "example.com.", true}, // a zone is within itself
		{"com.", "example.com.", false},        // the parent is not within the child
		{"example.org.", "com.", false},
		{"notexample.com.", "example.com.", false}, // a label boundary, not a substring
		{"anything.", ".", true},                   // everything is within the root
		{".", ".", true},
		{"EXAMPLE.CoM.", "example.com.", true}, // RFC 4343
		{"www.EXAMPLE.com.", "ExAmPlE.CoM.", true},

		// The reason this compares labels. "evil\.com" is one label whose text
		// happens to contain a dot, so it is a sibling of com, not a child of
		// it. A string suffix test reads it as ending in ".com." and admits it.
		{`evil\.com.`, "com.", false},
		{`ns1.evil\.com.`, "com.", false},
		{`ns1.evil\.com.`, `evil\.com.`, true},
	} {
		t.Run(string(tc.name)+" in "+string(tc.zone), func(t *testing.T) {
			if got := tc.name.Within(tc.zone); got != tc.want {
				t.Errorf("Name(%q).Within(%q) = %v, want %v", tc.name, tc.zone, got, tc.want)
			}
		})
	}
}

func TestWithinRejectsUnparsableNames(t *testing.T) {
	// A name that cannot be split is within nothing. A bailiwick check that
	// failed open on malformed input would be worse than not having one.
	if Name(`bad\`).Within("com.") {
		t.Error("an unparsable name was reported as within a zone")
	}
	if Name("example.com.").Within(`bad\`) {
		t.Error("a name was reported as within an unparsable zone")
	}
}
