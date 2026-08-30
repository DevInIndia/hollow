package wire

import (
	"fmt"
	"strings"
)

// Size limits from RFC 1035 section 2.3.4.
const (
	maxLabelLen = 63
	maxNameLen  = 255
)

// Name is a domain name in presentation format, fully qualified with a trailing
// dot. The root is ".".
//
// Case is preserved exactly as it arrived. Names match case-insensitively, which
// is what EqualFold is for, but decoding never folds case: the 0x20 defence
// depends on a response echoing the exact case that was sent.
//
// Octets outside the printable ASCII range, along with '.' and '\\', are escaped
// in the RFC 1035 section 5.1 style, so the presentation form is unambiguous and
// two Names are byte-equal only when the wire names were byte-equal.
type Name string

// Root is the zero-length name, encoded as a single zero octet.
const Root Name = "."

func (n Name) String() string { return string(n) }

// EqualFold reports whether two names are equal under DNS case-insensitive
// matching.
func (n Name) EqualFold(other Name) bool {
	return strings.EqualFold(string(n), string(other))
}

// Fold returns n lowercased, for use as a map key where DNS case-insensitive
// matching is wanted but a comparison per candidate is too slow.
//
// The result is a key and nothing else. It must never be stored in a record or
// written to the wire, because the 0x20 defence depends on the case that
// arrived surviving intact.
//
// Lowercasing the presentation string is sound because that string is always
// printable ASCII: appendEscaped escapes every octet outside '!' to '~', so
// there is no multi-byte sequence for strings.ToLower to fold differently from
// the ASCII rule RFC 4343 specifies. Escaped octets are unaffected for the same
// reason, since a letter is printable and therefore never escaped in the first
// place.
func (n Name) Fold() Name { return Name(strings.ToLower(string(n))) }

// Suffixes returns n followed by each of its parent names, from the name itself
// down to its final label. The root is not included, and neither the root nor a
// name that fails to parse yields anything.
//
// For "a.b.example.com." the result is "a.b.example.com.", "b.example.com.",
// "example.com.", "com.". Each is a slice of n's own storage, so the walk
// allocates once for the slice and never for the names.
//
// This exists because a suffix match over the raw string is wrong in the way
// that matters. Dots inside a label are escaped, so "evil\.com." is a single
// label whose bytes end in "com." and which must not be treated as living under
// com. Splitting on unescaped dots only, it yields itself and nothing else.
func (n Name) Suffixes() []Name {
	if n == "" || n == Root {
		return nil
	}
	s := string(n)
	out := []Name{n}
	for i := 0; i < len(s); {
		switch c := s[i]; {
		case c == '\\':
			_, w, err := unescape(s[i:])
			if err != nil {
				return nil
			}
			i += w
		case c == '.':
			// The dot that ends the last label terminates the name rather
			// than opening a parent, which is what keeps the root out.
			if i++; i < len(s) {
				out = append(out, Name(s[i:]))
			}
		default:
			i++
		}
	}
	return out
}

// Within reports whether n lies inside zone, either equal to it or below it.
// Every name is within the root.
//
// This compares labels, not bytes, and the difference is a security one. A
// label may contain a dot, escaped as "\." in presentation form, so a suffix
// test over the string would read the single label "evil\.com" as ending in the
// label "com" and place it inside the com zone. That is exactly the input a
// bailiwick check exists to reject, so the slower comparison is the only correct
// one. A name that does not parse is within nothing, which keeps the failure
// closed rather than open.
func (n Name) Within(zone Name) bool {
	zl, err := zone.labels()
	if err != nil {
		return false
	}
	if len(zl) == 0 {
		return true // the root contains everything
	}
	nl, err := n.labels()
	if err != nil || len(nl) < len(zl) {
		return false
	}
	for i := range zl {
		// RFC 4343: labels match without regard to case.
		if !strings.EqualFold(string(nl[len(nl)-len(zl)+i]), string(zl[i])) {
			return false
		}
	}
	return true
}

// ParseName converts a presentation-format name to a Name, accepting both
// "example.com" and "example.com." and canonicalising to the latter.
func ParseName(s string) (Name, error) {
	if s == "" || s == "." {
		return Root, nil
	}
	labels, err := splitPresentation(s)
	if err != nil {
		return "", err
	}
	var total int
	var b strings.Builder
	for _, l := range labels {
		total += 1 + len(l)
		if total >= maxNameLen {
			return "", fmt.Errorf("name %q: %w", s, ErrNameTooLong)
		}
		b.Write(appendEscaped(nil, l))
		b.WriteByte('.')
	}
	return Name(b.String()), nil
}

// labels returns the raw label octets, undoing presentation escapes.
func (n Name) labels() ([][]byte, error) {
	if n == "" || n == Root {
		return nil, nil
	}
	return splitPresentation(string(n))
}

// splitPresentation splits on unescaped dots and unescapes each label.
func splitPresentation(s string) ([][]byte, error) {
	var (
		labels [][]byte
		cur    []byte
	)
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '.':
			// A trailing dot terminates the name rather than opening an
			// empty label; an interior one would mean a zero-length label.
			if len(cur) == 0 && (i != len(s)-1 || len(labels) == 0) {
				return nil, fmt.Errorf("empty label at offset %d in %q: %w", i, s, ErrNameSyntax)
			}
			if len(cur) > 0 {
				labels = append(labels, cur)
				cur = nil
			}
			i++
		case c == '\\':
			b, n, err := unescape(s[i:])
			if err != nil {
				return nil, fmt.Errorf("offset %d in %q: %w", i, s, err)
			}
			cur = append(cur, b)
			i += n
		default:
			cur = append(cur, c)
			i++
		}
	}
	if len(cur) > 0 {
		labels = append(labels, cur)
	}
	for _, l := range labels {
		if len(l) > maxLabelLen {
			return nil, fmt.Errorf("label %q: %w", l, ErrLabelTooLong)
		}
	}
	return labels, nil
}

// unescape decodes one escape sequence at the start of s, which begins with a
// backslash, and reports how many octets of s it consumed.
func unescape(s string) (byte, int, error) {
	if len(s) < 2 {
		return 0, 0, ErrNameSyntax
	}
	if !isDigit(s[1]) {
		return s[1], 2, nil
	}
	if len(s) < 4 || !isDigit(s[2]) || !isDigit(s[3]) {
		return 0, 0, ErrNameSyntax
	}
	v := int(s[1]-'0')*100 + int(s[2]-'0')*10 + int(s[3]-'0')
	if v > 0xFF {
		return 0, 0, ErrNameSyntax
	}
	return byte(v), 4, nil
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// appendEscaped appends a label in presentation form.
func appendEscaped(dst, label []byte) []byte {
	for _, c := range label {
		switch {
		case c == '.' || c == '\\':
			dst = append(dst, '\\', c)
		case c < '!' || c > '~':
			dst = append(dst, '\\', '0'+c/100, '0'+(c/10)%10, '0'+c%10)
		default:
			dst = append(dst, c)
		}
	}
	return dst
}

// name decodes a domain name, following compression pointers.
//
// Loop defence: the first pointer must target an offset strictly below its own
// position, and every pointer after that must target an offset strictly below
// the previous pointer's target. Targets therefore form a strictly decreasing
// sequence of non-negative integers, so the number of jumps is bounded by the
// message length and the walk terminates by construction, with no visited set
// and no jump budget.
//
// Comparing against the previous target rather than against the current read
// position is what makes this sound. A pointer jumps backwards but the label
// walk then carries the cursor forward again, so "backwards from here" alone
// permits a cycle: a pointer at offset 20 targeting 15, where the labels at 15
// walk forward to offset 20, satisfies it at every step and never terminates.
//
// This rejects nothing legitimate, because a compression pointer can only
// reference a name already emitted earlier in the message.
func (d *decoder) name() (Name, error) {
	var (
		b      []byte
		off    = d.off
		bound  = -1 // previous pointer target; -1 until the first jump
		jumped bool
		total  int
	)
	for {
		if off >= len(d.msg) {
			return "", fmt.Errorf("name at offset %d: %w", d.off, ErrTruncated)
		}
		c := d.msg[off]
		switch c & 0xC0 {
		case 0x00:
			if c == 0 {
				off++
				if !jumped {
					d.off = off
				}
				if len(b) == 0 {
					return Root, nil
				}
				return Name(b), nil
			}
			end := off + 1 + int(c)
			if end > len(d.msg) {
				return "", fmt.Errorf("label at offset %d: %w", off, ErrTruncated)
			}
			total += 1 + int(c)
			if total >= maxNameLen {
				return "", fmt.Errorf("name at offset %d: %w", d.off, ErrNameTooLong)
			}
			b = appendEscaped(b, d.msg[off+1:end])
			b = append(b, '.')
			off = end
		case 0xC0:
			if off+1 >= len(d.msg) {
				return "", fmt.Errorf("pointer at offset %d: %w", off, ErrTruncated)
			}
			target := int(c&0x3F)<<8 | int(d.msg[off+1])
			limit := off
			if bound >= 0 {
				limit = bound
			}
			if target >= limit {
				return "", fmt.Errorf("pointer at offset %d targets %d, not below %d: %w",
					off, target, limit, ErrBadPointer)
			}
			bound = target
			if !jumped {
				d.off = off + 2
				jumped = true
			}
			off = target
		default:
			// 0x40 and 0x80 are reserved label types, so a length octet
			// above 63 is by definition not a length.
			return "", fmt.Errorf("label type %#02x at offset %d: %w", c&0xC0, off, ErrLabelType)
		}
	}
}

// name encodes a domain name, reusing an earlier occurrence of any suffix that
// has already been written.
//
// Suffixes are keyed by their exact octets rather than case-insensitively. A
// pointer replaces the name with whatever bytes sit at the target, so matching
// two spellings that differ in case would silently rewrite the case of the name
// being encoded, which is precisely what the 0x20 defence must not allow.
func (e *encoder) name(n Name) error { return e.encodeName(n, true) }

// nameUncompressed writes a name without pointing at an earlier copy of it, and
// without offering it as a target for a later one.
//
// RFC 2782 forbids compressing an SRV target, and RFC 3597 extends that to the
// rdata of every type defined after RFC 1035. The reason is the receiver, not
// the sender: anything that treats such rdata as opaque octets never expands a
// pointer inside it, so a compressed name reaches the far side corrupt. Not
// recording the offset matters for the same reason, since a pointer from
// elsewhere in the message into this name would be equally unreadable.
func (e *encoder) nameUncompressed(n Name) error { return e.encodeName(n, false) }

func (e *encoder) encodeName(n Name, compress bool) error {
	labels, err := n.labels()
	if err != nil {
		return err
	}
	var total int
	for _, l := range labels {
		total += 1 + len(l)
	}
	if total+1 > maxNameLen {
		return fmt.Errorf("name %q: %w", n, ErrNameTooLong)
	}

	for i, l := range labels {
		if compress {
			suffix := suffixKey(labels[i:])
			if off, ok := e.ptrs[suffix]; ok {
				e.buf = append(e.buf, byte(0xC0|off>>8), byte(off))
				return nil
			}
			// Offsets above 14 bits cannot be expressed as a pointer, so they
			// are never recorded as compression targets.
			if len(e.buf) <= 0x3FFF {
				e.ptrs[suffix] = len(e.buf)
			}
		}
		e.buf = append(e.buf, byte(len(l)))
		e.buf = append(e.buf, l...)
	}
	e.buf = append(e.buf, 0)
	return nil
}

// suffixKey identifies a name suffix by the octets it encodes to, length
// prefixes included.
//
// The prefixes are what make the key unambiguous, and joining the labels with a
// separator instead does not: a label may itself contain the separator octet,
// so the single label "a.b" and the pair "a", "b" would share a key while being
// different names. The encoder would then point the second at the first and
// silently rewrite it. Keying on the wire octets makes two suffixes collide
// exactly when a pointer between them is correct, which is the property being
// relied on when one name is replaced by the offset of another.
func suffixKey(labels [][]byte) string {
	var b strings.Builder
	for _, l := range labels {
		b.WriteByte(byte(len(l)))
		b.Write(l)
	}
	return b.String()
}
