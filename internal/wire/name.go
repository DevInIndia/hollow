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

func suffixKey(labels [][]byte) string {
	var b strings.Builder
	for _, l := range labels {
		b.Write(l)
		b.WriteByte('.')
	}
	return b.String()
}
