package cli

import (
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/DevInIndia/hollow/internal/resolver"
	"github.com/DevInIndia/hollow/internal/wire"
)

// writeDig renders a reply the way dig does. The format is worth copying rather
// than improving on: anyone reading this output already knows how to, and a
// difference from dig's rendering of the same message is a bug worth seeing.
func writeDig(w io.Writer, r *resolver.Reply, q wire.Question) error {
	// One tabwriter for the whole reply. Lines without tabs pass through
	// untouched, so the comment lines need no special handling and each run of
	// records lines up against its neighbours.
	tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)

	m := r.Msg
	fmt.Fprintf(tw, "; <<>> hollow <<>> %s %s\n", q.Name, q.Type)
	fmt.Fprintf(tw, ";; ->>HEADER<<- opcode: %s, status: %s, id: %d\n",
		opcodeName(m.Header.Opcode), rcodeName(m.Header.Rcode), m.Header.ID)
	fmt.Fprintf(tw, ";; flags:%s; QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d\n",
		flagNames(m.Header), len(m.Questions), len(m.Answers), len(m.Authority), len(m.Additional))

	// The OPT record is a pseudo-record: it carries no data about the name and
	// dig lifts it out of the additional section for that reason.
	if e, ok, err := m.EDNS(); err == nil && ok {
		var flags string
		if e.DO {
			flags = " do"
		}
		fmt.Fprintf(tw, "\n;; OPT PSEUDOSECTION:\n; EDNS: version: %d, flags:%s; udp: %d\n", e.Version, flags, e.UDPSize)
	}

	if len(m.Questions) > 0 {
		fmt.Fprint(tw, "\n;; QUESTION SECTION:\n")
		for _, question := range m.Questions {
			fmt.Fprintf(tw, ";%s\t%s\t%s\n", question.Name, className(question.Class), question.Type)
		}
	}
	writeSection(tw, "ANSWER", m.Answers)
	writeSection(tw, "AUTHORITY", m.Authority)
	writeSection(tw, "ADDITIONAL", m.Additional)

	fmt.Fprintf(tw, "\n;; Query time: %d ms\n", r.RTT.Milliseconds())
	fmt.Fprintf(tw, ";; SERVER: %s#%d (%s)\n", r.Server.Addr(), r.Server.Port(), r.Protocol)
	fmt.Fprintf(tw, ";; MSG SIZE  rcvd: %d\n", r.Size)

	return tw.Flush()
}

func writeSection(w io.Writer, name string, rrs []wire.RR) {
	// The OPT record was already shown as the pseudo-section, and printing it
	// again as a record would render fields that mean something else there.
	var shown []wire.RR
	for _, rr := range rrs {
		if rr.Type != wire.TypeOPT {
			shown = append(shown, rr)
		}
	}
	if len(shown) == 0 {
		return
	}

	fmt.Fprintf(w, "\n;; %s SECTION:\n", name)
	for _, rr := range shown {
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\n", rr.Name, rr.TTL, className(rr.Class), rr.Type, rdataText(rr.Data))
	}
}

// rdataText renders rdata in its presentation form, falling back to the RFC
// 3597 unknown-type syntax for anything this package does not model. That
// fallback is not a placeholder: it is the format a zone file would have to use
// for the same record, so the output stays usable rather than merely honest.
func rdataText(d wire.RData) string {
	switch v := d.(type) {
	case wire.A:
		return v.Addr.String()
	case wire.AAAA:
		return v.Addr.String()
	case wire.NS:
		return string(v.Host)
	case wire.CNAME:
		return string(v.Target)
	case wire.PTR:
		return string(v.Target)
	case wire.MX:
		return fmt.Sprintf("%d %s", v.Preference, v.Exchange)
	case wire.TXT:
		parts := make([]string, len(v.Strings))
		for i, s := range v.Strings {
			parts[i] = quote(s)
		}
		return strings.Join(parts, " ")
	case wire.SOA:
		return fmt.Sprintf("%s %s %d %d %d %d %d",
			v.Primary, v.Mailbox, v.Serial, v.Refresh, v.Retry, v.Expire, v.Minimum)
	case wire.SRV:
		return fmt.Sprintf("%d %d %d %s", v.Priority, v.Weight, v.Port, v.Target)
	case wire.OPT:
		return fmt.Sprintf("%d options", len(v.Options))
	case wire.Unknown:
		return fmt.Sprintf(`\# %d %s`, len(v.Data), hex.EncodeToString(v.Data))
	}
	return fmt.Sprintf("; unrenderable rdata of type %s", d.Type())
}

// quote renders a character-string in the RFC 1035 section 5.1 presentation
// form. strconv.Quote is close but not the same: it escapes a non-ASCII octet
// as \xNN where a zone file needs the decimal \NNN, and a TXT record that comes
// back out of this output has to be one a zone file would accept.
func quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := range len(s) {
		switch c := s[i]; {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c < ' ' || c > '~':
			fmt.Fprintf(&b, `\%03d`, c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func flagNames(h wire.Header) string {
	var b strings.Builder
	for _, f := range []struct {
		set  bool
		name string
	}{
		{h.Response, "qr"},
		{h.Authoritative, "aa"},
		{h.Truncated, "tc"},
		{h.RecursionDesired, "rd"},
		{h.RecursionAvailable, "ra"},
		{h.AuthenticData, "ad"},
		{h.CheckingDisabled, "cd"},
	} {
		if f.set {
			b.WriteByte(' ')
			b.WriteString(f.name)
		}
	}
	return b.String()
}

func rcodeName(rcode uint8) string {
	switch rcode {
	case wire.RcodeSuccess:
		return "NOERROR"
	case wire.RcodeFormErr:
		return "FORMERR"
	case wire.RcodeServFail:
		return "SERVFAIL"
	case wire.RcodeNXDomain:
		return "NXDOMAIN"
	case wire.RcodeNotImp:
		return "NOTIMP"
	case wire.RcodeRefused:
		return "REFUSED"
	}
	return fmt.Sprintf("RCODE%d", rcode)
}

func opcodeName(opcode uint8) string {
	switch opcode {
	case 0:
		return "QUERY"
	case 1:
		return "IQUERY"
	case 2:
		return "STATUS"
	}
	return fmt.Sprintf("OPCODE%d", opcode)
}

func className(c wire.Class) string {
	if c == wire.ClassIN {
		return "IN"
	}
	return fmt.Sprintf("CLASS%d", uint16(c))
}
