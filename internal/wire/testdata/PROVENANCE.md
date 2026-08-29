# Golden fixtures

Captured 2026-08-29 from this machine. Raw UDP response bytes, no EDNS0 on
either query, so both sit under the 512-octet limit that makes fixture 2
interesting.

Queries were hand-built by a throwaway program rather than by `internal/wire`,
so the fixtures are independent of the code they test.

## example-com-a.bin

`example.com A` to `8.8.8.8`, RD=1.

| Property | Value |
|---|---|
| Size | 61 octets |
| Flags | `0x8180` (QR, RD, RA) |
| Counts | QD 1, AN 2, NS 0, AR 0 |
| Answers | two A records, TTL 300 |
| Compression | `c0 0c`, back to the question name |

Addresses came back as `104.20.23.154` and `172.66.147.243`, which are
Cloudflare. `example.com` no longer resolves to `93.184.216.34`, so tests must
assert on structure rather than on addresses.

## com-ns-referral.bin

`com. NS` to `198.41.0.4` (a.root-servers.net), RD=0.

| Property | Value |
|---|---|
| Size | 509 octets |
| Flags | `0x8200` (QR, **TC**) |
| Counts | QD 1, AN 0, NS 13, AR 12 |

Structurally valid but truncated, which is what makes it useful: 13 NS records
with both A and AAAA glue, cut off mid-additional-section.

It contains the byte sequence `01 6a c0 23` at one offset: a fresh single-octet
label `j` followed by a pointer to offset `0x23`, which is itself inside a name
reached by an earlier pointer. That decodes to `j.gtld-servers.net.`. Suffix
sharing across a partially compressed name is what a one-level pointer resolver
gets wrong, so this is the highest-value case in the set.

Pointer target histogram: `c0 23` and `c0 0c` appear 13 times each, `c0 00`
seven times, then a tail of one-off targets.

## Reproducing

`dig` cannot be used directly for the referral. Because TC is set, dig
automatically retries over TCP and returns the 817-octet untruncated response
with 26 additional records, not the 509-octet truncated one. The `.dig.txt`
companions are human-readable annotations only; the `.bin` files are the
fixtures.
