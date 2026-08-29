# hollow

`hollow` is a zero-dependency DNS toolkit built entirely on the Go standard library (`net`, `encoding/binary`, `crypto/rand`, `net/netip`, `flag`, `text/tabwriter`, `encoding/json`). It provides wire-level DNS encoding and decoding, resolution over UDP with TCP fallback, dig-style presentation and JSON output, in a single static binary.

## Quick Start

Build the binary from source:

```bash
go build ./cmd/hollow
```

## Example Usage

Run DNS queries directly against a DNS server:

```bash
# 1. Resolve A records for example.com
./hollow resolve --server 8.8.8.8 example.com

# 2. Resolve MX records for google.com
./hollow resolve --server 8.8.8.8 google.com MX

# 3. Output resolution result in JSON format
./hollow resolve --server 8.8.8.8 --json example.com
```

## Architecture

The codebase is organized into clean, focused packages:

* `cmd/hollow/`: CLI entry point and verb routing.
* `internal/cli/`: Flag parsing, exit code mapping, dig-style and JSON output formatting.
* `internal/wire/`: Standard-library DNS message codec (`Header`, `Question`, `RR`, `Message`, `EDNS`, `RData`). Implements domain name compression pointer loop defenses.
* `internal/resolver/`: Network transport layer handling UDP resolution with automatic TCP fallback on truncation (TC bit set).

## Concurrency Model

There is no concurrency model to document yet. `hollow serve` is not implemented, and `hollow resolve` performs one exchange at a time, so nothing in the binary as it stands runs concurrently.

When the server lands, this section will state the worker pool size, what happens when the queue is full and why dropping is the correct answer for UDP, and where the model breaks under load.

## Honest Limitations

* **Server Status**: The `serve` command is currently an unimplemented stub.
* **Iterative Resolution**: Iterative root hint resolution is currently under active development (`--server` IP is required).
* **DNSSEC**: EDNS0 is implemented and queries advertise a 1232-octet payload size. The DO bit is decoded and displayed when a server sets it, but there is no flag to request DNSSEC records and no validation of them.

## Reproducible Build Proof

`hollow` builds reproducibly: the same source produces a byte-identical binary, from any directory, because `-trimpath` keeps the build path out of it.

* **SHA-256, linux/amd64, go1.25.0, `CGO_ENABLED=0`**: `6426a469b14a2da851e5d2b2fd99a3ec14ada6efa3ca20a04987748f342c37df`
* The hash is of the binary this commit builds and is specific to that platform and toolchain. A build for another target will differ, and so will this line after any change to `cmd/hollow` or anything it imports.
* Verify reproducibility locally:

```bash
make reproduce
```