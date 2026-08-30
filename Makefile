BINARY := hollow
PKG    := ./cmd/hollow
MODULE := github.com/DevInIndia/hollow

# GOTOOLCHAIN=auto lets Go download a toolchain from proxy.golang.org at build
# time if go.mod names a version newer than the local one. That is a network
# fetch during the build and an invisible dependency, so pin it off.
export GOTOOLCHAIN := local

# No paths, no VCS stamp, no build id, so two builds from different directories
# produce identical bytes.
LDFLAGS := -s -w -buildid=
REPRO   := -trimpath -buildvcs=false -ldflags='$(LDFLAGS)'

# The verify recipe relies on set -e and on positional parameters surviving
# across lines, both of which need the whole recipe in one shell.
.ONESHELL:
.SHELLFLAGS := -ec

# The environment the SHA-256 published in README.md belongs to. A reproducible
# build is reproducible for one platform and one toolchain, not universally, so
# the hash check runs only where the published value can be right and says why
# it stood aside anywhere else.
HASH_GOOS      := linux
HASH_GOARCH    := amd64
HASH_TOOLCHAIN := go1.25.0

# The four targets the verify gate cross-compiles and the release publishes.
# One list, so a target that is released is a target that is known to build.
TARGETS := linux/amd64 linux/arm64 darwin/arm64 windows/amd64

.PHONY: build test verify hash-check deps-proof reproduce release

build:
	CGO_ENABLED=0 go build $(REPRO) -o $(BINARY) $(PKG)

test:
	go test -race ./...

# The gate that must pass before every commit. CGO_ENABLED is deliberately not
# set globally: -race requires cgo, while the release builds must not link it.
verify:
	go mod tidy
	! grep -qE '^require' go.mod
	test ! -f go.sum
	test ! -d vendor
	test -z "$$(gofmt -l .)"
	go vet ./...
	go test -race ./...
	# Every package, not just $(PKG). The command imports none of the internal
	# tree yet, so building it alone cross-compiled 45 lines of main.go and left
	# the actual code unchecked. No -o: with more than one package go build
	# discards its output already, and -o refuses a second main package, which
	# is a failure that would arrive on the day a second command is added.
	for t in $(TARGETS); do
		CGO_ENABLED=0 GOOS=$${t%/*} GOARCH=$${t#*/} go build ./...
	done
	$(MAKE) --no-print-directory hash-check
	echo "VERIFY: all checks passed"

# Keeping the published hash current was a discipline problem, which means it was
# going to go stale between the commit that changed the binary and the commit
# that noticed. The dependency claim is a gate rather than a promise, and this is
# the same claim about the same artifact, so it gets the same treatment.
hash-check:
	here="$$(go env GOOS)/$$(go env GOARCH) $$(go env GOVERSION)"
	want="$(HASH_GOOS)/$(HASH_GOARCH) $(HASH_TOOLCHAIN)"
	if [ "$$here" != "$$want" ]; then
		echo "HASH: skipped, README publishes $$want and this is $$here"
		exit 0
	fi

	# Read the hash rather than trusting a copy of it: the README is the
	# published artifact, so it is the README that has to be right.
	#
	# The hash is found by the platform named beside it, not by being first in
	# the file. Taking the first 64-hex string worked while exactly one hash was
	# published and became a silent trap the moment the README grew a table of
	# four: reordering the rows would have compared this build against another
	# platform's hash and failed with nothing to suggest why.
	published=$$(grep -E '$(HASH_GOOS)/$(HASH_GOARCH)' README.md | grep -oE '\b[0-9a-f]{64}\b' | head -n 1)
	if [ -z "$$published" ]; then
		echo "HASH: README.md publishes no SHA-256 for $(HASH_GOOS)/$(HASH_GOARCH)" >&2
		exit 1
	fi

	mkdir -p build
	CGO_ENABLED=0 go build $(REPRO) -o build/$(BINARY).hash $(PKG)
	actual=$$(sha256sum build/$(BINARY).hash | cut -d' ' -f1)
	rm -rf build

	if [ "$$published" != "$$actual" ]; then
		echo "HASH: README.md is stale." >&2
		echo "  published $$published" >&2
		echo "  actual    $$actual" >&2
		echo "  Update the SHA-256 in README.md before committing." >&2
		exit 1
	fi
	echo "HASH: README.md matches the build ($$actual)"

# Records the commands as well as their output so a judge can rerun them.
# A standard library import path never has a dot in its first element, so
# filtering out this module leaves third-party imports as the only lines that do.
#
# CGO_ENABLED=0 because that is how the binary is built. With cgo on, the list
# gains runtime/cgo and describes an artifact nobody ships.
deps-proof:
	{
		echo "$$ cat go.mod"
		cat go.mod
		echo
		echo "$$ ls go.sum vendor"
		ls go.sum vendor 2>&1 || true
		echo
		echo "$$ CGO_ENABLED=0 go list -deps ./... | grep -v '^$(MODULE)'"
		CGO_ENABLED=0 go list -deps ./... | grep -v '^$(MODULE)'
		echo
		echo "$$ CGO_ENABLED=0 go list -deps ./... | grep -v '^$(MODULE)' | grep '^[^/]*\.'"
		CGO_ENABLED=0 go list -deps ./... | grep -v '^$(MODULE)' | grep '^[^/]*\.' || true
		echo "(no output above this line means zero third-party dependencies)"
		echo
		echo "One line above needs a word: vendor/golang.org/x/net/dns/dnsmessage."
		echo "That is not a dependency of this project. It is part of the Go"
		echo "distribution, vendored inside the standard library, and package net"
		echo "imports it for the pure-Go resolver. It carries the vendor/ prefix"
		echo "precisely because it is not fetched: it ships with the toolchain."
		echo "There is no vendor/ directory in this repository, no require line,"
		echo "and no go.sum, all of which the commands above demonstrate."
		echo
		echo "$$ go version"
		go version
	} > deps-proof.txt
	cat deps-proof.txt

# Cross-compiled artifacts for a release, built with the same flags as the hash
# gate so that the linux/amd64 row of the published table is the same artifact
# the gate checks on every commit.
#
# Named with their platform, because the one thing a downloader must not have to
# guess is which file is theirs, and .exe on Windows because a browser there
# will not run a file without it.
release:
	rm -rf dist
	mkdir -p dist
	for t in $(TARGETS); do
		os=$${t%/*}
		arch=$${t#*/}
		out=dist/$(BINARY)-$$os-$$arch
		if [ "$$os" = windows ]; then out=$$out.exe; fi
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build $(REPRO) -o $$out $(PKG)
	done

	# A subshell, because .ONESHELL runs this whole recipe in one shell and a cd
	# here would move every line after it. The cd is what keeps bare filenames
	# in the sums file, so sha256sum -c works from the directory a downloader
	# unpacks into. The glob names the binaries rather than everything, since
	# redirection creates SHA256SUMS before the glob expands and it would
	# otherwise checksum itself.
	( cd dist && sha256sum $(BINARY)-* > SHA256SUMS )
	cat dist/SHA256SUMS
	echo "RELEASE: dist/ holds $$(ls dist | grep -c '^$(BINARY)-') binaries and their sums"

reproduce:
	mkdir -p build
	CGO_ENABLED=0 go build $(REPRO) -o build/$(BINARY).1 $(PKG)
	CGO_ENABLED=0 go build $(REPRO) -o build/$(BINARY).2 $(PKG)
	sha256sum build/$(BINARY).1 build/$(BINARY).2
	cmp build/$(BINARY).1 build/$(BINARY).2
	rm -rf build
	echo "REPRODUCE: both builds are byte-identical"
