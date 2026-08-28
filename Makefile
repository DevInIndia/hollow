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

.PHONY: build test verify deps-proof reproduce

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
	for t in "linux amd64" "linux arm64" "darwin arm64" "windows amd64"; do
		set -- $$t
		CGO_ENABLED=0 GOOS=$$1 GOARCH=$$2 go build -o /dev/null $(PKG)
	done
	echo "VERIFY: all checks passed"

# Records the commands as well as their output so a judge can rerun them.
# A standard library import path never has a dot in its first element, so
# filtering out this module leaves third-party imports as the only lines that do.
deps-proof:
	{
		echo "$$ cat go.mod"
		cat go.mod
		echo
		echo "$$ ls go.sum vendor"
		ls go.sum vendor 2>&1 || true
		echo
		echo "$$ go list -deps ./... | grep -v '^$(MODULE)'"
		go list -deps ./... | grep -v '^$(MODULE)'
		echo
		echo "$$ go list -deps ./... | grep -v '^$(MODULE)' | grep '^[^/]*\.'"
		go list -deps ./... | grep -v '^$(MODULE)' | grep '^[^/]*\.' || true
		echo "(no output above this line means zero third-party dependencies)"
		echo
		echo "$$ go version"
		go version
	} > deps-proof.txt
	cat deps-proof.txt

reproduce:
	mkdir -p build
	CGO_ENABLED=0 go build $(REPRO) -o build/$(BINARY).1 $(PKG)
	CGO_ENABLED=0 go build $(REPRO) -o build/$(BINARY).2 $(PKG)
	sha256sum build/$(BINARY).1 build/$(BINARY).2
	cmp build/$(BINARY).1 build/$(BINARY).2
	rm -rf build
	echo "REPRODUCE: both builds are byte-identical"
