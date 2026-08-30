# A second build path, and a second proof. The image has one layer holding one
# static binary, because there is nothing else to put in it.
#
# There is no `go mod download` step here. That line is the first thing in
# almost every Go Dockerfile ever written, and its absence is the point: there
# is nothing to download. The build copies source and compiles it.

# Pinned to a patch version, not to golang:1.25. The floating tag was go1.25.14
# on the day this was written and the binary it produced differed from the
# published hash, which is correct behaviour and exactly the problem: a
# reproducible build is reproducible for one toolchain. Pinning is what lets the
# check below be an equality rather than a hope.
FROM golang:1.25.0 AS build

# The same reason the Makefile pins it. GOTOOLCHAIN=auto would let the build
# fetch a toolchain from proxy.golang.org if go.mod ever named a newer version,
# which is a network dependency arriving through the back door.
ENV GOTOOLCHAIN=local
ENV CGO_ENABLED=0

WORKDIR /src

# One COPY, not the usual two. The go.mod-first idiom exists to cache a
# `go mod download` layer, and with no download step to cache, splitting the
# copy would buy nothing and imply a step that is not here.
COPY . .

# The same flags as make build and make release. With the toolchain pinned above
# and -trimpath keeping /src out of the result, the binary in this image is byte
# identical to the linux/amd64 hash published in README.md, which turns the
# image into a second way to check that number rather than a second artifact
# nobody checked.
RUN go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o /hollow ./cmd/hollow

FROM scratch

# No CA bundle is copied in, and that is not an oversight. DNS over UDP and TCP
# carries no TLS, so there is no certificate to verify; the resolver's trust
# comes from the compiled-in root hints instead. A scratch image with a
# ca-certificates layer would be cargo cult.
#
# No /etc/resolv.conf either. hollow walks from the root servers rather than
# asking the host resolver, so an image with no resolver configuration at all is
# still a working one. Forwarding mode is the exception and it takes its
# upstream on the command line.

COPY --from=build /hollow /hollow

# Numeric because scratch has no /etc/passwd for a name to resolve against.
# Port 15353 rather than 53 is what makes this possible: an unprivileged
# process cannot bind a port below 1024 without a capability.
USER 65534:65534

EXPOSE 15353/udp 15353/tcp 15354/tcp

# 0.0.0.0, not the 127.0.0.1 default. The default is deliberately loopback so
# that running hollow on a laptop does not put an open resolver on the network,
# but inside a container loopback is the container's own, and a published port
# would reach nothing. The network boundary here is the container's, and -p is
# what decides who can see it.
ENTRYPOINT ["/hollow"]
CMD ["serve", "--addr", "0.0.0.0:15353"]
