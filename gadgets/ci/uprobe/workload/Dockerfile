# Build the same Go workload with several Go toolchains and several
# linking/stripping options, to test uprobe symbol resolution against all of
# them. A single builder image is used: the additional toolchains are fetched
# on demand through GOTOOLCHAIN, which is much cheaper than pulling one golang
# image per Go version.
FROM golang:1.25.6-bookworm AS builder

# "<directory>:<toolchain>" pairs. The directory only carries the major.minor
# version, so bumping a patch release does not require updating
# program.bpf.c and the integration test.
#
# Please keep the Go versions and build modes in sync with:
# - ../program.bpf.c
# - ../test/integration/ci_uprobe_test.go
ARG GO_TOOLCHAINS="go1.25:go1.25.6 go1.26:go1.26.4"

WORKDIR /src
COPY go.mod main.go ./

RUN set -eux; \
	for pair in $GO_TOOLCHAINS; do \
		dir="${pair%%:*}"; \
		GOTOOLCHAIN="${pair#*:}"; \
		export GOTOOLCHAIN; \
		mkdir -p "/out/$dir/normal" "/out/$dir/pie" \
			"/out/$dir/linker" "/out/$dir/strip"; \
		go build -trimpath -o "/out/$dir/normal/target" .; \
		go build -trimpath -buildmode=pie -o "/out/$dir/pie/target" .; \
		go build -trimpath -ldflags='-s -w' -o "/out/$dir/linker/target" .; \
		go build -trimpath -o /tmp/target .; \
		strip --strip-all -o "/out/$dir/strip/target" /tmp/target; \
	done

FROM debian:bookworm-slim

COPY --from=builder /out /opt/ig-tests/ci-uprobe
