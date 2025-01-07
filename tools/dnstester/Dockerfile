FROM --platform=${BUILDPLATFORM} golang:1.23-alpine@sha256:13aaa4b92fd4dc81683816b4b62041442e9f685deeb848897ce78c5e2fb03af7 AS builder

ARG TARGETARCH

WORKDIR /go/src/github.com/inspektor-gadget/inspektor-gadget/tools/dnstester
COPY go.mod go.sum dnstester.go /go/src/github.com/inspektor-gadget/inspektor-gadget/tools/dnstester/
RUN GOARCH=${TARGETARCH} go build -o /dnstester /go/src/github.com/inspektor-gadget/inspektor-gadget/tools/dnstester

# Final image
FROM alpine:3.18@sha256:1875c923b73448b558132e7d4a44b815d078779ed7a73f76209c6372de95ea8d
COPY --from=builder /dnstester /dnstester

CMD ["/dnstester"]
