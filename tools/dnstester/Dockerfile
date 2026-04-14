FROM --platform=${BUILDPLATFORM} golang:1.25.9-alpine@sha256:7a00384194cf2cb68924bbb918d675f1517357433c8541bac0ab2f929b9d5447 AS builder

ARG TARGETARCH

WORKDIR /go/src/github.com/inspektor-gadget/inspektor-gadget/tools/dnstester
COPY go.mod go.sum dnstester.go /go/src/github.com/inspektor-gadget/inspektor-gadget/tools/dnstester/
RUN GOARCH=${TARGETARCH} go build -o /dnstester /go/src/github.com/inspektor-gadget/inspektor-gadget/tools/dnstester

# Final image
FROM alpine:3.18@sha256:1875c923b73448b558132e7d4a44b815d078779ed7a73f76209c6372de95ea8d
COPY --from=builder /dnstester /dnstester
RUN apk --no-cache upgrade -a && apk --no-cache add bind-tools

CMD ["/dnstester"]
