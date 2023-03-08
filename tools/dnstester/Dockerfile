FROM golang:1.19-alpine AS builder
WORKDIR /go/src/github.com/inspektor-gadget/inspektor-gadget/tools/dnstester

COPY go.mod go.sum dnstester.go /go/src/github.com/inspektor-gadget/inspektor-gadget/tools/dnstester/
RUN go build -o /dnstester /go/src/github.com/inspektor-gadget/inspektor-gadget/tools/dnstester

# Final image
FROM alpine:3.14
COPY --from=builder /dnstester /dnstester
