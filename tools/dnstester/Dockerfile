FROM --platform=${BUILDPLATFORM} golang:1.25.5-alpine@sha256:26111811bc967321e7b6f852e914d14bede324cd1accb7f81811929a6a57fea9 AS builder

ARG TARGETARCH

WORKDIR /go/src/github.com/inspektor-gadget/inspektor-gadget/tools/dnstester
COPY go.mod go.sum dnstester.go /go/src/github.com/inspektor-gadget/inspektor-gadget/tools/dnstester/
RUN GOARCH=${TARGETARCH} go build -o /dnstester /go/src/github.com/inspektor-gadget/inspektor-gadget/tools/dnstester

# Final image
FROM alpine:3.23@sha256:865b95f46d98cf867a156fe4a135ad3fe50d2056aa3f25ed31662dff6da4eb62
COPY --from=builder /dnstester /dnstester
RUN apk --no-cache upgrade -a && apk --no-cache add bind-tools

CMD ["/dnstester"]
