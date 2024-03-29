FROM --platform=${BUILDPLATFORM} golang:1.21 AS builder

ARG TARGETARCH

WORKDIR /go/src/github.com/inspektor-gadget/inspektor-gadget/tools/oomkilltester
COPY go.mod oomkilltester.go /go/src/github.com/inspektor-gadget/inspektor-gadget/tools/oomkilltester/
RUN GOARCH=${TARGETARCH} go build -o /oomkilltester /go/src/github.com/inspektor-gadget/inspektor-gadget/tools/oomkilltester

# Final image
FROM gcr.io/distroless/static-debian12
COPY --from=builder /oomkilltester /oomkilltester

CMD ["/oomkilltester"]
