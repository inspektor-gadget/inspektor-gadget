FROM --platform=${BUILDPLATFORM} golang:1.22-alpine AS builder

ARG TARGETARCH

WORKDIR /go/src/github.com/inspektor-gadget/inspektor-gadget/tools/prepopulator
COPY go.mod go.sum prepopulator.go /go/src/github.com/inspektor-gadget/inspektor-gadget/tools/prepopulator/
RUN GOARCH=${TARGETARCH} go build -o /prepopulator /go/src/github.com/inspektor-gadget/inspektor-gadget/tools/prepopulator

# Final image
FROM gcr.io/distroless/static-debian12
COPY --from=builder /prepopulator /prepopulator

CMD ["/prepopulator"]
