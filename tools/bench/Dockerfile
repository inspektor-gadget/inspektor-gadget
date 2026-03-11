FROM --platform=${BUILDPLATFORM} golang:1.25.8-alpine@sha256:8e02eb337d9e0ea459e041f1ee5eece41cbb61f1d83e7d883a3e2fb4862063fa AS builder

ARG TARGETARCH

WORKDIR /go/src/github.com/inspektor-gadget/inspektor-gadget/tools/bench
COPY . /go/src/github.com/inspektor-gadget/inspektor-gadget/tools/bench/
RUN GOARCH=${TARGETARCH} go build -o /bench /go/src/github.com/inspektor-gadget/inspektor-gadget/tools/bench

# Final image
FROM gcr.io/distroless/static-debian12:nonroot@sha256:e8a4044e0b4ae4257efa45fc026c0bc30ad320d43bd4c1a7d5271bd241e386d0
COPY --from=builder /bench /bench

CMD ["/bench"]
