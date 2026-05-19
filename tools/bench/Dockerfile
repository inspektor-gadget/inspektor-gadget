FROM --platform=${BUILDPLATFORM} golang:1.26.3-alpine@sha256:91eda9776261207ea25fd06b5b7fed8d397dd2c0a283e77f2ab6e91bfa71079d AS builder

ARG TARGETARCH

WORKDIR /go/src/github.com/inspektor-gadget/inspektor-gadget/tools/bench
COPY . /go/src/github.com/inspektor-gadget/inspektor-gadget/tools/bench/
RUN GOARCH=${TARGETARCH} go build -o /bench /go/src/github.com/inspektor-gadget/inspektor-gadget/tools/bench

# Final image
FROM gcr.io/distroless/static-debian12:nonroot@sha256:e8a4044e0b4ae4257efa45fc026c0bc30ad320d43bd4c1a7d5271bd241e386d0
COPY --from=builder /bench /bench

CMD ["/bench"]
