FROM --platform=${BUILDPLATFORM} golang:1.26.3-alpine@sha256:91eda9776261207ea25fd06b5b7fed8d397dd2c0a283e77f2ab6e91bfa71079d AS builder

ARG TARGETARCH

WORKDIR /go/src/github.com/inspektor-gadget/inspektor-gadget/tools/ca-job
COPY go.mod go.sum kubelet-get-ca.go /go/src/github.com/inspektor-gadget/inspektor-gadget/tools/ca-job/
RUN CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -ldflags '-w -s' -o /kubelet-get-ca .

FROM gcr.io/distroless/static-debian12@sha256:ce46866b3a5170db3b49364900fb3168dc0833dfb46c26da5c77f22abb01d8c3
COPY --from=builder /kubelet-get-ca /kubelet-get-ca
ENTRYPOINT ["/kubelet-get-ca"]
