FROM --platform=${BUILDPLATFORM} golang:1.25.8-alpine@sha256:8e02eb337d9e0ea459e041f1ee5eece41cbb61f1d83e7d883a3e2fb4862063fa AS builder

ARG TARGETARCH

WORKDIR /go/src/github.com/inspektor-gadget/inspektor-gadget/tools/ca-job
COPY go.mod go.sum kubelet-get-ca.go /go/src/github.com/inspektor-gadget/inspektor-gadget/tools/ca-job/
RUN CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -ldflags '-w -s' -o /kubelet-get-ca .

FROM gcr.io/distroless/static-debian12@sha256:ce46866b3a5170db3b49364900fb3168dc0833dfb46c26da5c77f22abb01d8c3
COPY --from=builder /kubelet-get-ca /kubelet-get-ca
ENTRYPOINT ["/kubelet-get-ca"]
