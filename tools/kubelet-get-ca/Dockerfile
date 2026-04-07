FROM --platform=${BUILDPLATFORM} golang:1.25.9-alpine@sha256:7a00384194cf2cb68924bbb918d675f1517357433c8541bac0ab2f929b9d5447 AS builder

ARG TARGETARCH

WORKDIR /go/src/github.com/inspektor-gadget/inspektor-gadget/tools/ca-job
COPY go.mod go.sum kubelet-get-ca.go /go/src/github.com/inspektor-gadget/inspektor-gadget/tools/ca-job/
RUN CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -ldflags '-w -s' -o /kubelet-get-ca .

FROM gcr.io/distroless/static-debian12@sha256:ce46866b3a5170db3b49364900fb3168dc0833dfb46c26da5c77f22abb01d8c3
COPY --from=builder /kubelet-get-ca /kubelet-get-ca
ENTRYPOINT ["/kubelet-get-ca"]
