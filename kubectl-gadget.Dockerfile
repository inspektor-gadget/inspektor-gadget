FROM golang:1.18-bullseye as builder

# Cache go modules so they won't be downloaded at each build
COPY go.mod go.sum /gadget/
RUN cd /gadget && go mod download

# This COPY is limited by .dockerignore
COPY ./ /gadget

RUN cd /gadget && make kubectl-gadget

FROM scratch
COPY --from=builder /gadget/kubectl-gadget /kubectl-gadget
