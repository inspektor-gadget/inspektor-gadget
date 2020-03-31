# Main gadget image

FROM docker.io/kinvolk/bcc:latest
RUN apt-get update && apt-get install -y \
  curl

ADD traceloop /bin/traceloop

