# First, from the bcc sources:
#
#   git clone https://github.com/iovisor/bcc.git
#   cd bcc
#   TAG="snapshot-$(date +%Y%m%d)-$(git describe --tags --always)"
#   docker build -t kinvolk/bcc:${TAG} -f ./Dockerfile.ubuntu .
#
# Then, use this Dockerfile with:
#
#   cd gadget-ds/
#   make docker-bcc/build
#   make docker-bcc/push

FROM kinvolk/bcc:snapshot-20200220-v0.13.0-2-g12eafe87 as packages

FROM ubuntu:bionic

COPY --from=packages /root/bcc/*.deb /root/

RUN set -ex; \
  apt-get update -y; \
  DEBIAN_FRONTEND=noninteractive \
  apt-get install -y \
    python python3 binutils libelf1; \
  dpkg -i /root/*.deb; \
  rm -f /root/*.deb
