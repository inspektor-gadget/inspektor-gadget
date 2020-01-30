# First, from the bcc sources:
#
#   git clone https://github.com/iovisor/bcc.git
#   cd bcc
#   docker build -t kinvolk/bcc:snapshot-20191221-git-8174c0ae5541 -f ./Dockerfile.ubuntu .
#
# Then, use this Dockerfile with:
#
#   cd gadget-ds/
#   make docker-bcc/build
#   make docker-bcc/push

FROM kinvolk/bcc:snapshot-20191221-git-8174c0ae5541 as packages

FROM ubuntu:bionic

COPY --from=packages /root/bcc/*.deb /root/

RUN set -ex; \
  apt-get update -y; \
  DEBIAN_FRONTEND=noninteractive \
  apt-get install -y \
    python python3 binutils libelf1; \
  dpkg -i /root/*.deb; \
  rm -f /root/*.deb
