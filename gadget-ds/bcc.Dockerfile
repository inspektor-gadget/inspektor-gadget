# First, build bcc from the upstream Dockerfile.ubuntu:
#
#   docker build -t kinvolk/bcc:snapshot-20191214-git-6e9b4509fc7a -f ./Dockerfile.ubuntu .
#
# Then, use this Dockerfile with:
#
#   make docker-bcc/build

FROM kinvolk/bcc:snapshot-20191214-git-6e9b4509fc7a as packages

FROM ubuntu:bionic

COPY --from=packages /root/bcc/*.deb /root/

RUN set -ex; \
  apt-get update -y; \
  DEBIAN_FRONTEND=noninteractive \
  apt-get install -y \
    python python3 binutils libelf1; \
  dpkg -i /root/*.deb; \
  rm -f /root/*.deb
