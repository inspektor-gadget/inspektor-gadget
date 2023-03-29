#!/bin/sh

# Copyright 2019-2023 The Inspektor Gadget authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e

if [ ! -r /host/etc/os-release ] ; then
  echo "$0 must be executed in a pod with access to the host via /host" >&2
  exit 1
fi

. /host/etc/os-release

echo -n "OS detected: "
echo $PRETTY_NAME

KERNEL=$(uname -r)
echo -n "Kernel detected: "
echo $KERNEL

# The gadget-core image does not provide bcc.
if [ "$GADGET_IMAGE_FLAVOUR" = "default" ] ; then
	echo -n "bcc detected: "
	dpkg-query --show libbcc | awk '{print $2}' || true
fi

echo -n "Gadget image: "
echo $GADGET_IMAGE

echo "Gadget image flavour: ${GADGET_IMAGE_FLAVOUR}"

echo "Deployment options:"
env | grep '^INSPEKTOR_GADGET_OPTION_.*='

echo -n "Inspektor Gadget version: "
echo $INSPEKTOR_GADGET_VERSION

# Workaround for Minikube with the Docker driver:
# Since it starts an outer docker container with a read-only /sys without bpf
# mounted, passing /sys/fs/bpf from the pseudo-host does not work.
# See also:
# https://github.com/kubernetes/minikube/blob/99a0c91459f17ad8c83c80fc37a9ded41e34370c/deploy/kicbase/entrypoint#L76-L81
BPF_MOUNTPOINT_TYPE="`stat -f -c %T /sys/fs/bpf`"
if [ "$BPF_MOUNTPOINT_TYPE" != "bpf_fs" ] ; then
  echo "/sys/fs/bpf is of type $BPF_MOUNTPOINT_TYPE. Remounting."
  mount -t bpf bpf /sys/fs/bpf/
fi

CRIO=0
if grep -q '^1:name=systemd:.*/crio-[0-9a-f]*\.scope$' /proc/self/cgroup > /dev/null ; then
    echo "CRI-O detected."
    CRIO=1
fi

## Hooks Begins ##

# Choose what hook mode to use based on the configuration detected
HOOK_MODE="$INSPEKTOR_GADGET_OPTION_HOOK_MODE"

if [ "$HOOK_MODE" = "auto" ] || [ -z "$HOOK_MODE" ] ; then
  if [ "$CRIO" = 1 ] ; then
    echo "Hook mode CRI-O detected"
    HOOK_MODE="crio"
  fi
fi

if [ "$HOOK_MODE" = "crio" ] ; then
  echo "Installing hooks scripts on host..."

  mkdir -p /host/opt/hooks/oci/
  for i in ocihookgadget prestart.sh poststop.sh ; do
    echo "Installing $i..."
    cp /opt/hooks/oci/$i /host/opt/hooks/oci/
  done

  for HOOK_PATH in "/host/etc/containers/oci/hooks.d" \
                   "/host/usr/share/containers/oci/hooks.d/"
  do
    echo "Installing OCI hooks configuration in /etc/containers/oci/hooks.d"
    mkdir -p $HOOK_PATH
    cp /opt/hooks/crio/gadget-prestart.json $HOOK_PATH 2>/dev/null || true
    cp /opt/hooks/crio/gadget-poststop.json $HOOK_PATH 2>/dev/null || true

    if ! ls $HOOK_PATH/gadget-{prestart,poststop}.json > /dev/null 2>&1; then
      echo "Couldn't install OCI hooks configuration" >&2
    else
      echo "Hooks installation done"
    fi
  done
fi

if [ "$HOOK_MODE" = "nri" ] ; then
  echo "Installing NRI hooks"

  # first install the binary
  mkdir -p /host/opt/nri/bin/
  cp /opt/hooks/nri/nrigadget /host/opt/nri/bin/

  # then install the configuration
  # if the configuration already exists append a new plugin
  if [ -f "/host/etc/nri/conf.json" ] ; then
    jq '.plugins += [{"type": "nrigadget"}]' /host/etc/nri/conf.json > /tmp/conf.json
    mv /tmp/conf.json /host/etc/nri/conf.json
  else
    mkdir -p /host/etc/nri/
    cp /opt/hooks/nri/conf.json /host/etc/nri/
  fi
fi

if [ "$HOOK_MODE" = "crio" ] || [ "$HOOK_MODE" = "nri" ] ; then
  # For crio and nri, the gadgettracermanager process can passively wait for
  # the gRPC calls without monitoring containers itself.
  GADGET_TRACER_MANAGER_HOOK_MODE=none
elif [ "$HOOK_MODE" = "fanotify" ] || [ "$HOOK_MODE" = "podinformer" ] ; then
  # fanotify and podinformer are implemented in the gadgettracermanager
  # process.
  GADGET_TRACER_MANAGER_HOOK_MODE="$HOOK_MODE"
else
  # Use fanotify if possible, or fall back on podinformer
  GADGET_TRACER_MANAGER_HOOK_MODE="auto"
fi

echo "Gadget Tracer Manager hook mode: ${GADGET_TRACER_MANAGER_HOOK_MODE}"

## Hooks Ends ##

# Use BTFHub if needed
ARCH=$(uname -m)
if test -f /sys/kernel/btf/vmlinux; then
  echo "Kernel provided BTF is available at /sys/kernel/btf/vmlinux"
else
  echo "Kernel provided BTF is not available: Trying shipped BTF files"
  SOURCE_BTF=/btfs/$ID/$VERSION_ID/$ARCH/$KERNEL.btf
  if [ -f $SOURCE_BTF ]; then
    objcopy --input binary --output elf64-little --rename-section .data=.BTF $SOURCE_BTF /boot/vmlinux-$KERNEL
    echo "shipped BTF available. Installed at /boot/vmlinux-$KERNEL"
  else
    echo "shipped BTF not available. Trying to download from BTFHub"

    URL="https://github.com/aquasecurity/btfhub-archive/raw/main/$ID/$VERSION_ID/$ARCH/$KERNEL.btf.tar.xz"

    echo "Trying to download vmlinux from $URL"

    if [[ $(wget -S --spider "$URL" 2>&1 | grep 'HTTP/1.1 200 OK') ]]; then
      wget -q -O /tmp/vmlinux.btf.tar.xz "$URL"
      tar -xf /tmp/vmlinux.btf.tar.xz
      # Use objcopy to put the btf info in an ELF file as libbpf and cilium/ebpf
      # by default check if there is an ELF file with the .BTF section at
      # /boot/vmlinux-$KERNEL.
      objcopy --input binary --output elf64-little --rename-section .data=.BTF *.btf /boot/vmlinux-$KERNEL
      echo "BTF downloaded at /boot/vmlinux-$KERNEL"
    else
      echo "BTF not found"
    fi
  fi
fi

echo "Starting the Gadget Tracer Manager..."
# change directory before running gadgettracermanager
cd /
rm -f /run/gadgettracermanager.socket
rm -f /run/gadgetservice.socket
exec /bin/gadgettracermanager -serve -hook-mode=$GADGET_TRACER_MANAGER_HOOK_MODE \
    -controller -fallback-podinformer=$INSPEKTOR_GADGET_OPTION_FALLBACK_POD_INFORMER
