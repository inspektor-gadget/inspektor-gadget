#!/bin/bash

# Copyright 2019-2021 The Inspektor Gadget authors
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

echo -n "OS detected: "
grep PRETTY_NAME= /host/etc/os-release|cut -d= -f2-

echo -n "Kernel detected: "
uname -r

echo -n "bcc detected: "
dpkg-query --show libbcc|awk '{print $2}'

echo -n "Gadget image: "
echo $TRACELOOP_IMAGE

echo "Deployment options:"
env | grep '^INSPEKTOR_GADGET_OPTION_.*='

echo -n "Inspektor Gadget version: "
echo $INSPEKTOR_GADGET_VERSION

# gobpf currently uses global kprobes via debugfs/tracefs and not the Perf
# Event file descriptor based kprobe (Linux >=4.17). So unfortunately, kprobes
# can remain from previous executions. Ideally, gobpf should implement Perf
# Event based kprobe and fallback to debugfs/tracefs, like bcc:
# https://github.com/iovisor/bcc/blob/6e9b4509fc7a063302b574520bac6d49b01ca97e/src/cc/libbpf.c#L1021-L1027
# Meanwhile, as a workaround, delete probes manually.
# See: https://github.com/iovisor/gobpf/issues/223
echo "-:pfree_uts_ns" >> /sys/kernel/debug/tracing/kprobe_events 2>/dev/null || true
echo "-:pcap_capable" >> /sys/kernel/debug/tracing/kprobe_events 2>/dev/null || true

# Workaround for Minikube with the Docker driver:
# Since it starts an outer docker container with a read-only /sys without bpf
# mounted, passing /sys/fs/bpf from the pseudo-host does not work.
# See also:
# https://github.com/kubernetes/minikube/blob/99a0c91459f17ad8c83c80fc37a9ded41e34370c/deploy/kicbase/entrypoint#L76-L81
BPF_MOUNTPOINT_TYPE="`stat -f --format=%T /sys/fs/bpf`"
if [ "$BPF_MOUNTPOINT_TYPE" != "bpf_fs" ] ; then
  echo "/sys/fs/bpf is of type $BPF_MOUNTPOINT_TYPE. Remounting."
  mount -t bpf bpf /sys/fs/bpf/
fi

CRIO=0
if grep -q '^1:name=systemd:.*/crio-[0-9a-f]*\.scope$' /proc/self/cgroup > /dev/null ; then
    echo "CRI-O detected."
    CRIO=1
fi

if grep -q '^ID="rhcos"$' /host/etc/os-release > /dev/null ; then
  if [ ! -d "/host/usr/src/kernels/$(uname -r)" ] ; then
    echo "Fetching kernel-devel from CentOS 8."
    REPO=http://mirror.centos.org/centos/8/BaseOS/x86_64/os/Packages/
    RPM=kernel-devel-$(uname -r).rpm
    RPMDIR=/opt/gadget-kernel/
    RPMHOSTDIR=/host${RPMDIR}
    mkdir -p $RPMHOSTDIR/usr/src/kernels/
    test -r $RPMHOSTDIR/$RPM || \
        curl -fsSLo $RPMHOSTDIR/$RPM $REPO/$RPM
    test -r $RPMHOSTDIR/usr/src/kernels/`uname -r`/.config || \
        chroot /host sh -c "cd $RPMDIR && rpm2cpio $RPM | cpio -i"
    test ! -L /usr/src || rm -f /usr/src
    mkdir -p /usr/src/kernels/`uname -r`/
    mount --bind $RPMHOSTDIR/usr/src/kernels/`uname -r` /usr/src/kernels/`uname -r`
  fi
fi

## Hooks Begins ##

# Choose what hook mode to use based on the configuration detected
HOOK_MODE="$INSPEKTOR_GADGET_OPTION_HOOK_MODE"

if [ "$HOOK_MODE" = "auto" ] || [ -z "$HOOK_MODE" ] ; then
  if [ "$CRIO" = 1 ] ; then
    echo "hook mode cri-o detected."
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

  echo "Installing OCI hooks configuration in /usr/share/containers/oci/hooks.d"
  mkdir -p /host/usr/share/containers/oci/hooks.d
  cp /opt/hooks/crio/gadget-prestart.json /host/usr/share/containers/oci/hooks.d/gadget-prestart.json
  cp /opt/hooks/crio/gadget-poststop.json /host/usr/share/containers/oci/hooks.d/gadget-poststop.json

  echo "Hooks installation done"
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
KERNEL=$(uname -r)
ARCH=$(uname -m)
if test -f /sys/kernel/btf/vmlinux; then
  echo "BTF is available at /sys/kernel/btf/vmlinux"
else
  echo "BTF is not available: Trying BTFHub"
  source /host/etc/os-release

  URL="https://github.com/aquasecurity/btfhub/raw/main/archive/$ID/$VERSION_ID/$ARCH/$KERNEL.btf.tar.xz"

  echo "Trying to download vmlinux from $URL"

  if [[ $(wget -S --spider "$URL" 2>&1 | grep 'HTTP/1.1 200 OK') ]]; then
    wget -q -O /tmp/vmlinux.btf.tar.xz "$URL"
    tar -xf /tmp/vmlinux.btf.tar.xz
    # Use objcopy to put the btf info in an ELF file as libbpf and cilium/ebpf
    # by default check if there is an ELF file with the .BTF section at
    # /boot/vmlinux-$KERNEL.
    objcopy --input binary --output elf64-little --rename-section .data=.BTF *.btf /boot/vmlinux-$KERNEL
    echo "vmlinux downloaded at /boot/vmlinux-$KERNEL"
  else
    echo "vmlinux not found"
  fi
fi

# Choose what kind of tools based on the configuration detected
TOOLS_MODE="$INSPEKTOR_GADGET_OPTION_TOOLS_MODE"

if [ "$TOOLS_MODE" = "auto" ] || [ -z "$TOOLS_MODE" ] ; then
  if test -f /sys/kernel/btf/vmlinux; then
    echo "BTF is available at /sys/kernel/btf/vmlinux: Using CO-RE based tools"
    TOOLS_MODE="core"
  elif test -f /boot/vmlinux-$KERNEL; then
    echo "BTF is available at /boot/vmlinux-$KERNEL: Using CO-RE based tools"
    TOOLS_MODE="core"
  else
    echo "vmlinux not found. Using standard tools"
    TOOLS_MODE="standard"
  fi
fi

# Create symlinks for tools according to the value of TOOLS_MODE
if [ "$TOOLS_MODE" = "core" ] ; then
  ln -s /bin/libbpf-tools/ /bin/gadgets
elif [ "$TOOLS_MODE" = "standard" ] ; then
  ln -s /usr/share/bcc/tools/ /bin/gadgets
fi

echo "Starting the Gadget Tracer Manager in the background..."
rm -f /run/gadgettracermanager.socket

if [ "$INSPEKTOR_GADGET_OPTION_TRACELOOP" = "true" ] ; then
  /bin/gadgettracermanager -serve -hook-mode=$GADGET_TRACER_MANAGER_HOOK_MODE -controller &

  rm -f /run/traceloop.socket
  if [ "$INSPEKTOR_GADGET_OPTION_TRACELOOP_LOGLEVEL" != "" ] ; then
    exec /bin/traceloop -log "$INSPEKTOR_GADGET_OPTION_TRACELOOP_LOGLEVEL" k8s
  else
    exec /bin/traceloop k8s
  fi
else
  exec /bin/gadgettracermanager -serve -hook-mode=$GADGET_TRACER_MANAGER_HOOK_MODE \
    -controller -fallback-podinformer=$INSPEKTOR_GADGET_OPTION_FALLBACK_POD_INFORMER
fi
