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

# This script cleans up all the files installed by Inspektor Gadget

# OCI hooks
for i in ocihookgadget prestart.sh poststop.sh ; do
  rm -f /host/opt/hooks/oci/$i
done

# CRIO hooks
for HOOK_PATH in "/host/etc/containers/oci/hooks.d" \
                 "/host/usr/share/containers/oci/hooks.d/"
do
  rm -f $HOOK_PATH/gadget-prestart.json
  rm -f $HOOK_PATH/gadget-poststop.json
done

# ld preload support
if [ -f "/host/etc/ld.so.preload" ] ; then
  # remove entry in /host/etc/ld.so.preload
  sed -i '/\/opt\/hooks\/runc\/runchooks.so/d' "/host/etc/ld.so.preload"
fi

# nri
if [ -f "/host/etc/nri/conf.json" ] ; then
  jq 'del(.plugins[] | select(.type == "nrigadget"))' /host/etc/nri/conf.json > /tmp/conf.json
  if [ $(jq '.plugins | length' /tmp/conf.json) == 0 ] ; then
    rm -f /host/etc/nri/conf.json
  else
    mv /tmp/conf.json /host/etc/nri/conf.json
  fi
fi

rm -f /host/opt/nri/bin/nrigadget

# This is a last resource to remove all possible pinned ebpf objects created by
# Inspektor Gadget & Traceloop
rm -rf /sys/fs/bpf/gadget/
rm -rf /sys/fs/bpf/straceback/

echo "Cleanup completed"
