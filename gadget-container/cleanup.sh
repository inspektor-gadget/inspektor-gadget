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
for i in ocihookgadget runc-hook-prestart.sh runc-hook-poststop.sh ; do
  /bin/rm -f /host/opt/bin/$i
done

# CRIO hooks
/bin/rm -f /host/etc/containers/oci/hooks.d/gadget-prestart.json
/bin/rm -f /host/etc/containers/oci/hooks.d/gadget-poststop.json

# ld preload support
if [ -f "/host/etc/ld.so.preload" ] ; then
  # remove entry in /host/etc/ld.so.preload
  sed -i '/\/opt\/runchooks\/runchooks.so/d' "/host/etc/ld.so.preload"
fi

/bin/rm -f /host/opt/runchooks/runchooks.so
/bin/rm -f /host/opt/runchooks/add-hooks.jq

echo "Cleanup completed"
