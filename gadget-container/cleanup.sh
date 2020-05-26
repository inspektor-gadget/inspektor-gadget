#!/bin/bash

# This script cleans up all the files installed by Inspektor Gadget

# OCI hooks
for i in ocihookgadget runc-hook-prestart.sh runc-hook-poststop.sh ; do
  /bin/rm -f /host/opt/bin/$i
done

# CRIO hooks
/bin/rm -f /host/etc/containers/oci/hooks.d/gadget-prestart.json
/bin/rm -f /host/etc/containers/oci/hooks.d/gadget-prestart.json

# ld preload support
if [ -f "/host/etc/ld.so.preload" ] ; then
  # remove entry in /host/etc/ld.so.preload
  sed -i '/\/opt\/runchooks\/runchooks.so/d' "/host/etc/ld.so.preload"
fi

/bin/rm -f /host/opt/runchooks/runchooks.so
/bin/rm -f /host/opt/runchooks/add-hooks.jq

echo "Cleanup completed"
