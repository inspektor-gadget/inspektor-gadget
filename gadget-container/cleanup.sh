#!/bin/bash

# This script cleans up all the files installed by Inspektor Gadget

for i in ocihookgadget runc-hook-prestart.sh runc-hook-poststop.sh ; do
  echo "Removing $i..."
  /bin/rm -f /host/opt/bin/$i
done
echo "Cleanup completed"
