#!/bin/bash
read JSON
test -S /run/gadgettracermanager.socket || exit 0
echo $JSON | /opt/hooks/oci/ocihookgadget -hook prestart >> /var/log/gadget.log 2>&1
exit 0
