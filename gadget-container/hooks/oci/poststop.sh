#!/bin/bash
read JSON
pidof gadgettracermanager > /dev/null || exit 0
echo $JSON | /opt/hooks/oci/ocihookgadget -hook poststop >> /var/log/gadget.log 2>&1
exit 0
