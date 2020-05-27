#!/bin/bash
read JSON
pidof gadgettracermanager > /dev/null || exit 0
NODE_NAME=
echo $JSON | /opt/bin/ocihookgadget -hook prestart -node "$NODE_NAME" >> /var/log/gadget.log 2>&1
exit 0
