#!/bin/bash
read JSON
pidof gadgettracermanager > /dev/null || exit 0
echo $JSON | /opt/bin/ocihookgadget %NODE% -hook poststop >> /var/log/gadget.log 2>&1
exit 0
