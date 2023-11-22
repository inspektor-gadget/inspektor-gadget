#!/bin/bash
# $1 is the gadget namespace name

read JSON
test -S /run/$1-gadgettracermanager.socket || exit 0
echo $JSON | /opt/hooks/oci/$1-gadget/ocihookgadget -hook prestart -socketfile /run/$1-gadgettracermanager.socket >> /var/log/$1-gadget.log 2>&1
exit 0
