#!/bin/bash

source $(dirname ${BASH_SOURCE})/../util.sh

docker stop nginx-container

profile_gadget_json=$(relative profile_gadget.json)
rm $profile_gadget_json
