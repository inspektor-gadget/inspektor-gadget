#!/bin/bash
source $(dirname ${BASH_SOURCE})/../util.sh

run "docker stop nginx-container"
run "sudo local-gadget advise seccomp-profile -c nginx-container > local-gadget-advise-seccomp-profile/profile_gadget.json"
