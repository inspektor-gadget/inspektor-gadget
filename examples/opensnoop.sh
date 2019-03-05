#!/bin/bash

CID=${1:-8e0391ab255c21e352b6f32b36af8368af4e6fb053aef17f7091a92344bbce58}
/bin/bpftool map exec pinned /sys/fs/bpf/pidmap fd 99 cmd -- /bin/opensnoop --extended_fields --containerid $CID

