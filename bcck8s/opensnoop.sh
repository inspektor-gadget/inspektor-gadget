#!/bin/bash

/bin/bpftool map exec pinned /sys/fs/bpf/pidmap       fd 90 cmd -- \
/bin/bpftool map exec pinned /sys/fs/bpf/containermap fd 91 cmd -- \
/bin/opensnoop $@

