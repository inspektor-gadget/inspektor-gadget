#!/bin/bash

CID=${1:-9b05f87e21763e8c434ad4904a651fd4f6fdf164faf5753bf6902ba2cd99e17f}

/bin/bpftool map exec pinned /sys/fs/bpf/pidmap       fd 90 cmd -- \
/bin/bpftool map exec pinned /sys/fs/bpf/containermap fd 91 cmd -- \
/bin/opensnoop --extended_fields --containerid $CID

