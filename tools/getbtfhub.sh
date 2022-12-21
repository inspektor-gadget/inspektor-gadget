#!/bin/bash

set -e

git clone --depth 1 https://github.com/inspektor-gadget/btfhub /tmp/btfhub -b mauricio/update-bpftool
git clone --depth 1 https://github.com/aquasecurity/btfhub-archive/ /tmp/btfhub-archive/
