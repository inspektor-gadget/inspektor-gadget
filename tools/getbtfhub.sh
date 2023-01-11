#!/bin/bash

set -e

# Don't clone the repo to /tmp because on some systems it's mounted as tempfs and will require a lot
# of RAM.

if [ ! -d $HOME/btfhub ]; then
	git clone --depth 1 https://github.com/aquasecurity/btfhub $HOME/btfhub
fi

if [ ! -d $HOME/btfhub-archive/ ]; then
	git clone --depth 1 https://github.com/aquasecurity/btfhub-archive/ $HOME/btfhub-archive/
fi
