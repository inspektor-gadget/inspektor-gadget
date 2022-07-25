# We need <asm/types.h> and depending on Linux distributions, it is installed
# at different paths:
#
# * Ubuntu, package linux-libc-dev:
#   /usr/include/x86_64-linux-gnu/asm/types.h
#
# * Fedora, package kernel-headers
#   /usr/include/asm/types.h
#
# Since Ubuntu does not install it in a standard path, add a compiler flag for
# it.
#! /bin/bash
CLANG_OS_FLAGS=
if [ "$(grep -oP '^NAME="\K\w+(?=")' /etc/os-release)" == "Ubuntu" ]; then
       CLANG_OS_FLAGS="-I/usr/include/$(uname -m)-linux-gnu"
fi
