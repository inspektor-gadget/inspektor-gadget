#!/bin/bash

set -e
set -x

LIBBPFTOOLS="${LIBBPFTOOLS:-$(pwd)/../bcc/libbpf-tools/.output/}"
BTFHUB="${BTFHUB:-$(pwd)/../btfhub/}"
INSPEKTOR_GADGET=${INSPEKTOR_GADGET:-$(pwd)}
ARCH=x86_64
OUTPUT=/tmp/btfs

if [ ! -d "${LIBBPFTOOLS}" ]; then
    echo "error: libbpftools folder not found"
    exit 1
fi

if [ ! -d "${BTFHUB}" ]; then
    echo "error: btfhub folder not found"
    exit 1
fi

if [ ! -d "${INSPEKTOR_GADGET}" ]; then
    echo "error: Inspektor Gadget not found"
    exit 1
fi

${BTFHUB}/tools/btfgen.sh -a ${ARCH}                                    \
    -o ${LIBBPFTOOLS}/bindsnoop.bpf.o                                   \
    -o ${LIBBPFTOOLS}/execsnoop.bpf.o                                   \
    -o ${LIBBPFTOOLS}/mountsnoop.bpf.o                                  \
    -o ${LIBBPFTOOLS}/opensnoop.bpf.o                                   \
    -o ${LIBBPFTOOLS}/tcpconnect.bpf.o                                  \
    -o ${INSPEKTOR_GADGET}/pkg/gadgets/seccomp/tracer/bpf/seccomp.o     \
    -o ${INSPEKTOR_GADGET}/pkg/gadgets/filetop/tracer/filetop_bpfel.o   \
    -o ${INSPEKTOR_GADGET}/pkg/gadgets/oomkill/tracer/oomkill_bpfel.o   \
    #

mkdir -p ${OUTPUT}
cp -r ${BTFHUB}/custom-archive/* ${OUTPUT}
