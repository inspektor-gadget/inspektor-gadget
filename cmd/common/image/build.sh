#! /bin/sh

# This script is designed to be called by ig. Don't run it directly.
set -eux

inputFile=$1
outputDir=$2
cflags=$3

clang -target bpf -Wall -g -O2 -D __TARGET_ARCH_x86 -c $inputFile \
	-I /usr/include/gadget/amd64/ \
	$cflags \
	-o $outputDir/x86.bpf.o
llvm-strip -g $outputDir/x86.bpf.o

clang -target bpf -Wall -g -O2 -D __TARGET_ARCH_arm64 -c $inputFile \
	-I  /usr/include/gadget/arm64/ \
	$cflags \
	-o $outputDir/arm64.bpf.o
llvm-strip -g $outputDir/arm64.bpf.o
