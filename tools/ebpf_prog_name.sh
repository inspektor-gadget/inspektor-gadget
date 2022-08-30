#!/bin/bash

echo "all eBPF program names:"

for file in $(find pkg/gadgets -type f -name "*.o") ; do
	nm -g -C $file | \
		grep ' T ' | \
		awk '{printf "%s %s\n", "'$file'", $3}'
done | column -t

echo
echo "eBPF program with names longer than 15 characters:"

for file in $(find pkg/gadgets -type f -name "*.o") ; do
	nm -g -C $file | \
		grep ' T ' | \
		awk '{print $3}' | \
		grep -E '(\w{16,})' | \
		awk '{printf "%s %s\n", "'$file'", $1}'
done | column -t

echo
echo "eBPF program with names not starting with ig_:"

for file in $(find pkg/gadgets -type f -name "*.o") ; do
	nm -g -C $file | \
		grep ' T ' | \
		awk '{print $3}' | \
		grep -v '^ig_' | \
		awk '{printf "%s %s\n", "'$file'", $1}'
done | column -t
