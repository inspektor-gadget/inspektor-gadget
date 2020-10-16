SHELL=/bin/bash -o pipefail
DEST_DIR?=/dist
LINUX_HEADERS=$(shell rpm -q kernel-devel --last | head -n 1 | awk -F'kernel-devel-' '{print "/usr/src/kernels/"$$2}' | cut -d " " -f 1)

build:
	@mkdir -p "$(DEST_DIR)"
	# main
	clang -D__KERNEL__ -D__ASM_SYSREG_H \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wunused \
		-Wall \
		-Werror \
		-O2 -emit-llvm -c tracer-map.c \
		-DKBUILD_MODNAME="\"inspektor-gadget\"" \
		$(foreach path,$(LINUX_HEADERS), -I $(path)/arch/x86/include -I $(path)/arch/x86/include/generated -I $(path)/include -I $(path)/include/generated/uapi -I $(path)/arch/x86/include/uapi -I $(path)/include/uapi) \
		-o - | llc -march=bpf -filetype=obj -o "${DEST_DIR}/tracer-map.o"
	# bindata
	go-bindata -pkg gadgettracermanager -prefix "${DEST_DIR}/" -modtime 1 -o "${DEST_DIR}/tracer-map-assets-bpf.go" \
		"${DEST_DIR}/tracer-map.o"
