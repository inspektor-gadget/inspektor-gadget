GADGETS = \
	trace_exec_x86.bpf.o trace_exec_arm64.bpf.o \
	trace_open_x86.bpf.o trace_open_arm64.bpf.o \
	trace_tcpconnect_x86.bpf.o trace_tcpconnect_arm64.bpf.o \
	snapshot_process_x86.bpf.o snapshot_process_arm64.bpf.o \
	#

.PHONY: all
all: $(GADGETS)

%_x86.bpf.o : %.bpf.c
	clang -target bpf -Wall -g -O2 -D __TARGET_ARCH_x86 -c $(filter %.c,$^) \
		-I ../pkg/amd64/ -I ../pkg/gadgets/common/ -o $@
%_arm64.bpf.o : %.bpf.c
	clang -target bpf -Wall -g -O2 -D __TARGET_ARCH_arm64 -c $(filter %.c,$^) \
		-I ../pkg/arm64/ -I ../pkg/gadgets/common/ -o $@

clean:
	rm *.o
