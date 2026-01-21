# gadget-template

# cuda-ebpf-poc

trace_cuda is a [gadget from Inspektor
Gadget](https://inspektor-gadget.io/). It traces cuda/GPU operation such as LaunchKernel, MemAlloc,Memcpy.

## How to use

```bash
$ make build
$ make run PARAMS="--verify-image=false -o jsonpretty -v --collect_ustack --host"
```

## Requirements

- ig v0.26.0
- Linux v5.15 

## License 

The user space components are licensed under the [Apache License, Version
2.0](LICENSE). The BPF code templates are licensed under the [General Public
License, Version 2.0, with the Linux-syscall-note](LICENSE-bpf.txt).
