# Wasm Support in Inspektor Gadget

We want to further extend the flexibility of [image-based
gadgets](./002-containerized-gadgets.md) by allowing users to run custom code in
user space.

## Wasm Capabilities

This section covers the features Wasm should provide to gadget developers.

### Manipulate Data Sources

The Wasm module should be able to manipulate the data coming from other sources,
(eBPF being one of them). It'll allow the Wasm module to change the format of
the fields, for instance, performing string manipulations that are difficult to
implement in eBPF, to enrich events with new information it gathers from other
places, etc. The Wasm program should also be able to create a new data source on
its own to provide new information.

This is the list of operations the Wasm module should be able to do:

- Change the value of fields
  - Implement data manipulations impossible to make in eBPF
- Add fields
  - Create "virtual fields" by combining existing ones. Like the "call" field on the trace mount gadget
  - Create new fields to enrich the event with information the Wasm module has
- Change fields attributes
  - Hide or show the field
  - Change the width used to print it
  - Add and update annotations
  - etc.
- Drop events
  - Implement advanced filtering capabilities
- Create new data sources

### Handle eBPF objects

There are cases when it's useful to allow the Wasm module to directly interact
with eBPF objects.

- Manipulate maps: Get, Delete, Update, etc. (many possible operations allowed on a map)
- Manipulate the eBPF objects before loading
  - Disable or enable programs based on kernel features
  - BPFProgramDisableAutoAttach(progName string)
  - BPFProgramManualAttach(progName string, attachTo string)
- Discover host features
  - KAllSyms (from pkg/kallsyms/kallsyms.go)
    - KAllSymsSymbolExists(name string) bool
    - KAllSymsLookupByInstructionPointer(ip uint64) string
    - KAllSymsSpecUpdateAddresses(funcName string) error
  - btf
    - BTFKernelSpecTypeByName(name string) (btfID u32) (TODO: how to marshall btf.Type?)

### Parameters

- Define new parameters
- Access value of parameters

### Define new output modes

There are gadgets that print their result on a specific format:
- seccomp advisor: provides a yaml file that can be used with the SPO or with Kubernetes
- snapshot process: can print the process using a tree

The Wasm module should be able to define new output modes so we gadget developer
can print the result in any format they want.

### Interact with host system

In order to implement more powerful things, the Wasm module should be able to
have some interaction with the host system. This will allow the gadget to
collect more information.

Note: We need to investigate the security implications of this suppport.

- Read and write files
  - Collect information from the host like logs
  - Report the output of the gadget in different formats
- Open network connections ??
- Interactions with Kubernetes ??
- Interact with container runtimes ??
