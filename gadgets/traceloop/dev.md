# Developer Notes

This file complements the README file with implementation details specific to this gadget. It includes diagrams that illustrate how eBPF programs interact with eBPF maps. These visualizations help clarify the internal data flow and logic, making it easier to understand, maintain, and extend the gadget.

## Program-Map interactions

The following diagrams are generated using the `ig image inspect` command. Note they are a best-effort representation of the actual interactions, as they do not account for conditionals in the code that may prevent certain program–map interactions from occurring at runtime.

### Flowchart

```mermaid
flowchart LR
fake_stack[("fake_stack")]
gadget_mntns_filter_map[("gadget_mntns_filter_map")]
map_of_perf_buffers[("map_of_perf_buffers")]
probe_at_sys_exit[("probe_at_sys_exit")]
regs_map[("regs_map")]
syscalls[("syscalls")]
ig_traceloop_e -- "Lookup" --> map_of_perf_buffers
ig_traceloop_e -- "Lookup+Update" --> fake_stack
ig_traceloop_e -- "Lookup" --> syscalls
ig_traceloop_e -- "Lookup+Update+Delete" --> regs_map
ig_traceloop_e -- "Lookup+Update" --> probe_at_sys_exit
ig_traceloop_e["ig_traceloop_e"]
ig_traceloop_x -- "Lookup" --> map_of_perf_buffers
ig_traceloop_x -- "Lookup+Update+Delete" --> regs_map
ig_traceloop_x -- "Lookup+Update" --> fake_stack
ig_traceloop_x -- "Lookup" --> syscalls
ig_traceloop_x -- "Lookup+Delete" --> probe_at_sys_exit
ig_traceloop_x["ig_traceloop_x"]
```

### Sequence Diagram

```mermaid
sequenceDiagram
box eBPF Programs
participant ig_traceloop_e
participant ig_traceloop_x
end
box eBPF Maps
participant map_of_perf_buffers
participant fake_stack
participant syscalls
participant regs_map
participant probe_at_sys_exit
end
ig_traceloop_e->>map_of_perf_buffers: Lookup
ig_traceloop_e->>fake_stack: Update
ig_traceloop_e->>fake_stack: Lookup
ig_traceloop_e->>syscalls: Lookup
ig_traceloop_e->>regs_map: Update
ig_traceloop_e->>regs_map: Lookup
ig_traceloop_e->>probe_at_sys_exit: Update
ig_traceloop_e->>probe_at_sys_exit: Lookup
ig_traceloop_e->>regs_map: Delete
ig_traceloop_x->>map_of_perf_buffers: Lookup
ig_traceloop_x->>regs_map: Update
ig_traceloop_x->>regs_map: Lookup
ig_traceloop_x->>fake_stack: Update
ig_traceloop_x->>fake_stack: Lookup
ig_traceloop_x->>syscalls: Lookup
ig_traceloop_x->>probe_at_sys_exit: Lookup
ig_traceloop_x->>probe_at_sys_exit: Delete
ig_traceloop_x->>regs_map: Delete
```
