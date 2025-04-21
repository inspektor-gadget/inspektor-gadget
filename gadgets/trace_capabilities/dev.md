# Developer Notes

This file complements the README file with implementation details specific to this gadget. It includes diagrams that illustrate how eBPF programs interact with eBPF maps. These visualizations help clarify the internal data flow and logic, making it easier to understand, maintain, and extend the gadget.

## Program-Map interactions

The following diagrams are generated using the `ig image inspect` command. Note they are a best-effort representation of the actual interactions, as they do not account for conditionals in the code that may prevent certain program–map interactions from occurring at runtime.

### Flowchart

```mermaid
flowchart LR
current_syscall[("current_syscall")]
events[("events")]
gadget_heap[("gadget_heap")]
gadget_mntns_filter_map[("gadget_mntns_filter_map")]
ig_kstack[("ig_kstack")]
ig_ustack[("ig_ustack")]
seen[("seen")]
start[("start")]
ig_cap_sched_exec -- "Delete" --> current_syscall
ig_cap_sched_exec["ig_cap_sched_exec"]
ig_cap_sched_exit -- "Delete" --> current_syscall
ig_cap_sched_exit["ig_cap_sched_exit"]
ig_cap_sys_enter -- "Lookup" --> gadget_mntns_filter_map
ig_cap_sys_enter -- "Update" --> current_syscall
ig_cap_sys_enter["ig_cap_sys_enter"]
ig_cap_sys_exit -- "Delete" --> current_syscall
ig_cap_sys_exit["ig_cap_sys_exit"]
ig_trace_cap_e -- "Lookup" --> gadget_mntns_filter_map
ig_trace_cap_e -- "Lookup+Update" --> seen
ig_trace_cap_e -- "Update" --> start
ig_trace_cap_e["ig_trace_cap_e"]
ig_trace_cap_x -- "Lookup+Delete" --> start
ig_trace_cap_x -- "Lookup" --> gadget_heap
ig_trace_cap_x -- "Lookup" --> current_syscall
ig_trace_cap_x -- "EventOutput" --> events
ig_trace_cap_x["ig_trace_cap_x"]
```

### Sequence Diagram

```mermaid
sequenceDiagram
box eBPF Programs
participant ig_cap_sched_exec
participant ig_cap_sched_exit
participant ig_cap_sys_enter
participant ig_cap_sys_exit
participant ig_trace_cap_e
participant ig_trace_cap_x
end
box eBPF Maps
participant current_syscall
participant gadget_mntns_filter_map
participant seen
participant start
participant gadget_heap
participant events
end
ig_cap_sched_exec->>current_syscall: Delete
ig_cap_sched_exit->>current_syscall: Delete
ig_cap_sys_enter->>gadget_mntns_filter_map: Lookup
ig_cap_sys_enter->>current_syscall: Update
ig_cap_sys_exit->>current_syscall: Delete
ig_trace_cap_e->>gadget_mntns_filter_map: Lookup
ig_trace_cap_e->>seen: Lookup
ig_trace_cap_e->>seen: Update
ig_trace_cap_e->>start: Update
ig_trace_cap_x->>start: Lookup
ig_trace_cap_x->>gadget_heap: Lookup
ig_trace_cap_x->>current_syscall: Lookup
ig_trace_cap_x->>events: EventOutput
ig_trace_cap_x->>start: Delete
```
