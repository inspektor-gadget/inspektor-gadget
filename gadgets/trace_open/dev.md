# Developer Notes

This file complements the README file with implementation details specific to this gadget. It includes diagrams that illustrate how eBPF programs interact with eBPF maps. These visualizations help clarify the internal data flow and logic, making it easier to understand, maintain, and extend the gadget.

## Program-Map interactions

The following diagrams are generated using the `ig image inspect` command. Note they are a best-effort representation of the actual interactions, as they do not account for conditionals in the code that may prevent certain program–map interactions from occurring at runtime.

### Flowchart

```mermaid
flowchart LR
events[("events")]
gadget_heap[("gadget_heap")]
gadget_mntns_filter_map[("gadget_mntns_filter_map")]
ig_ustack[("ig_ustack")]
start[("start")]
ig_open_e -- "Lookup" --> gadget_mntns_filter_map
ig_open_e -- "Update" --> start
ig_open_e["ig_open_e"]
ig_open_x -- "Lookup+Delete" --> start
ig_open_x -- "Lookup" --> gadget_heap
ig_open_x -- "EventOutput" --> events
ig_open_x["ig_open_x"]
ig_openat_e -- "Lookup" --> gadget_mntns_filter_map
ig_openat_e -- "Update" --> start
ig_openat_e["ig_openat_e"]
ig_openat_x -- "Lookup+Delete" --> start
ig_openat_x -- "Lookup" --> gadget_heap
ig_openat_x -- "EventOutput" --> events
ig_openat_x["ig_openat_x"]
```

### Sequence Diagram

```mermaid
sequenceDiagram
box eBPF Programs
participant ig_open_e
participant ig_open_x
participant ig_openat_e
participant ig_openat_x
end
box eBPF Maps
participant gadget_mntns_filter_map
participant start
participant gadget_heap
participant events
end
ig_open_e->>gadget_mntns_filter_map: Lookup
ig_open_e->>start: Update
ig_open_x->>start: Lookup
ig_open_x->>gadget_heap: Lookup
ig_open_x->>events: EventOutput
ig_open_x->>start: Delete
ig_openat_e->>gadget_mntns_filter_map: Lookup
ig_openat_e->>start: Update
ig_openat_x->>start: Lookup
ig_openat_x->>gadget_heap: Lookup
ig_openat_x->>events: EventOutput
ig_openat_x->>start: Delete
```
