# Developer Notes

This file complements the README file with implementation details specific to this gadget. It includes diagrams that illustrate how eBPF programs interact with eBPF maps. These visualizations help clarify the internal data flow and logic, making it easier to understand, maintain, and extend the gadget.

## Program-Map interactions

The following diagrams are generated using the `ig image inspect` command. Note they are a best-effort representation of the actual interactions, as they do not account for conditionals in the code that may prevent certain program–map interactions from occurring at runtime.

### Flowchart

```mermaid
flowchart LR
events[("events")]
gadget_mntns_filter_map[("gadget_mntns_filter_map")]
heap[("heap")]
ig_trace_link -- "Lookup" --> gadget_mntns_filter_map
ig_trace_link -- "EventOutput" --> events
ig_trace_link["ig_trace_link"]
ig_trace_symlink -- "Lookup" --> gadget_mntns_filter_map
ig_trace_symlink -- "Lookup" --> heap
ig_trace_symlink -- "EventOutput" --> events
ig_trace_symlink["ig_trace_symlink"]
```

### Sequence Diagram

```mermaid
sequenceDiagram
box eBPF Programs
participant ig_trace_link
participant ig_trace_symlink
end
box eBPF Maps
participant gadget_mntns_filter_map
participant heap
participant events
end
ig_trace_link->>gadget_mntns_filter_map: Lookup
ig_trace_link->>events: EventOutput
ig_trace_symlink->>gadget_mntns_filter_map: Lookup
ig_trace_symlink->>heap: Lookup
ig_trace_symlink->>events: EventOutput
```
