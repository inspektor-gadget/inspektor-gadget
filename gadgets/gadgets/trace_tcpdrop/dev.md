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
gadget_sockets[("gadget_sockets")]
ig_kstack[("ig_kstack")]
ig_tcpdrop -- "Lookup" --> gadget_heap
ig_tcpdrop -- "Lookup" --> gadget_sockets
ig_tcpdrop -- "Lookup" --> gadget_mntns_filter_map
ig_tcpdrop -- "EventOutput" --> events
ig_tcpdrop["ig_tcpdrop"]
```

### Sequence Diagram

```mermaid
sequenceDiagram
box eBPF Programs
participant ig_tcpdrop
end
box eBPF Maps
participant gadget_heap
participant gadget_sockets
participant gadget_mntns_filter_map
participant events
end
ig_tcpdrop->>gadget_heap: Lookup
ig_tcpdrop->>gadget_sockets: Lookup
ig_tcpdrop->>gadget_mntns_filter_map: Lookup
ig_tcpdrop->>events: EventOutput
```
