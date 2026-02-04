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
ig_init_module_e -- "Lookup" --> gadget_mntns_filter_map
ig_init_module_e -- "Lookup" --> gadget_heap
ig_init_module_e -- "EventOutput" --> events
ig_init_module_e["ig_init_module_e"]
```

### Sequence Diagram

```mermaid
sequenceDiagram
box eBPF Programs
participant ig_init_module_e
end
box eBPF Maps
participant gadget_mntns_filter_map
participant gadget_heap
participant events
end
ig_init_module_e->>gadget_mntns_filter_map: Lookup
ig_init_module_e->>gadget_heap: Lookup
ig_init_module_e->>events: EventOutput
```
