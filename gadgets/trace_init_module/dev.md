# Developer Notes

This file complements the README file with implementation details specific to this gadget. It includes diagrams that illustrate how eBPF programs interact with eBPF maps. These visualizations help clarify the internal data flow and logic, making it easier to understand, maintain, and extend the gadget.

## Program-Map interactions

The following diagrams are generated using the `ig image inspect` command. Note they are a best-effort representation of the actual interactions, as they do not account for conditionals in the code that may prevent certain program–map interactions from occurring at runtime.

### Flowchart

```mermaid
flowchart LR
bufs[("bufs")]
events[("events")]
events_lost_samples[("events_lost_samples")]
gadget_heap[("gadget_heap")]
gadget_mntns_filter_map[("gadget_mntns_filter_map")]
ig_finit_module_e -- "Lookup" --> gadget_mntns_filter_map
ig_finit_module_e -- "Lookup" --> gadget_heap
ig_finit_module_e -- "Lookup" --> bufs
ig_finit_module_e -- "Lookup" --> events_lost_samples
ig_finit_module_e -- "EventOutput" --> events
ig_finit_module_e["ig_finit_module_e"]
ig_init_module_e -- "Lookup" --> gadget_mntns_filter_map
ig_init_module_e -- "Lookup" --> gadget_heap
ig_init_module_e -- "Lookup" --> events_lost_samples
ig_init_module_e -- "EventOutput" --> events
ig_init_module_e["ig_init_module_e"]
```

### Sequence Diagram

```mermaid
sequenceDiagram
box eBPF Programs
participant ig_finit_module_e
participant ig_init_module_e
end
box eBPF Maps
participant gadget_mntns_filter_map
participant gadget_heap
participant bufs
participant events_lost_samples
participant events
end
ig_finit_module_e->>gadget_mntns_filter_map: Lookup
ig_finit_module_e->>gadget_heap: Lookup
ig_finit_module_e->>bufs: Lookup
ig_finit_module_e->>events_lost_samples: Lookup
ig_finit_module_e->>events: EventOutput
ig_init_module_e->>gadget_mntns_filter_map: Lookup
ig_init_module_e->>gadget_heap: Lookup
ig_init_module_e->>events_lost_samples: Lookup
ig_init_module_e->>events: EventOutput
```
