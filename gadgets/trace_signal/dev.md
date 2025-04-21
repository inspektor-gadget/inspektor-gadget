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
values[("values")]
ig_sig_generate -- "Lookup" --> gadget_mntns_filter_map
ig_sig_generate -- "Lookup" --> gadget_heap
ig_sig_generate -- "EventOutput" --> events
ig_sig_generate["ig_sig_generate"]
ig_sig_kill_e -- "Lookup" --> gadget_mntns_filter_map
ig_sig_kill_e -- "Update" --> values
ig_sig_kill_e["ig_sig_kill_e"]
ig_sig_kill_x -- "Lookup+Delete" --> values
ig_sig_kill_x -- "Lookup" --> gadget_heap
ig_sig_kill_x -- "EventOutput" --> events
ig_sig_kill_x["ig_sig_kill_x"]
ig_sig_tgkill_e -- "Lookup" --> gadget_mntns_filter_map
ig_sig_tgkill_e -- "Update" --> values
ig_sig_tgkill_e["ig_sig_tgkill_e"]
ig_sig_tgkill_x -- "Lookup+Delete" --> values
ig_sig_tgkill_x -- "Lookup" --> gadget_heap
ig_sig_tgkill_x -- "EventOutput" --> events
ig_sig_tgkill_x["ig_sig_tgkill_x"]
ig_sig_tkill_e -- "Lookup" --> gadget_mntns_filter_map
ig_sig_tkill_e -- "Update" --> values
ig_sig_tkill_e["ig_sig_tkill_e"]
ig_sig_tkill_x -- "Lookup+Delete" --> values
ig_sig_tkill_x -- "Lookup" --> gadget_heap
ig_sig_tkill_x -- "EventOutput" --> events
ig_sig_tkill_x["ig_sig_tkill_x"]
```

### Sequence Diagram

```mermaid
sequenceDiagram
box eBPF Programs
participant ig_sig_generate
participant ig_sig_kill_e
participant ig_sig_kill_x
participant ig_sig_tgkill_e
participant ig_sig_tgkill_x
participant ig_sig_tkill_e
participant ig_sig_tkill_x
end
box eBPF Maps
participant gadget_mntns_filter_map
participant gadget_heap
participant events
participant values
end
ig_sig_generate->>gadget_mntns_filter_map: Lookup
ig_sig_generate->>gadget_heap: Lookup
ig_sig_generate->>events: EventOutput
ig_sig_kill_e->>gadget_mntns_filter_map: Lookup
ig_sig_kill_e->>values: Update
ig_sig_kill_x->>values: Lookup
ig_sig_kill_x->>gadget_heap: Lookup
ig_sig_kill_x->>events: EventOutput
ig_sig_kill_x->>values: Delete
ig_sig_tgkill_e->>gadget_mntns_filter_map: Lookup
ig_sig_tgkill_e->>values: Update
ig_sig_tgkill_x->>values: Lookup
ig_sig_tgkill_x->>gadget_heap: Lookup
ig_sig_tgkill_x->>events: EventOutput
ig_sig_tgkill_x->>values: Delete
ig_sig_tkill_e->>gadget_mntns_filter_map: Lookup
ig_sig_tkill_e->>values: Update
ig_sig_tkill_x->>values: Lookup
ig_sig_tkill_x->>gadget_heap: Lookup
ig_sig_tkill_x->>events: EventOutput
ig_sig_tkill_x->>values: Delete
```
