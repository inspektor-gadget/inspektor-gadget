# Developer Notes

This file complements the README file with implementation details specific to this gadget. It includes diagrams that illustrate how eBPF programs interact with eBPF maps. These visualizations help clarify the internal data flow and logic, making it easier to understand, maintain, and extend the gadget.

## Program-Map interactions

The following diagrams are generated using the `ig image inspect` command. Note they are a best-effort representation of the actual interactions, as they do not account for conditionals in the code that may prevent certain program–map interactions from occurring at runtime.

### Flowchart

```mermaid
flowchart LR
counts[("counts")]
gadget_mntns_filter_map[("gadget_mntns_filter_map")]
start[("start")]
whobyreq[("whobyreq")]
ig_topio_done -- "Lookup+Delete" --> start
ig_topio_done -- "Lookup+Delete" --> whobyreq
ig_topio_done -- "Lookup+Update" --> counts
ig_topio_done["ig_topio_done"]
ig_topio_req -- "Update" --> start
ig_topio_req["ig_topio_req"]
ig_topio_start -- "Lookup" --> gadget_mntns_filter_map
ig_topio_start -- "Update" --> whobyreq
ig_topio_start["ig_topio_start"]
```

### Sequence Diagram

```mermaid
sequenceDiagram
box eBPF Programs
participant ig_topio_done
participant ig_topio_req
participant ig_topio_start
end
box eBPF Maps
participant start
participant whobyreq
participant counts
participant gadget_mntns_filter_map
end
ig_topio_done->>start: Lookup
ig_topio_done->>whobyreq: Lookup
ig_topio_done->>counts: Lookup
ig_topio_done->>counts: Update
ig_topio_done->>start: Delete
ig_topio_done->>whobyreq: Delete
ig_topio_req->>start: Update
ig_topio_start->>gadget_mntns_filter_map: Lookup
ig_topio_start->>whobyreq: Update
```
