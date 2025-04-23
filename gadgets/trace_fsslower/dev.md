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
starts[("starts")]
ig_fssl_open_e -- "Lookup" --> gadget_mntns_filter_map
ig_fssl_open_e -- "Update" --> starts
ig_fssl_open_e["ig_fssl_open_e"]
ig_fssl_open_x -- "Lookup+Delete" --> starts
ig_fssl_open_x -- "Lookup" --> gadget_heap
ig_fssl_open_x -- "EventOutput" --> events
ig_fssl_open_x["ig_fssl_open_x"]
ig_fssl_read_e -- "Lookup" --> gadget_mntns_filter_map
ig_fssl_read_e -- "Update" --> starts
ig_fssl_read_e["ig_fssl_read_e"]
ig_fssl_read_x -- "Lookup+Delete" --> starts
ig_fssl_read_x -- "Lookup" --> gadget_heap
ig_fssl_read_x -- "EventOutput" --> events
ig_fssl_read_x["ig_fssl_read_x"]
ig_fssl_statfs_e -- "Lookup" --> gadget_mntns_filter_map
ig_fssl_statfs_e -- "Update" --> starts
ig_fssl_statfs_e["ig_fssl_statfs_e"]
ig_fssl_statfs_x -- "Lookup+Delete" --> starts
ig_fssl_statfs_x -- "Lookup" --> gadget_heap
ig_fssl_statfs_x -- "EventOutput" --> events
ig_fssl_statfs_x["ig_fssl_statfs_x"]
ig_fssl_sync_e -- "Lookup" --> gadget_mntns_filter_map
ig_fssl_sync_e -- "Update" --> starts
ig_fssl_sync_e["ig_fssl_sync_e"]
ig_fssl_sync_x -- "Lookup+Delete" --> starts
ig_fssl_sync_x -- "Lookup" --> gadget_heap
ig_fssl_sync_x -- "EventOutput" --> events
ig_fssl_sync_x["ig_fssl_sync_x"]
ig_fssl_wr_e -- "Lookup" --> gadget_mntns_filter_map
ig_fssl_wr_e -- "Update" --> starts
ig_fssl_wr_e["ig_fssl_wr_e"]
ig_fssl_wr_x -- "Lookup+Delete" --> starts
ig_fssl_wr_x -- "Lookup" --> gadget_heap
ig_fssl_wr_x -- "EventOutput" --> events
ig_fssl_wr_x["ig_fssl_wr_x"]
```

### Sequence Diagram

```mermaid
sequenceDiagram
box eBPF Programs
participant ig_fssl_open_e
participant ig_fssl_open_x
participant ig_fssl_read_e
participant ig_fssl_read_x
participant ig_fssl_statfs_e
participant ig_fssl_statfs_x
participant ig_fssl_sync_e
participant ig_fssl_sync_x
participant ig_fssl_wr_e
participant ig_fssl_wr_x
end
box eBPF Maps
participant gadget_mntns_filter_map
participant starts
participant gadget_heap
participant events
end
ig_fssl_open_e->>gadget_mntns_filter_map: Lookup
ig_fssl_open_e->>starts: Update
ig_fssl_open_x->>starts: Lookup
ig_fssl_open_x->>starts: Delete
ig_fssl_open_x->>gadget_heap: Lookup
ig_fssl_open_x->>events: EventOutput
ig_fssl_read_e->>gadget_mntns_filter_map: Lookup
ig_fssl_read_e->>starts: Update
ig_fssl_read_x->>starts: Lookup
ig_fssl_read_x->>starts: Delete
ig_fssl_read_x->>gadget_heap: Lookup
ig_fssl_read_x->>events: EventOutput
ig_fssl_statfs_e->>gadget_mntns_filter_map: Lookup
ig_fssl_statfs_e->>starts: Update
ig_fssl_statfs_x->>starts: Lookup
ig_fssl_statfs_x->>starts: Delete
ig_fssl_statfs_x->>gadget_heap: Lookup
ig_fssl_statfs_x->>events: EventOutput
ig_fssl_sync_e->>gadget_mntns_filter_map: Lookup
ig_fssl_sync_e->>starts: Update
ig_fssl_sync_x->>starts: Lookup
ig_fssl_sync_x->>starts: Delete
ig_fssl_sync_x->>gadget_heap: Lookup
ig_fssl_sync_x->>events: EventOutput
ig_fssl_wr_e->>gadget_mntns_filter_map: Lookup
ig_fssl_wr_e->>starts: Update
ig_fssl_wr_x->>starts: Lookup
ig_fssl_wr_x->>starts: Delete
ig_fssl_wr_x->>gadget_heap: Lookup
ig_fssl_wr_x->>events: EventOutput
```
