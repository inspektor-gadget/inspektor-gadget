# Developer Notes

This file complements the README file with implementation details specific to this gadget. It includes diagrams that illustrate how eBPF programs interact with eBPF maps. These visualizations help clarify the internal data flow and logic, making it easier to understand, maintain, and extend the gadget.

## Program-Map interactions

The following diagrams are generated using the `ig image inspect` command. Note they are a best-effort representation of the actual interactions, as they do not account for conditionals in the code that may prevent certain program–map interactions from occurring at runtime.

### Flowchart

```mermaid
flowchart LR
args_scratch[("args_scratch")]
bufs[("bufs")]
events[("events")]
events_lost_samples[("events_lost_samples")]
gadget_heap[("gadget_heap")]
gadget_mntns_filter_map[("gadget_mntns_filter_map")]
start[("start")]
ig_rename_e -- "Lookup" --> gadget_mntns_filter_map
ig_rename_e -- "Lookup" --> args_scratch
ig_rename_e -- "Update" --> start
ig_rename_e["ig_rename_e"]
ig_rename_paths -- "Lookup" --> start
ig_rename_paths -- "Lookup" --> bufs
ig_rename_paths["ig_rename_paths"]
ig_rename_x -- "Lookup+Delete" --> start
ig_rename_x -- "Lookup" --> gadget_heap
ig_rename_x -- "Lookup" --> events_lost_samples
ig_rename_x -- "EventOutput" --> events
ig_rename_x["ig_rename_x"]
ig_renameat2_e -- "Lookup" --> gadget_mntns_filter_map
ig_renameat2_e -- "Lookup" --> args_scratch
ig_renameat2_e -- "Update" --> start
ig_renameat2_e["ig_renameat2_e"]
ig_renameat2_x -- "Lookup+Delete" --> start
ig_renameat2_x -- "Lookup" --> gadget_heap
ig_renameat2_x -- "Lookup" --> events_lost_samples
ig_renameat2_x -- "EventOutput" --> events
ig_renameat2_x["ig_renameat2_x"]
ig_renameat_e -- "Lookup" --> gadget_mntns_filter_map
ig_renameat_e -- "Lookup" --> args_scratch
ig_renameat_e -- "Update" --> start
ig_renameat_e["ig_renameat_e"]
ig_renameat_x -- "Lookup+Delete" --> start
ig_renameat_x -- "Lookup" --> gadget_heap
ig_renameat_x -- "Lookup" --> events_lost_samples
ig_renameat_x -- "EventOutput" --> events
ig_renameat_x["ig_renameat_x"]
```

### Sequence Diagram

```mermaid
sequenceDiagram
box eBPF Programs
participant ig_rename_e
participant ig_rename_paths
participant ig_rename_x
participant ig_renameat2_e
participant ig_renameat2_x
participant ig_renameat_e
participant ig_renameat_x
end
box eBPF Maps
participant gadget_mntns_filter_map
participant args_scratch
participant start
participant bufs
participant gadget_heap
participant events_lost_samples
participant events
end
ig_rename_e->>gadget_mntns_filter_map: Lookup
ig_rename_e->>args_scratch: Lookup
ig_rename_e->>start: Update
ig_rename_paths->>start: Lookup
ig_rename_paths->>bufs: Lookup
ig_rename_x->>start: Lookup
ig_rename_x->>gadget_heap: Lookup
ig_rename_x->>events_lost_samples: Lookup
ig_rename_x->>events: EventOutput
ig_rename_x->>start: Delete
ig_renameat2_e->>gadget_mntns_filter_map: Lookup
ig_renameat2_e->>args_scratch: Lookup
ig_renameat2_e->>start: Update
ig_renameat2_x->>start: Lookup
ig_renameat2_x->>gadget_heap: Lookup
ig_renameat2_x->>events_lost_samples: Lookup
ig_renameat2_x->>events: EventOutput
ig_renameat2_x->>start: Delete
ig_renameat_e->>gadget_mntns_filter_map: Lookup
ig_renameat_e->>args_scratch: Lookup
ig_renameat_e->>start: Update
ig_renameat_x->>start: Lookup
ig_renameat_x->>gadget_heap: Lookup
ig_renameat_x->>events_lost_samples: Lookup
ig_renameat_x->>events: EventOutput
ig_renameat_x->>start: Delete
```
