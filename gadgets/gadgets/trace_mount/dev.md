# Developer Notes

This file complements the README file with implementation details specific to this gadget. It includes diagrams that illustrate how eBPF programs interact with eBPF maps. These visualizations help clarify the internal data flow and logic, making it easier to understand, maintain, and extend the gadget.

## Program-Map interactions

The following diagrams are generated using the `ig image inspect` command. Note they are a best-effort representation of the actual interactions, as they do not account for conditionals in the code that may prevent certain program–map interactions from occurring at runtime.

### Flowchart

```mermaid
flowchart LR
args[("args")]
bufs[("bufs")]
events[("events")]
gadget_heap[("gadget_heap")]
gadget_mntns_filter_map[("gadget_mntns_filter_map")]
ig_mount_e -- "Lookup" --> gadget_mntns_filter_map
ig_mount_e -- "Update" --> args
ig_mount_e["ig_mount_e"]
ig_mount_x -- "Lookup+Delete" --> args
ig_mount_x -- "Lookup" --> gadget_heap
ig_mount_x -- "EventOutput" --> events
ig_mount_x["ig_mount_x"]
ig_umount_e -- "Lookup" --> gadget_mntns_filter_map
ig_umount_e -- "Update" --> args
ig_umount_e["ig_umount_e"]
ig_umount_x -- "Lookup+Delete" --> args
ig_umount_x -- "Lookup" --> gadget_heap
ig_umount_x -- "EventOutput" --> events
ig_umount_x["ig_umount_x"]
```

### Sequence Diagram

```mermaid
sequenceDiagram
box eBPF Programs
participant ig_mount_e
participant ig_mount_x
participant ig_umount_e
participant ig_umount_x
end
box eBPF Maps
participant gadget_mntns_filter_map
participant args
participant gadget_heap
participant events
end
ig_mount_e->>gadget_mntns_filter_map: Lookup
ig_mount_e->>args: Update
ig_mount_x->>args: Lookup
ig_mount_x->>gadget_heap: Lookup
ig_mount_x->>events: EventOutput
ig_mount_x->>args: Delete
ig_umount_e->>gadget_mntns_filter_map: Lookup
ig_umount_e->>args: Update
ig_umount_x->>args: Lookup
ig_umount_x->>gadget_heap: Lookup
ig_umount_x->>events: EventOutput
ig_umount_x->>args: Delete
```
