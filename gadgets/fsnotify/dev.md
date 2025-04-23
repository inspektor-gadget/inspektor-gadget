# Developer Notes

This file complements the README file with implementation details specific to this gadget. It includes diagrams that illustrate how eBPF programs interact with eBPF maps. These visualizations help clarify the internal data flow and logic, making it easier to understand, maintain, and extend the gadget.

## Program-Map interactions

The following diagrams are generated using the `ig image inspect` command. Note they are a best-effort representation of the actual interactions, as they do not account for conditionals in the code that may prevent certain program–map interactions from occurring at runtime.

### Flowchart

```mermaid
flowchart LR
bufs[("bufs")]
enriched_fsnotify_events[("enriched_fsnotify_events")]
events[("events")]
fsnotify_insert_event_ctx[("fsnotify_insert_event_ctx")]
fsnotify_remove_first_event_ctx[("fsnotify_remove_first_event_ctx")]
gadget_heap[("gadget_heap")]
gadget_mntns_filter_map[("gadget_mntns_filter_map")]
fanotify_handle_event_e -- "Update" --> fsnotify_insert_event_ctx
fanotify_handle_event_e["fanotify_handle_event_e"]
fanotify_handle_event_x -- "Delete" --> fsnotify_insert_event_ctx
fanotify_handle_event_x["fanotify_handle_event_x"]
fsnotify_destroy_event -- "Lookup" --> fsnotify_insert_event_ctx
fsnotify_destroy_event -- "Lookup" --> gadget_heap
fsnotify_destroy_event -- "Lookup+Delete" --> enriched_fsnotify_events
fsnotify_destroy_event -- "Lookup" --> bufs
fsnotify_destroy_event -- "EventOutput" --> events
fsnotify_destroy_event["fsnotify_destroy_event"]
fsnotify_insert_event_e -- "Lookup" --> fsnotify_insert_event_ctx
fsnotify_insert_event_e -- "Lookup+Update" --> enriched_fsnotify_events
fsnotify_insert_event_e -- "Lookup" --> bufs
fsnotify_insert_event_e["fsnotify_insert_event_e"]
ig_fa_pick_e -- "Update" --> fsnotify_remove_first_event_ctx
ig_fa_pick_e["ig_fa_pick_e"]
ig_fa_pick_x -- "Lookup+Delete" --> fsnotify_remove_first_event_ctx
ig_fa_pick_x -- "Lookup" --> gadget_heap
ig_fa_pick_x -- "Lookup" --> enriched_fsnotify_events
ig_fa_pick_x -- "EventOutput" --> events
ig_fa_pick_x["ig_fa_pick_x"]
inotify_handle_event_e -- "Update" --> fsnotify_insert_event_ctx
inotify_handle_event_e["inotify_handle_event_e"]
inotify_handle_event_x -- "Delete" --> fsnotify_insert_event_ctx
inotify_handle_event_x["inotify_handle_event_x"]
inotify_handle_inode_event_e -- "Update" --> fsnotify_insert_event_ctx
inotify_handle_inode_event_e["inotify_handle_inode_event_e"]
inotify_handle_inode_event_x -- "Delete" --> fsnotify_insert_event_ctx
inotify_handle_inode_event_x["inotify_handle_inode_event_x"]
```

### Sequence Diagram

```mermaid
sequenceDiagram
box eBPF Programs
participant fanotify_handle_event_e
participant fanotify_handle_event_x
participant fsnotify_destroy_event
participant fsnotify_insert_event_e
participant ig_fa_pick_e
participant ig_fa_pick_x
participant inotify_handle_event_e
participant inotify_handle_event_x
participant inotify_handle_inode_event_e
participant inotify_handle_inode_event_x
end
box eBPF Maps
participant fsnotify_insert_event_ctx
participant gadget_heap
participant enriched_fsnotify_events
participant bufs
participant events
participant fsnotify_remove_first_event_ctx
end
fanotify_handle_event_e->>fsnotify_insert_event_ctx: Update
fanotify_handle_event_x->>fsnotify_insert_event_ctx: Delete
fsnotify_destroy_event->>fsnotify_insert_event_ctx: Lookup
fsnotify_destroy_event->>gadget_heap: Lookup
fsnotify_destroy_event->>enriched_fsnotify_events: Lookup
fsnotify_destroy_event->>bufs: Lookup
fsnotify_destroy_event->>events: EventOutput
fsnotify_destroy_event->>enriched_fsnotify_events: Delete
fsnotify_insert_event_e->>fsnotify_insert_event_ctx: Lookup
fsnotify_insert_event_e->>enriched_fsnotify_events: Update
fsnotify_insert_event_e->>enriched_fsnotify_events: Lookup
fsnotify_insert_event_e->>bufs: Lookup
ig_fa_pick_e->>fsnotify_remove_first_event_ctx: Update
ig_fa_pick_x->>fsnotify_remove_first_event_ctx: Lookup
ig_fa_pick_x->>gadget_heap: Lookup
ig_fa_pick_x->>enriched_fsnotify_events: Lookup
ig_fa_pick_x->>events: EventOutput
ig_fa_pick_x->>fsnotify_remove_first_event_ctx: Delete
inotify_handle_event_e->>fsnotify_insert_event_ctx: Update
inotify_handle_event_x->>fsnotify_insert_event_ctx: Delete
inotify_handle_inode_event_e->>fsnotify_insert_event_ctx: Update
inotify_handle_inode_event_x->>fsnotify_insert_event_ctx: Delete
```
