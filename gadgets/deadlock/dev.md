# Developer Notes

This file complements the README file with implementation details specific to this gadget. It includes diagrams that illustrate how eBPF programs interact with eBPF maps. These visualizations help clarify the internal data flow and logic, making it easier to understand, maintain, and extend the gadget.

## Program-Map interactions

The following diagrams are generated using the `ig image inspect` command. Note they are a best-effort representation of the actual interactions, as they do not account for conditionals in the code that may prevent certain program–map interactions from occurring at runtime.

### Flowchart

```mermaid
flowchart LR
dead_pids[("dead_pids")]
edges[("edges")]
gadget_heap[("gadget_heap")]
gadget_mntns_filter_map[("gadget_mntns_filter_map")]
stackmap[("stackmap")]
thread_to_held_mutexes[("thread_to_held_mutexes")]
trace_sched_process_exit -- "Lookup" --> gadget_mntns_filter_map
trace_sched_process_exit -- "Delete" --> thread_to_held_mutexes
trace_sched_process_exit -- "Lookup" --> gadget_heap
trace_sched_process_exit -- "EventOutput" --> dead_pids
trace_sched_process_exit["trace_sched_process_exit"]
trace_uprobe_mutex_lock -- "Lookup" --> gadget_mntns_filter_map
trace_uprobe_mutex_lock -- "Lookup+Update" --> thread_to_held_mutexes
trace_uprobe_mutex_lock -- "Update" --> edges
trace_uprobe_mutex_lock["trace_uprobe_mutex_lock"]
trace_uprobe_mutex_unlock -- "Lookup" --> gadget_mntns_filter_map
trace_uprobe_mutex_unlock -- "Lookup+Delete" --> thread_to_held_mutexes
trace_uprobe_mutex_unlock["trace_uprobe_mutex_unlock"]
```

### Sequence Diagram

```mermaid
sequenceDiagram
box eBPF Programs
participant trace_sched_process_exit
participant trace_uprobe_mutex_lock
participant trace_uprobe_mutex_unlock
end
box eBPF Maps
participant gadget_mntns_filter_map
participant thread_to_held_mutexes
participant gadget_heap
participant dead_pids
participant edges
end
trace_sched_process_exit->>gadget_mntns_filter_map: Lookup
trace_sched_process_exit->>thread_to_held_mutexes: Delete
trace_sched_process_exit->>gadget_heap: Lookup
trace_sched_process_exit->>dead_pids: EventOutput
trace_uprobe_mutex_lock->>gadget_mntns_filter_map: Lookup
trace_uprobe_mutex_lock->>thread_to_held_mutexes: Lookup
trace_uprobe_mutex_lock->>thread_to_held_mutexes: Update
trace_uprobe_mutex_lock->>edges: Update
trace_uprobe_mutex_unlock->>gadget_mntns_filter_map: Lookup
trace_uprobe_mutex_unlock->>thread_to_held_mutexes: Lookup
trace_uprobe_mutex_unlock->>thread_to_held_mutexes: Delete
```
