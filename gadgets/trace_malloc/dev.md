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
ig_ustack[("ig_ustack")]
memptrs[("memptrs")]
sizes[("sizes")]
trace_sched_process_exit -- "Delete" --> sizes
trace_sched_process_exit -- "Delete" --> memptrs
trace_sched_process_exit["trace_sched_process_exit"]
trace_uprobe_aligned_alloc -- "Update" --> sizes
trace_uprobe_aligned_alloc["trace_uprobe_aligned_alloc"]
trace_uprobe_calloc -- "Update" --> sizes
trace_uprobe_calloc["trace_uprobe_calloc"]
trace_uprobe_free -- "Lookup" --> gadget_mntns_filter_map
trace_uprobe_free -- "Lookup" --> gadget_heap
trace_uprobe_free -- "EventOutput" --> events
trace_uprobe_free["trace_uprobe_free"]
trace_uprobe_malloc -- "Update" --> sizes
trace_uprobe_malloc["trace_uprobe_malloc"]
trace_uprobe_memalign -- "Update" --> sizes
trace_uprobe_memalign["trace_uprobe_memalign"]
trace_uprobe_mmap -- "Update" --> sizes
trace_uprobe_mmap["trace_uprobe_mmap"]
trace_uprobe_munmap -- "Lookup" --> gadget_mntns_filter_map
trace_uprobe_munmap -- "Lookup" --> gadget_heap
trace_uprobe_munmap -- "EventOutput" --> events
trace_uprobe_munmap["trace_uprobe_munmap"]
trace_uprobe_posix_memalign -- "Update" --> memptrs
trace_uprobe_posix_memalign -- "Update" --> sizes
trace_uprobe_posix_memalign["trace_uprobe_posix_memalign"]
trace_uprobe_pvalloc -- "Update" --> sizes
trace_uprobe_pvalloc["trace_uprobe_pvalloc"]
trace_uprobe_realloc -- "Lookup" --> gadget_mntns_filter_map
trace_uprobe_realloc -- "Lookup" --> gadget_heap
trace_uprobe_realloc -- "EventOutput" --> events
trace_uprobe_realloc -- "Update" --> sizes
trace_uprobe_realloc["trace_uprobe_realloc"]
trace_uprobe_valloc -- "Update" --> sizes
trace_uprobe_valloc["trace_uprobe_valloc"]
trace_uretprobe_aligned_alloc -- "Lookup" --> gadget_mntns_filter_map
trace_uretprobe_aligned_alloc -- "Lookup+Delete" --> sizes
trace_uretprobe_aligned_alloc -- "Lookup" --> gadget_heap
trace_uretprobe_aligned_alloc -- "EventOutput" --> events
trace_uretprobe_aligned_alloc["trace_uretprobe_aligned_alloc"]
trace_uretprobe_calloc -- "Lookup" --> gadget_mntns_filter_map
trace_uretprobe_calloc -- "Lookup+Delete" --> sizes
trace_uretprobe_calloc -- "Lookup" --> gadget_heap
trace_uretprobe_calloc -- "EventOutput" --> events
trace_uretprobe_calloc["trace_uretprobe_calloc"]
trace_uretprobe_malloc -- "Lookup" --> gadget_mntns_filter_map
trace_uretprobe_malloc -- "Lookup+Delete" --> sizes
trace_uretprobe_malloc -- "Lookup" --> gadget_heap
trace_uretprobe_malloc -- "EventOutput" --> events
trace_uretprobe_malloc["trace_uretprobe_malloc"]
trace_uretprobe_memalign -- "Lookup" --> gadget_mntns_filter_map
trace_uretprobe_memalign -- "Lookup+Delete" --> sizes
trace_uretprobe_memalign -- "Lookup" --> gadget_heap
trace_uretprobe_memalign -- "EventOutput" --> events
trace_uretprobe_memalign["trace_uretprobe_memalign"]
trace_uretprobe_mmap -- "Lookup" --> gadget_mntns_filter_map
trace_uretprobe_mmap -- "Lookup+Delete" --> sizes
trace_uretprobe_mmap -- "Lookup" --> gadget_heap
trace_uretprobe_mmap -- "EventOutput" --> events
trace_uretprobe_mmap["trace_uretprobe_mmap"]
trace_uretprobe_posix_memalign -- "Lookup+Delete" --> memptrs
trace_uretprobe_posix_memalign -- "Lookup" --> gadget_mntns_filter_map
trace_uretprobe_posix_memalign -- "Lookup+Delete" --> sizes
trace_uretprobe_posix_memalign -- "Lookup" --> gadget_heap
trace_uretprobe_posix_memalign -- "EventOutput" --> events
trace_uretprobe_posix_memalign["trace_uretprobe_posix_memalign"]
trace_uretprobe_pvalloc -- "Lookup" --> gadget_mntns_filter_map
trace_uretprobe_pvalloc -- "Lookup+Delete" --> sizes
trace_uretprobe_pvalloc -- "Lookup" --> gadget_heap
trace_uretprobe_pvalloc -- "EventOutput" --> events
trace_uretprobe_pvalloc["trace_uretprobe_pvalloc"]
trace_uretprobe_realloc -- "Lookup" --> gadget_mntns_filter_map
trace_uretprobe_realloc -- "Lookup+Delete" --> sizes
trace_uretprobe_realloc -- "Lookup" --> gadget_heap
trace_uretprobe_realloc -- "EventOutput" --> events
trace_uretprobe_realloc["trace_uretprobe_realloc"]
trace_uretprobe_valloc -- "Lookup" --> gadget_mntns_filter_map
trace_uretprobe_valloc -- "Lookup+Delete" --> sizes
trace_uretprobe_valloc -- "Lookup" --> gadget_heap
trace_uretprobe_valloc -- "EventOutput" --> events
trace_uretprobe_valloc["trace_uretprobe_valloc"]
```

### Sequence Diagram

```mermaid
sequenceDiagram
box eBPF Programs
participant trace_sched_process_exit
participant trace_uprobe_aligned_alloc
participant trace_uprobe_calloc
participant trace_uprobe_free
participant trace_uprobe_malloc
participant trace_uprobe_memalign
participant trace_uprobe_mmap
participant trace_uprobe_munmap
participant trace_uprobe_posix_memalign
participant trace_uprobe_pvalloc
participant trace_uprobe_realloc
participant trace_uprobe_valloc
participant trace_uretprobe_aligned_alloc
participant trace_uretprobe_calloc
participant trace_uretprobe_malloc
participant trace_uretprobe_memalign
participant trace_uretprobe_mmap
participant trace_uretprobe_posix_memalign
participant trace_uretprobe_pvalloc
participant trace_uretprobe_realloc
participant trace_uretprobe_valloc
end
box eBPF Maps
participant sizes
participant memptrs
participant gadget_mntns_filter_map
participant gadget_heap
participant events
end
trace_sched_process_exit->>sizes: Delete
trace_sched_process_exit->>memptrs: Delete
trace_uprobe_aligned_alloc->>sizes: Update
trace_uprobe_calloc->>sizes: Update
trace_uprobe_free->>gadget_mntns_filter_map: Lookup
trace_uprobe_free->>gadget_heap: Lookup
trace_uprobe_free->>events: EventOutput
trace_uprobe_malloc->>sizes: Update
trace_uprobe_memalign->>sizes: Update
trace_uprobe_mmap->>sizes: Update
trace_uprobe_munmap->>gadget_mntns_filter_map: Lookup
trace_uprobe_munmap->>gadget_heap: Lookup
trace_uprobe_munmap->>events: EventOutput
trace_uprobe_posix_memalign->>memptrs: Update
trace_uprobe_posix_memalign->>sizes: Update
trace_uprobe_pvalloc->>sizes: Update
trace_uprobe_realloc->>gadget_mntns_filter_map: Lookup
trace_uprobe_realloc->>gadget_heap: Lookup
trace_uprobe_realloc->>events: EventOutput
trace_uprobe_realloc->>sizes: Update
trace_uprobe_valloc->>sizes: Update
trace_uretprobe_aligned_alloc->>gadget_mntns_filter_map: Lookup
trace_uretprobe_aligned_alloc->>sizes: Lookup
trace_uretprobe_aligned_alloc->>sizes: Delete
trace_uretprobe_aligned_alloc->>gadget_heap: Lookup
trace_uretprobe_aligned_alloc->>events: EventOutput
trace_uretprobe_calloc->>gadget_mntns_filter_map: Lookup
trace_uretprobe_calloc->>sizes: Lookup
trace_uretprobe_calloc->>sizes: Delete
trace_uretprobe_calloc->>gadget_heap: Lookup
trace_uretprobe_calloc->>events: EventOutput
trace_uretprobe_malloc->>gadget_mntns_filter_map: Lookup
trace_uretprobe_malloc->>sizes: Lookup
trace_uretprobe_malloc->>sizes: Delete
trace_uretprobe_malloc->>gadget_heap: Lookup
trace_uretprobe_malloc->>events: EventOutput
trace_uretprobe_memalign->>gadget_mntns_filter_map: Lookup
trace_uretprobe_memalign->>sizes: Lookup
trace_uretprobe_memalign->>sizes: Delete
trace_uretprobe_memalign->>gadget_heap: Lookup
trace_uretprobe_memalign->>events: EventOutput
trace_uretprobe_mmap->>gadget_mntns_filter_map: Lookup
trace_uretprobe_mmap->>sizes: Lookup
trace_uretprobe_mmap->>sizes: Delete
trace_uretprobe_mmap->>gadget_heap: Lookup
trace_uretprobe_mmap->>events: EventOutput
trace_uretprobe_posix_memalign->>memptrs: Lookup
trace_uretprobe_posix_memalign->>memptrs: Delete
trace_uretprobe_posix_memalign->>gadget_mntns_filter_map: Lookup
trace_uretprobe_posix_memalign->>sizes: Lookup
trace_uretprobe_posix_memalign->>sizes: Delete
trace_uretprobe_posix_memalign->>gadget_heap: Lookup
trace_uretprobe_posix_memalign->>events: EventOutput
trace_uretprobe_pvalloc->>gadget_mntns_filter_map: Lookup
trace_uretprobe_pvalloc->>sizes: Lookup
trace_uretprobe_pvalloc->>sizes: Delete
trace_uretprobe_pvalloc->>gadget_heap: Lookup
trace_uretprobe_pvalloc->>events: EventOutput
trace_uretprobe_realloc->>gadget_mntns_filter_map: Lookup
trace_uretprobe_realloc->>sizes: Lookup
trace_uretprobe_realloc->>sizes: Delete
trace_uretprobe_realloc->>gadget_heap: Lookup
trace_uretprobe_realloc->>events: EventOutput
trace_uretprobe_valloc->>gadget_mntns_filter_map: Lookup
trace_uretprobe_valloc->>sizes: Lookup
trace_uretprobe_valloc->>sizes: Delete
trace_uretprobe_valloc->>gadget_heap: Lookup
trace_uretprobe_valloc->>events: EventOutput
```
