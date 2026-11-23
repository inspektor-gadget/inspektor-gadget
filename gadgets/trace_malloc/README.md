# trace malloc

use uprobe to trace malloc and free in libc.so

## Hook points
This gadget instruments libc memory to trace allocation and deallocation events, along with the user stack and process info for each event.

| Hook point | Used for |
|---|---|
| `tracepoint/sched/sched_process_exit` | Cleans up per-thread allocation state when a thread is killed or exits. |
| `uprobe/libc:malloc` | Tracks malloc entry and stores the requested size. |
| `uretprobe/libc:malloc` | Emits the malloc event with the returned pointer and size. |
| `uprobe/libc:free` | Emits a free event for a pointer being released. |
| `uprobe/libc:calloc` | Tracks calloc entry and stores `nmemb * size`. |
| `uretprobe/libc:calloc` | Emits the calloc event with the returned pointer and size. |
| `uprobe/libc:realloc` | Records the old pointer as a free-like event and stores the new requested size. |
| `uretprobe/libc:realloc` | Emits the realloc event with the new pointer and size. |
| `uprobe/libc:mmap` | Tracks mmap allocation entry and stores the requested size. |
| `uretprobe/libc:mmap` | Emits the mmap event with the returned mapped address and size. |
| `uprobe/libc:munmap` | Emits an unmap/free event for a mapped region. |
| `uprobe/libc:posix_memalign` | Stores the output pointer location and requested size. |
| `uretprobe/libc:posix_memalign` | Reads the pointer written by posix_memalign and emits the event. |
| `uprobe/libc:aligned_alloc` | Tracks aligned_alloc entry and stores the requested size. |
| `uretprobe/libc:aligned_alloc` | Emits the aligned_alloc event with the returned pointer and size. |
| `uprobe/libc:valloc` | Tracks valloc entry and stores the requested size. |
| `uretprobe/libc:valloc` | Emits the valloc event with the returned pointer and size. |
| `uprobe/libc:memalign` | Tracks memalign entry and stores the requested size. |
| `uretprobe/libc:memalign` | Emits the memalign event with the returned pointer and size. |
| `uprobe/libc:pvalloc` | Tracks pvalloc entry and stores the requested size. |
| `uretprobe/libc:pvalloc` | Emits the pvalloc event with the returned pointer and size. |

Check the full documentation on https://inspektor-gadget.io/docs/latest/gadgets/trace_malloc
