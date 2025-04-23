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
tcp_tid_fd[("tcp_tid_fd")]
tcp_tid_sock[("tcp_tid_sock")]
tuplepid[("tuplepid")]
ig_tcp_accept -- "Lookup" --> gadget_mntns_filter_map
ig_tcp_accept -- "Update" --> tcp_tid_sock
ig_tcp_accept["ig_tcp_accept"]
ig_tcp_close -- "Lookup" --> gadget_mntns_filter_map
ig_tcp_close -- "Lookup" --> gadget_heap
ig_tcp_close -- "EventOutput" --> events
ig_tcp_close["ig_tcp_close"]
ig_tcp_state -- "Lookup+Delete" --> tuplepid
ig_tcp_state -- "Lookup" --> gadget_heap
ig_tcp_state -- "EventOutput" --> events
ig_tcp_state["ig_tcp_state"]
ig_tcp_v4_co_e -- "Lookup" --> gadget_mntns_filter_map
ig_tcp_v4_co_e -- "Update" --> tcp_tid_sock
ig_tcp_v4_co_e["ig_tcp_v4_co_e"]
ig_tcp_v4_co_x -- "Lookup" --> tcp_tid_sock
ig_tcp_v4_co_x -- "Lookup" --> tcp_tid_fd
ig_tcp_v4_co_x -- "Update" --> tuplepid
ig_tcp_v4_co_x["ig_tcp_v4_co_x"]
ig_tcp_v6_co_e -- "Lookup" --> gadget_mntns_filter_map
ig_tcp_v6_co_e -- "Update" --> tcp_tid_sock
ig_tcp_v6_co_e["ig_tcp_v6_co_e"]
ig_tcp_v6_co_x -- "Lookup" --> tcp_tid_sock
ig_tcp_v6_co_x -- "Lookup" --> tcp_tid_fd
ig_tcp_v6_co_x -- "Update" --> tuplepid
ig_tcp_v6_co_x["ig_tcp_v6_co_x"]
sys_accept4_e -- "Update" --> tcp_tid_fd
sys_accept4_e["sys_accept4_e"]
sys_accept4_x -- "Lookup+Delete" --> tcp_tid_fd
sys_accept4_x -- "Lookup+Delete" --> tcp_tid_sock
sys_accept4_x -- "Lookup" --> gadget_heap
sys_accept4_x -- "EventOutput" --> events
sys_accept4_x["sys_accept4_x"]
sys_accept_e -- "Update" --> tcp_tid_fd
sys_accept_e["sys_accept_e"]
sys_accept_x -- "Lookup+Delete" --> tcp_tid_fd
sys_accept_x -- "Lookup+Delete" --> tcp_tid_sock
sys_accept_x -- "Lookup" --> gadget_heap
sys_accept_x -- "EventOutput" --> events
sys_accept_x["sys_accept_x"]
sys_connect_e -- "Update" --> tcp_tid_fd
sys_connect_e["sys_connect_e"]
sys_connect_x -- "Delete" --> tcp_tid_sock
sys_connect_x -- "Delete" --> tcp_tid_fd
sys_connect_x["sys_connect_x"]
```

### Sequence Diagram

```mermaid
sequenceDiagram
box eBPF Programs
participant ig_tcp_accept
participant ig_tcp_close
participant ig_tcp_state
participant ig_tcp_v4_co_e
participant ig_tcp_v4_co_x
participant ig_tcp_v6_co_e
participant ig_tcp_v6_co_x
participant sys_accept4_e
participant sys_accept4_x
participant sys_accept_e
participant sys_accept_x
participant sys_connect_e
participant sys_connect_x
end
box eBPF Maps
participant gadget_mntns_filter_map
participant tcp_tid_sock
participant gadget_heap
participant events
participant tuplepid
participant tcp_tid_fd
end
ig_tcp_accept->>gadget_mntns_filter_map: Lookup
ig_tcp_accept->>tcp_tid_sock: Update
ig_tcp_close->>gadget_mntns_filter_map: Lookup
ig_tcp_close->>gadget_heap: Lookup
ig_tcp_close->>events: EventOutput
ig_tcp_state->>tuplepid: Lookup
ig_tcp_state->>gadget_heap: Lookup
ig_tcp_state->>events: EventOutput
ig_tcp_state->>tuplepid: Delete
ig_tcp_v4_co_e->>gadget_mntns_filter_map: Lookup
ig_tcp_v4_co_e->>tcp_tid_sock: Update
ig_tcp_v4_co_x->>tcp_tid_sock: Lookup
ig_tcp_v4_co_x->>tcp_tid_fd: Lookup
ig_tcp_v4_co_x->>tuplepid: Update
ig_tcp_v6_co_e->>gadget_mntns_filter_map: Lookup
ig_tcp_v6_co_e->>tcp_tid_sock: Update
ig_tcp_v6_co_x->>tcp_tid_sock: Lookup
ig_tcp_v6_co_x->>tcp_tid_fd: Lookup
ig_tcp_v6_co_x->>tuplepid: Update
sys_accept4_e->>tcp_tid_fd: Update
sys_accept4_x->>tcp_tid_fd: Lookup
sys_accept4_x->>tcp_tid_fd: Delete
sys_accept4_x->>tcp_tid_sock: Lookup
sys_accept4_x->>gadget_heap: Lookup
sys_accept4_x->>events: EventOutput
sys_accept4_x->>tcp_tid_sock: Delete
sys_accept_e->>tcp_tid_fd: Update
sys_accept_x->>tcp_tid_fd: Lookup
sys_accept_x->>tcp_tid_fd: Delete
sys_accept_x->>tcp_tid_sock: Lookup
sys_accept_x->>gadget_heap: Lookup
sys_accept_x->>events: EventOutput
sys_accept_x->>tcp_tid_sock: Delete
sys_connect_e->>tcp_tid_fd: Update
sys_connect_x->>tcp_tid_sock: Delete
sys_connect_x->>tcp_tid_fd: Delete
```
