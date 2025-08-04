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
ports[("ports")]
sockets[("sockets")]
ig_bind_ipv4_e -- "Lookup" --> gadget_mntns_filter_map
ig_bind_ipv4_e -- "Update" --> sockets
ig_bind_ipv4_e["ig_bind_ipv4_e"]
ig_bind_ipv4_x -- "Lookup+Delete" --> sockets
ig_bind_ipv4_x -- "Lookup" --> ports
ig_bind_ipv4_x -- "Lookup" --> gadget_heap
ig_bind_ipv4_x -- "EventOutput" --> events
ig_bind_ipv4_x["ig_bind_ipv4_x"]
ig_bind_ipv6_e -- "Lookup" --> gadget_mntns_filter_map
ig_bind_ipv6_e -- "Update" --> sockets
ig_bind_ipv6_e["ig_bind_ipv6_e"]
ig_bind_ipv6_x -- "Lookup+Delete" --> sockets
ig_bind_ipv6_x -- "Lookup" --> ports
ig_bind_ipv6_x -- "Lookup" --> gadget_heap
ig_bind_ipv6_x -- "EventOutput" --> events
ig_bind_ipv6_x["ig_bind_ipv6_x"]
```

### Sequence Diagram

```mermaid
sequenceDiagram
box eBPF Programs
participant ig_bind_ipv4_e
participant ig_bind_ipv4_x
participant ig_bind_ipv6_e
participant ig_bind_ipv6_x
end
box eBPF Maps
participant gadget_mntns_filter_map
participant sockets
participant ports
participant gadget_heap
participant events
end
ig_bind_ipv4_e->>gadget_mntns_filter_map: Lookup
ig_bind_ipv4_e->>sockets: Update
ig_bind_ipv4_x->>sockets: Lookup
ig_bind_ipv4_x->>ports: Lookup
ig_bind_ipv4_x->>gadget_heap: Lookup
ig_bind_ipv4_x->>events: EventOutput
ig_bind_ipv4_x->>sockets: Delete
ig_bind_ipv6_e->>gadget_mntns_filter_map: Lookup
ig_bind_ipv6_e->>sockets: Update
ig_bind_ipv6_x->>sockets: Lookup
ig_bind_ipv6_x->>ports: Lookup
ig_bind_ipv6_x->>gadget_heap: Lookup
ig_bind_ipv6_x->>events: EventOutput
ig_bind_ipv6_x->>sockets: Delete
```
