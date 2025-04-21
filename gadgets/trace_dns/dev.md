# Developer Notes

This file complements the README file with implementation details specific to this gadget. It includes diagrams that illustrate how eBPF programs interact with eBPF maps. These visualizations help clarify the internal data flow and logic, making it easier to understand, maintain, and extend the gadget.

## Program-Map interactions

The following diagrams are generated using the `ig image inspect` command. Note they are a best-effort representation of the actual interactions, as they do not account for conditionals in the code that may prevent certain program–map interactions from occurring at runtime.

### Flowchart

```mermaid
flowchart LR
events[("events")]
gadget_mntns_filter_map[("gadget_mntns_filter_map")]
gadget_sockets[("gadget_sockets")]
query_map[("query_map")]
tmp_events[("tmp_events")]
ig_trace_dns -- "Lookup" --> tmp_events
ig_trace_dns -- "Lookup" --> gadget_sockets
ig_trace_dns -- "Lookup" --> gadget_mntns_filter_map
ig_trace_dns -- "Lookup+Update+Delete" --> query_map
ig_trace_dns -- "EventOutput" --> events
ig_trace_dns["ig_trace_dns"]
```

### Sequence Diagram

```mermaid
sequenceDiagram
box eBPF Programs
participant ig_trace_dns
end
box eBPF Maps
participant tmp_events
participant gadget_sockets
participant gadget_mntns_filter_map
participant query_map
participant events
end
ig_trace_dns->>tmp_events: Lookup
ig_trace_dns->>gadget_sockets: Lookup
ig_trace_dns->>gadget_mntns_filter_map: Lookup
ig_trace_dns->>query_map: Update
ig_trace_dns->>query_map: Lookup
ig_trace_dns->>query_map: Delete
ig_trace_dns->>events: EventOutput
```
