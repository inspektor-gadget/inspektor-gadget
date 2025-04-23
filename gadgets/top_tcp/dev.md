# Developer Notes

This file complements the README file with implementation details specific to this gadget. It includes diagrams that illustrate how eBPF programs interact with eBPF maps. These visualizations help clarify the internal data flow and logic, making it easier to understand, maintain, and extend the gadget.

## Program-Map interactions

The following diagrams are generated using the `ig image inspect` command. Note they are a best-effort representation of the actual interactions, as they do not account for conditionals in the code that may prevent certain program–map interactions from occurring at runtime.

### Flowchart

```mermaid
flowchart LR
gadget_mntns_filter_map[("gadget_mntns_filter_map")]
ip_map[("ip_map")]
ig_toptcp_clean -- "Lookup" --> gadget_mntns_filter_map
ig_toptcp_clean -- "Lookup+Update" --> ip_map
ig_toptcp_clean["ig_toptcp_clean"]
ig_toptcp_sdmsg -- "Lookup" --> gadget_mntns_filter_map
ig_toptcp_sdmsg -- "Lookup+Update" --> ip_map
ig_toptcp_sdmsg["ig_toptcp_sdmsg"]
```

### Sequence Diagram

```mermaid
sequenceDiagram
box eBPF Programs
participant ig_toptcp_clean
participant ig_toptcp_sdmsg
end
box eBPF Maps
participant gadget_mntns_filter_map
participant ip_map
end
ig_toptcp_clean->>gadget_mntns_filter_map: Lookup
ig_toptcp_clean->>ip_map: Lookup
ig_toptcp_clean->>ip_map: Update
ig_toptcp_sdmsg->>gadget_mntns_filter_map: Lookup
ig_toptcp_sdmsg->>ip_map: Lookup
ig_toptcp_sdmsg->>ip_map: Update
```
