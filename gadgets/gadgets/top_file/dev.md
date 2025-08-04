# Developer Notes

This file complements the README file with implementation details specific to this gadget. It includes diagrams that illustrate how eBPF programs interact with eBPF maps. These visualizations help clarify the internal data flow and logic, making it easier to understand, maintain, and extend the gadget.

## Program-Map interactions

The following diagrams are generated using the `ig image inspect` command. Note they are a best-effort representation of the actual interactions, as they do not account for conditionals in the code that may prevent certain program–map interactions from occurring at runtime.

### Flowchart

```mermaid
flowchart LR
bufs[("bufs")]
gadget_mntns_filter_map[("gadget_mntns_filter_map")]
stats[("stats")]
ig_topfile_rd_e -- "Lookup" --> gadget_mntns_filter_map
ig_topfile_rd_e -- "Lookup+Update" --> stats
ig_topfile_rd_e -- "Lookup" --> bufs
ig_topfile_rd_e["ig_topfile_rd_e"]
ig_topfile_wr_e -- "Lookup" --> gadget_mntns_filter_map
ig_topfile_wr_e -- "Lookup+Update" --> stats
ig_topfile_wr_e -- "Lookup" --> bufs
ig_topfile_wr_e["ig_topfile_wr_e"]
```

### Sequence Diagram

```mermaid
sequenceDiagram
box eBPF Programs
participant ig_topfile_rd_e
participant ig_topfile_wr_e
end
box eBPF Maps
participant gadget_mntns_filter_map
participant stats
participant bufs
end
ig_topfile_rd_e->>gadget_mntns_filter_map: Lookup
ig_topfile_rd_e->>stats: Lookup
ig_topfile_rd_e->>stats: Update
ig_topfile_rd_e->>bufs: Lookup
ig_topfile_wr_e->>gadget_mntns_filter_map: Lookup
ig_topfile_wr_e->>stats: Lookup
ig_topfile_wr_e->>stats: Update
ig_topfile_wr_e->>bufs: Lookup
```
