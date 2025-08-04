# Developer Notes

This file complements the README file with implementation details specific to this gadget. It includes diagrams that illustrate how eBPF programs interact with eBPF maps. These visualizations help clarify the internal data flow and logic, making it easier to understand, maintain, and extend the gadget.

## Program-Map interactions

The following diagrams are generated using the `ig image inspect` command. Note they are a best-effort representation of the actual interactions, as they do not account for conditionals in the code that may prevent certain program–map interactions from occurring at runtime.

### Flowchart

```mermaid
flowchart LR
cgroup_map[("cgroup_map")]
hists[("hists")]
start[("start")]
ig_profio_done -- "Lookup+Delete" --> start
ig_profio_done -- "Lookup+Update" --> hists
ig_profio_done["ig_profio_done"]
ig_profio_ins -- "Update" --> start
ig_profio_ins["ig_profio_ins"]
ig_profio_iss -- "Update" --> start
ig_profio_iss["ig_profio_iss"]
```

### Sequence Diagram

```mermaid
sequenceDiagram
box eBPF Programs
participant ig_profio_done
participant ig_profio_ins
participant ig_profio_iss
end
box eBPF Maps
participant start
participant hists
end
ig_profio_done->>start: Lookup
ig_profio_done->>hists: Lookup
ig_profio_done->>hists: Update
ig_profio_done->>start: Delete
ig_profio_ins->>start: Update
ig_profio_iss->>start: Update
```
