# Developer Notes

This file complements the README file with implementation details specific to this gadget. It includes diagrams that illustrate how eBPF programs interact with eBPF maps. These visualizations help clarify the internal data flow and logic, making it easier to understand, maintain, and extend the gadget.

## Program-Map interactions

The following diagrams are generated using the `ig image inspect` command. Note they are a best-effort representation of the actual interactions, as they do not account for conditionals in the code that may prevent certain program–map interactions from occurring at runtime.

### Flowchart

```mermaid
flowchart LR
hists[("hists")]
start[("start")]
consume_skb -- "Lookup+Delete" --> start
consume_skb -- "Lookup+Update" --> hists
consume_skb["consume_skb"]
kfree_skb -- "Lookup+Delete" --> start
kfree_skb -- "Lookup+Update" --> hists
kfree_skb["kfree_skb"]
qdisc_dequeue -- "Lookup+Delete" --> start
qdisc_dequeue -- "Lookup+Update" --> hists
qdisc_dequeue["qdisc_dequeue"]
qdisc_enqueue -- "Update" --> start
qdisc_enqueue["qdisc_enqueue"]
```

### Sequence Diagram

```mermaid
sequenceDiagram
box eBPF Programs
participant consume_skb
participant kfree_skb
participant qdisc_dequeue
participant qdisc_enqueue
end
box eBPF Maps
participant start
participant hists
end
consume_skb->>start: Lookup
consume_skb->>hists: Lookup
consume_skb->>hists: Update
consume_skb->>start: Delete
kfree_skb->>start: Lookup
kfree_skb->>hists: Lookup
kfree_skb->>hists: Update
kfree_skb->>start: Delete
qdisc_dequeue->>start: Lookup
qdisc_dequeue->>hists: Lookup
qdisc_dequeue->>hists: Update
qdisc_dequeue->>start: Delete
qdisc_enqueue->>start: Update
```
