# Developer Notes

This file complements the README file with implementation details specific to this gadget. It includes diagrams that illustrate how eBPF programs interact with eBPF maps. These visualizations help clarify the internal data flow and logic, making it easier to understand, maintain, and extend the gadget.

## Program-Map interactions

The following diagrams are generated using the `ig image inspect` command. Note they are a best-effort representation of the actual interactions, as they do not account for conditionals in the code that may prevent certain program–map interactions from occurring at runtime.

### Flowchart

```mermaid
flowchart LR
bufs[("bufs")]
events[("events")]
fget_raw_ctx[("fget_raw_ctx")]
gadget_heap[("gadget_heap")]
gadget_mntns_filter_map[("gadget_mntns_filter_map")]
scm_send_ctx[("scm_send_ctx")]
sendmsg_ctx[("sendmsg_ctx")]
fget_raw_e -- "Lookup" --> gadget_mntns_filter_map
fget_raw_e -- "Lookup" --> scm_send_ctx
fget_raw_e -- "Update" --> fget_raw_ctx
fget_raw_e["fget_raw_e"]
fget_raw_x -- "Lookup" --> scm_send_ctx
fget_raw_x -- "Lookup+Delete" --> fget_raw_ctx
fget_raw_x -- "Lookup" --> sendmsg_ctx
fget_raw_x -- "Lookup" --> gadget_heap
fget_raw_x -- "Lookup" --> bufs
fget_raw_x -- "EventOutput" --> events
fget_raw_x["fget_raw_x"]
scm_snd_e -- "Lookup" --> gadget_mntns_filter_map
scm_snd_e -- "Update" --> scm_send_ctx
scm_snd_e["scm_snd_e"]
scm_snd_x -- "Delete" --> scm_send_ctx
scm_snd_x["scm_snd_x"]
sendmmsg_e -- "Lookup" --> gadget_mntns_filter_map
sendmmsg_e -- "Update" --> sendmsg_ctx
sendmmsg_e["sendmmsg_e"]
sendmmsg_x -- "Delete" --> sendmsg_ctx
sendmmsg_x["sendmmsg_x"]
sendmsg_e -- "Lookup" --> gadget_mntns_filter_map
sendmsg_e -- "Update" --> sendmsg_ctx
sendmsg_e["sendmsg_e"]
sendmsg_x -- "Delete" --> sendmsg_ctx
sendmsg_x["sendmsg_x"]
```

### Sequence Diagram

```mermaid
sequenceDiagram
box eBPF Programs
participant fget_raw_e
participant fget_raw_x
participant scm_snd_e
participant scm_snd_x
participant sendmmsg_e
participant sendmmsg_x
participant sendmsg_e
participant sendmsg_x
end
box eBPF Maps
participant gadget_mntns_filter_map
participant scm_send_ctx
participant fget_raw_ctx
participant sendmsg_ctx
participant gadget_heap
participant bufs
participant events
end
fget_raw_e->>gadget_mntns_filter_map: Lookup
fget_raw_e->>scm_send_ctx: Lookup
fget_raw_e->>fget_raw_ctx: Update
fget_raw_x->>scm_send_ctx: Lookup
fget_raw_x->>fget_raw_ctx: Lookup
fget_raw_x->>sendmsg_ctx: Lookup
fget_raw_x->>gadget_heap: Lookup
fget_raw_x->>bufs: Lookup
fget_raw_x->>events: EventOutput
fget_raw_x->>fget_raw_ctx: Delete
scm_snd_e->>gadget_mntns_filter_map: Lookup
scm_snd_e->>scm_send_ctx: Update
scm_snd_x->>scm_send_ctx: Delete
sendmmsg_e->>gadget_mntns_filter_map: Lookup
sendmmsg_e->>sendmsg_ctx: Update
sendmmsg_x->>sendmsg_ctx: Delete
sendmsg_e->>gadget_mntns_filter_map: Lookup
sendmsg_e->>sendmsg_ctx: Update
sendmsg_x->>sendmsg_ctx: Delete
```
