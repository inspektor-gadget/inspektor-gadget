# Developer Notes

This file complements the README file with implementation details specific to this gadget. It includes diagrams that illustrate how eBPF programs interact with eBPF maps. These visualizations help clarify the internal data flow and logic, making it easier to understand, maintain, and extend the gadget.

## Program-Map interactions

The following diagrams are generated using the `ig image inspect` command. Note they are a best-effort representation of the actual interactions, as they do not account for conditionals in the code that may prevent certain program–map interactions from occurring at runtime.

### Flowchart

```mermaid
flowchart LR
bufs[("bufs")]
events[("events")]
execs[("execs")]
gadget_mntns_filter_map[("gadget_mntns_filter_map")]
security_bprm_hit_map[("security_bprm_hit_map")]
ig_execve_e -- "Lookup" --> gadget_mntns_filter_map
ig_execve_e -- "Lookup+Update" --> execs
ig_execve_e -- "Lookup" --> bufs
ig_execve_e["ig_execve_e"]
ig_execve_x -- "Lookup+Delete" --> execs
ig_execve_x -- "Lookup" --> bufs
ig_execve_x -- "EventOutput" --> events
ig_execve_x -- "Delete" --> security_bprm_hit_map
ig_execve_x["ig_execve_x"]
ig_execveat_e -- "Lookup" --> gadget_mntns_filter_map
ig_execveat_e -- "Lookup+Update" --> execs
ig_execveat_e -- "Lookup" --> bufs
ig_execveat_e["ig_execveat_e"]
ig_execveat_x -- "Lookup+Delete" --> execs
ig_execveat_x -- "Lookup" --> bufs
ig_execveat_x -- "EventOutput" --> events
ig_execveat_x -- "Delete" --> security_bprm_hit_map
ig_execveat_x["ig_execveat_x"]
ig_sched_exec -- "Lookup+Delete" --> execs
ig_sched_exec -- "Lookup" --> bufs
ig_sched_exec -- "EventOutput" --> events
ig_sched_exec -- "Delete" --> security_bprm_hit_map
ig_sched_exec["ig_sched_exec"]
security_bprm_check -- "Lookup" --> execs
security_bprm_check -- "Lookup+Update" --> security_bprm_hit_map
security_bprm_check -- "Lookup" --> bufs
security_bprm_check["security_bprm_check"]
```

### Sequence Diagram

```mermaid
sequenceDiagram
box eBPF Programs
participant ig_execve_e
participant ig_execve_x
participant ig_execveat_e
participant ig_execveat_x
participant ig_sched_exec
participant security_bprm_check
end
box eBPF Maps
participant gadget_mntns_filter_map
participant execs
participant bufs
participant events
participant security_bprm_hit_map
end
ig_execve_e->>gadget_mntns_filter_map: Lookup
ig_execve_e->>execs: Update
ig_execve_e->>execs: Lookup
ig_execve_e->>bufs: Lookup
ig_execve_x->>execs: Lookup
ig_execve_x->>bufs: Lookup
ig_execve_x->>events: EventOutput
ig_execve_x->>execs: Delete
ig_execve_x->>security_bprm_hit_map: Delete
ig_execveat_e->>gadget_mntns_filter_map: Lookup
ig_execveat_e->>execs: Update
ig_execveat_e->>execs: Lookup
ig_execveat_e->>bufs: Lookup
ig_execveat_x->>execs: Lookup
ig_execveat_x->>bufs: Lookup
ig_execveat_x->>events: EventOutput
ig_execveat_x->>execs: Delete
ig_execveat_x->>security_bprm_hit_map: Delete
ig_sched_exec->>execs: Lookup
ig_sched_exec->>bufs: Lookup
ig_sched_exec->>events: EventOutput
ig_sched_exec->>execs: Delete
ig_sched_exec->>security_bprm_hit_map: Delete
security_bprm_check->>execs: Lookup
security_bprm_check->>security_bprm_hit_map: Lookup
security_bprm_check->>security_bprm_hit_map: Update
security_bprm_check->>bufs: Lookup
```
