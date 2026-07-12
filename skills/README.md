# Inspektor Gadget agent skills

Two **progressive-disclosure agent skills** that teach an AI assistant to
troubleshoot systems at the kernel level with [Inspektor
Gadget](https://inspektor-gadget.io) (IG). IG runs eBPF programs to trace live
kernel events — syscalls, network packets, DNS, capability checks, OOM kills —
and enriches each event with the workload identity (Kubernetes
namespace/pod/container/node, or container runtime name) that produced it.

## Contents

```
skills/
├── AGENTS.md                       # router: which skill, the shared mental model
├── README.md                       # this file
├── kubernetes-troubleshooting/     # cluster debugging via `kubectl gadget run`
│   ├── SKILL.md                    # thin entry point (router + 4-step loop + shortlist)
│   └── references/                 # loaded on demand
│       ├── gadget-catalog.md       # all upstream gadgets grouped by domain
│       ├── discovering-params-and-fields.md   # the golden discover-don't-guess rule
│       ├── common-flags.md         # scope / output / timeout flags + gotchas
│       ├── domain-networking.md    # DNS / TCP / drops / retransmits / TLS-SNI / policy
│       ├── domain-security.md      # capabilities / LSM / seccomp / module loading
│       ├── domain-process-lifecycle.md   # exec / signals / OOM / snapshots / traceloop
│       ├── domain-storage-fs.md    # open / slow FS / block I/O / mounts / fd / notify
│       ├── domain-performance.md   # CPU / throttle / RTT / deadlock / malloc / GPU
│       ├── install.md              # detect IG, then install plugin / deploy DaemonSet
│       └── linux-companion.md      # when to switch to standalone `ig`
└── linux-troubleshooting/          # single-host debugging via `sudo ig run`
    ├── SKILL.md
    └── references/
        ├── gadget-catalog.md
        ├── discovering-params-and-fields.md
        ├── common-flags.md
        ├── install.md
        └── kubernetes-companion.md
```

## Design principles

- **Progressive disclosure.** A thin, always-loaded `SKILL.md` routes; deep
  material lives in `references/` and is opened only when a task needs it. This
  keeps the working context small and on-topic.
- **Action-oriented routing descriptions.** Each skill's frontmatter
  `description` is written around the *symptoms a user reports* ("DNS failing",
  "CrashLoopBackOff", "permission denied") so the agent selects the right skill
  from the trigger, and states what it is **not** for (logs, dashboards, cluster
  edits) to prevent mis-fire.
- **Discover, don't guess.** The skills teach the agent to enumerate a gadget's
  real flags and fields at run time (`<gadget>:latest --help`, `-o json | jq
  keys`) rather than hardcoding them. This is what makes the skills correct
  against **any future upstream gadget** without edits.
- **Bounded runs.** Every streaming example is scoped and time-boxed
  (`--timeout`, `--max-entries`) to avoid flooding the agent's context or the
  API server.
- **Two skills, one model.** The k8s and host skills share gadgets/flags/fields
  and cross-link via companion references, so the agent can route between
  cluster and single-host targets without relearning.

## Installing

These are plain Markdown skills — no build step, no runtime dependencies. Drop
the `skills/` tree wherever your agent framework loads skills from:

| Framework | Location |
|---|---|
| Skill-aware AI coding assistants | your project or user skills directory (each skill = a folder with `SKILL.md`) |
| GitHub Copilot | your repo's agent-skills location per the Copilot skills convention |
| Generic / MCP-based agents | point the agent's skill loader at this `skills/` directory |

The agent reads `AGENTS.md` (or a skill's `SKILL.md`) to route, then pulls a
`references/*.md` on demand. No secrets, no network calls, no scripts — the
skills only instruct the agent to run standard upstream `kubectl gadget` / `ig`
commands directly.

## Requirements (at run time, on the target)

- **Kubernetes skill:** the `kubectl gadget` plugin locally + the IG DaemonSet
  deployed (`kubectl gadget deploy`). See
  `kubernetes-troubleshooting/references/install.md`.
- **Linux skill:** the `ig` binary + root (CAP_BPF/CAP_SYS_ADMIN) + a kernel with
  BTF (`/sys/kernel/btf/vmlinux`). See `linux-troubleshooting/references/install.md`.

## Scope & safety

All gadgets referenced are **read-only** observers — they trace, they never
modify a workload or host. The skills are **upstream-generic**: they name only
gadgets from the public Inspektor Gadget catalog and teach a discovery-first
method that adapts to new gadgets automatically.

## License

Apache-2.0, matching the Inspektor Gadget project.
