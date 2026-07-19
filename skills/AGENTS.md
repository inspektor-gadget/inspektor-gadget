# Inspektor Gadget troubleshooting skills

This directory bundles **agent skills** that teach an AI assistant to debug
systems at the kernel level with **Inspektor Gadget (IG)** — eBPF-based tracing
that ties every kernel event (syscalls, packets, DNS, capability checks, OOM
kills) back to the workload that caused it.

## How to choose a skill (dynamic)

**Enumerate, don't hardcode.** This directory is an *open set* — a gadget may add
its own skill here without editing this file. To pick a skill:

1. **List** every `*/SKILL.md` under this directory (including any skill installed
   out-of-tree by the agent framework). Do **not** assume the set is fixed.
2. **Read each skill's `description`** (its YAML frontmatter). Choose the skill
   whose description best matches the user's symptom / target.
3. The base skills below are **always present**; gadget-specific skills are
   present **only when their gadget is installed** (see the next section).

### Base skills (always present)

| Use this skill | When the target is | Launcher |
|---|---|---|
| **`kubernetes-troubleshooting`** | a **Kubernetes** pod / Service / workload (cluster-wide, k8s-enriched) | `kubectl gadget run <gadget>:latest` |
| **`linux-troubleshooting`** | a **single Linux host / VM / container runtime** (no cluster) | `sudo ig run <gadget>:latest` |

Both expose the **same gadgets, flags, and fields** — they differ only in the
launcher and the enrichment metadata (`k8s.*` vs `runtime.*`). Each skill's
`references/*-companion.md` explains when to hop to the other.

### Gadget-specific skills (present only when their gadget is installed)

A third-party or add-on gadget may **ship its own skill** alongside its OCI image
(for example, an add-on gadget may ship a companion debug skill). Such a
skill is discovered exactly like the base skills — by its `SKILL.md`
`description` — but before routing to one you **must confirm the gadget is
actually available** (*discover, don't guess*):

    sudo ig image list --no-trunc | grep <gadget>   # is the gadget present locally?
    # or: the gadget is exposed as an ig-mcp-server tool

- **Gadget present** → route to its skill for that gadget's specific capability,
  and use a base skill for the general IG workflow. They are complementary.
- **Gadget absent** → do **not** route to its skill; fall back to a base skill.

This keeps behavior **identical to the two-skill baseline** whenever no add-on is
installed, and lets any future gadget become routable with **zero edits** to this
file.

## The shared mental model

1. **Route** the symptom to a domain (networking / security / process-lifecycle /
   storage-fs / performance) and a candidate gadget (each skill's SKILL.md has a
   symptom→gadget shortlist; `references/gadget-catalog.md` has the full grouped
   list).
2. **Discover, don't guess** — read the gadget's real flags and fields at run
   time with `<gadget>:latest --help` and inspect a shape-aware JSON sample.
   Never hardcode a field name from memory; gadget images evolve and new gadgets
   ship. This limits interface drift, while the routing catalog still needs
   periodic updates.
3. **Run bounded** — always scope (`-n`/`-p`/`-c`/`--host`) and time-box
   (`--timeout`, `--max-entries`) so a trace can't flood context or the cluster.
4. **Read the columns** — inspect the enriched fields to confirm/refute a
   hypothesis, then narrow and repeat until root cause.

## Progressive disclosure

Keep the entry point small and load depth on demand:

- **SKILL.md** — the always-loaded router: what the skill is for, the 4-step
  loop, the symptom→gadget shortlist, and pointers. Deliberately thin.
- **references/** — loaded only when the task needs it: the full gadget catalog,
  per-domain playbooks (with disambiguation reasoning + verified flags), the
  discover-don't-guess mechanics, common flags, setup, and companion routing.

A gadget-specific skill follows the same layout: a thin `SKILL.md` router backed
by `references/` (and optionally `scripts/`, `assets/`, `evals/`) loaded on
demand.

This mirrors the way IG itself treats each gadget as the single source of truth
for its own interface: the skill teaches the agent to *ask the gadget*, so the
docs stay small and never drift.

Read a skill's own `SKILL.md` first; open a `references/*.md` only when you're
working that domain.
