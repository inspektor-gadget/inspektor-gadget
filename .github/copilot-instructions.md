# Copilot Instructions for Inspektor Gadget

Inspektor Gadget is an eBPF-based tool and framework for data collection and system inspection on Kubernetes clusters and Linux hosts. Gadgets are eBPF programs packaged as OCI images.

## Build & Test Commands

```bash
# Build ig (standalone Linux tracer)
make ig

# Build kubectl-gadget (Kubernetes plugin)
make kubectl-gadget

# Build the gadget container image
make gadget-container

# Build eBPF object files (runs inside Docker)
make ebpf-objects

# Unit tests (requires sudo for eBPF)
make test
# Run a single test package
go test -exec sudo -v ./pkg/operators/ebpf/...
# Run a specific test
go test -exec sudo -v -run TestMyTest ./pkg/operators/ebpf/...

# Integration tests (requires a Kubernetes cluster with IG deployed)
make integration-tests
# Run a specific integration test
INTEGRATION_TESTS_PARAMS="-run TestTraceExec" make integration-tests

# Gadget-specific tests
make unit-test-gadgets
make integration-test-gadgets

# Regenerate testdata (needed when eBPF test fixtures change)
make generate-testdata

# Lint (runs in Docker using golangci-lint)
make lint

# Format eBPF C code (runs in Docker)
make clang-format
```

## Architecture

### Core Pipeline

Gadgets flow through a pipeline: **OCI Image → Operators → DataSources → Output**

- **Gadgets** (`gadgets/`) — OCI images containing eBPF C code (`program.bpf.c`), metadata (`gadget.yaml`), and optional WASM modules (`go/program.go`). Built with `ig image build`.
- **Operators** (`pkg/operators/`) — Pluggable stages that process gadget data. Two types:
  - `ImageOperator` — handles OCI media types (e.g., `ebpf/` loads eBPF programs, `wasm/` runs WASM modules)
  - `DataOperator` — transforms data in the pipeline (e.g., `filter/`, `sort/`, `formatters/`, enrichment operators like `kubemanager/`, `socketenricher/`)
  - Operators register via `RegisterOperatorForMediaType()` or `RegisterDataOperator()` in `pkg/operators/registry.go`
  - `DataOperator.Priority()` controls execution order
- **DataSources** (`pkg/datasource/`) — Typed event streams that operators produce and consume. Fields carry annotations for column display, JSON serialization, etc.
- **GadgetContext** (`pkg/gadget-context/`) — Orchestrates a gadget run: loads the OCI image, instantiates operators, wires up data sources, manages lifecycle.
- **Runtimes** (`pkg/runtime/`) — `local/` runs gadgets on the host; `grpc/` runs them remotely via gRPC.

### Three Binaries

| Binary | Entry point | Purpose |
|---|---|---|
| `ig` | `cmd/ig/` | Standalone Linux tracer (no Kubernetes) |
| `kubectl-gadget` | `cmd/kubectl-gadget/` | Kubernetes kubectl plugin |
| `gadgetctl` | `cmd/gadgetctl/` | Remote client (macOS/Windows) |

`kubectl-gadget` and `gadgetctl` are built with `-tags withoutebpf` since they don't run eBPF locally.

### Gadget Structure

Each gadget in `gadgets/` follows this layout:

```
gadgets/trace_open/
  program.bpf.c      # eBPF C source (GPL-2.0, includes <gadget/macros.h> etc.)
  gadget.yaml         # Metadata: datasources, field annotations, params
  go/program.go       # Optional WASM post-processing module (Go or Rust)
  test/               # Gadget-specific tests
  README.md           # Short description with link to full docs
  README.mdx          # Full documentation in MDX format for the website
```

- `gadget.yaml` defines datasources with field annotations (`columns.width`, `columns.hidden`, `columns.alignment`) and operator params.
- New gadgets must be added to `gadgets/Makefile` and have symlinks created in `docs/gadgets` to the `README.mdx`.

### WASM Extension API

Gadgets can include WASM modules for post-processing. The API is in `wasmapi/go/` (Go) and `wasmapi/rust/` (Rust), using `//go:wasmimport` host function bindings for datasource access, field manipulation, and event emission.

### Enrichment

Operators like `kubemanager/`, `kubenameresolver/`, `socketenricher/`, and `localmanager/` map kernel-level data (mount namespace IDs, PIDs, network namespaces) to high-level concepts (Kubernetes pods, containers, DNS names).

## Key Conventions

### Go Code

- **Module:** `github.com/inspektor-gadget/inspektor-gadget`
- **License headers:** Every Go source file must start with the Apache 2.0 copyright header with the current year: `// Copyright 2026 The Inspektor Gadget authors`
- **Error wrapping:** Always use `fmt.Errorf("context: %w", err)` — enforced by `errorlint` linter.
- **Formatting:** `gofumpt` + `goimports` with local prefix `github.com/inspektor-gadget/inspektor-gadget` (imports grouped: stdlib, external, then local). All files must end with a newline.
- **Logging:** Use the `pkg/logger.Logger` interface (`Warnf`, `Debugf`, `Infof`, etc.), not `logrus` directly in library code.
- **Testing:** Uses `github.com/stretchr/testify` (`require` and `assert`). Table-driven tests are standard. Many tests require `sudo` (`go test -exec sudo`). Test-only helpers belong in `internal/testing/` or `pkg/testing/`, not in production packages.
- **Build tags:** Use `//go:build !withoutebpf` to guard code requiring eBPF. Use `//go:build linux` for Linux-only code.

### eBPF Code

- Licensed under GPL-2.0 (separate from Go code which is Apache-2.0).
- Include gadget helpers: `<gadget/macros.h>`, `<gadget/types.h>`, `<gadget/filter.h>`, `<gadget/buffer.h>`.
- Use `<vmlinux.h>` for kernel types (BTF-based, no kernel headers needed).
- Code generation uses `bpf2go`: `//go:generate go run github.com/cilium/ebpf/cmd/bpf2go ...`
- Prefer enums over strings in eBPF structs — formatters will convert enums to human-readable strings in userspace. This saves BPF stack space and CPU cycles.
- Use `struct` not `class` for CO-RE type definitions.
- When adding CO-RE compatibility fixes, include links to the upstream kernel commits that introduced the changes.

### Gadget WASM Modules

- WASM modules in gadgets must only import `wasmapi/go/` (or the Rust equivalent). Do not import other Inspektor Gadget packages directly.
- Reuse existing field templates from `pkg/metadata/v1/annotations.go` (e.g., pid, timestamp, syscall) in `gadget.yaml` rather than redefining field annotations that already have templates.

### Commits and PRs

- All commits must be signed off (`git commit -s`) per the Developer Certificate of Origin.
- Commit titles use imperative mood prefixed with the area: `gadgets/trace_open: Fix field alignment`. Ideally 72 characters or less.
- Bug fixes should include a `Fixes:` tag with the first 12 chars of the commit hash being fixed.
- Squash fixup commits before merge. Review fixup commits must be squashed into the original commit, not left as separate commits.