# Install — the standalone `ig` binary (no Kubernetes)

`ig` is a single static binary that runs the Inspektor Gadget gadgets against the
local host and its container runtime. Confirm current commands with `ig --help`.

## 0. Detect — is `ig` already usable?

Run these first; only continue with section 1 if `ig` is missing.

```bash
command -v ig >/dev/null 2>&1 && ig version || echo "ig: MISSING (do section 1)"
test -f /sys/kernel/btf/vmlinux && echo "BTF: present" || echo "BTF: MISSING (CO-RE needs it — see section 2)"
```

- `ig` **present** and prints a version → ready; run it with `sudo` (see section 2).
- `ig` **missing** → do section 1. **Ask the operator before installing on a host
  you don't own.**

## 1. Install `ig`

Download the release binary for your arch from the upstream releases and put it
on `PATH`:

```bash
# example shape — use the current upstream release asset for your arch
IG_VERSION=$(curl -s https://api.github.com/repos/inspektor-gadget/inspektor-gadget/releases/latest | jq -r .tag_name)
curl -sL -o /tmp/ig.tar.gz \
  "https://github.com/inspektor-gadget/inspektor-gadget/releases/download/${IG_VERSION}/ig-linux-amd64-${IG_VERSION}.tar.gz"
sudo tar -C /usr/local/bin -xzf /tmp/ig.tar.gz ig
ig version
```

(A container image `ghcr.io/inspektor-gadget/ig` is also published if you prefer
to run it as a privileged container.)

## 2. Requirements

- **Root / privileges** — run with `sudo` (or grant CAP_BPF + CAP_SYS_ADMIN).
  Loading eBPF fails otherwise.
- **Kernel with BTF** — verify `/sys/kernel/btf/vmlinux` exists. IG uses CO-RE
  and needs BTF to relocate against the running kernel.
- **A container runtime (optional)** — to enrich events with container names,
  `ig` auto-detects containerd / Docker / CRI-O / podman. Use `--runtimes` to
  select, or `--host` to trace bare-host processes with no runtime.

## 3. Sanity check

```bash
sudo ig run trace_exec:latest --host --timeout 5 -o json   # should stream a few exec events
```

If it errors on privileges, re-run with `sudo`. For an image-signature error,
inspect the exact image reference and signer; do not disable verification to
bypass an unexplained failure. If it errors on BTF, your kernel lacks
`/sys/kernel/btf/vmlinux`.

## 4. Optional: daemon mode

For many repeated runs, start a local daemon and connect a client:

```bash
sudo ig daemon &            # exposes a local socket
ig run trace_dns:latest --timeout 5 -o json
```

One-shot `sudo ig run …` is perfectly fine for ad-hoc troubleshooting.
