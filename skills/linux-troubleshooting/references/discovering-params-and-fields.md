# Discovering params and fields — the golden rule (`ig` variant)

**Never hardcode a gadget's flags or fields from memory. Ask the gadget.**
Gadget images are versioned OCI artifacts; flags and fields change between
releases and new gadgets ship. The gadget's own `--help` output is the contract,
so a skill built on discovery never drifts.

## 1. List flags + every field, for any gadget

```bash
sudo ig run <gadget>:latest --help
```

The help output ends with a **`--fields`** block enumerating every *data source*
and every *field* the gadget can emit, each with a short description. This is the
authoritative field list for the image you actually pulled.

## 2. Confirm field names from a real sample

```bash
sudo ig run <gadget>:latest --timeout 5 -o json \
  | jq -s '(.[0] // {}) | if type == "array" then (.[0] // {}) else . end | keys'
```

Streaming datasources emit one JSON object per line; snapshot/top datasources emit
JSON arrays. `jq -s` collects the bounded sample, and the expression inspects only
its first event or first array row. Use the exact keys from this output in your
`jq`/filters. Nested groups appear dotted (e.g. `runtime.containerName`,
`proc.comm`, `dst.port`).

## 3. Select only the fields you need

```bash
sudo ig run trace_dns:latest --timeout 5 \
  -o columns --fields runtime.containerName,name,qtype,rcode,latency_ns
```

`-o json` for machine parsing, `-o columns --fields <comma-list>` for a compact
table, `-o jsonpretty` when eyeballing structure. (Do **not** write
`-o columns=<comma-list>` — `-o` comma-splits into output *modes*, so it prints nothing.)

## 4. There is no gadget list command — gadgets are images

`sudo ig run <name>:latest` pulls the gadget image on demand. There is **no
`list-gadgets` subcommand**. To know what exists: use the shortlist in `SKILL.md`
and `references/gadget-catalog.md`, run any candidate with `--help` to confirm it
resolves, or browse the upstream catalog at
<https://inspektor-gadget.io/docs/latest/gadgets/>.
