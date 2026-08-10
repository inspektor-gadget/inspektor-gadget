# Discovering params and fields — the golden rule

**Never hardcode a gadget's flags or fields from memory. Ask the gadget.**
Gadget images are versioned OCI artifacts; flags and fields change between
releases and new gadgets ship. If you rely on a remembered field name it will
eventually be wrong. The gadget's own `-h` output is the contract, so a skill
built on discovery never drifts.

## 1. List flags + every field, for any gadget

```bash
kubectl gadget run <gadget>:latest -h
```

The help output ends with a **`--fields`** block that enumerates every *data
source* and every *field* the gadget can emit, each with a short description.
This is the authoritative field list — richer than any doc, and always current
for the image you actually pulled. Today this block is human-readable text
only — there is no machine-parseable (`-o json`) form of `-h`, so to feed the
field list into `jq`/tooling you currently scrape the text or run the gadget
once with `-o json` and read the keys off a sample event. Example (abridged) for `trace_dns`:

```
--fields string   Available data sources / fields
                    "dns" (data source):
                      addresses   Comma-separated IPs from the DNS responses ...
                      name        The queried domain name
                      qtype       The query type (A, AAAA, ...)
                      latency_ns  Time between query and response ...
                      src / dst   endpoint (+ .k8s.namespace/.k8s.name/.port ...)
                      ...
```

## 2. Confirm field names from a real sample

Flags tell you what *can* be emitted; a live sample tells you the exact JSON
keys you'll parse:

```bash
kubectl gadget run <gadget>:latest -A --timeout 5 -o json \
  | jq -s '(.[0] // {}) | if type == "array" then (.[0] // {}) else . end | keys'
```

Streaming datasources emit one JSON object per line; snapshot/top datasources emit
JSON arrays. `jq -s` collects the bounded sample, and the expression inspects only
its first event or first array row. Use the exact keys from this output in your
`jq`/filters. Nested groups appear dotted (e.g. `k8s.podName`, `proc.comm`,
`dst.port`).

## 3. Select only the fields you need

Long event rows waste context and slow reading. Project fields once you know
their names:

```bash
kubectl gadget run trace_dns:latest -n prod --timeout 5 \
  -o columns --fields k8s.podName,name,qtype,rcode,latency_ns
```

`-o json` for machine parsing, `-o columns --fields <comma-list>` for a compact
human table, `-o jsonpretty` when eyeballing structure. (Do **not** write
`-o columns=<comma-list>` — `-o` comma-splits into output *modes*, so it prints nothing.)

## 4. There is no gadget list command — gadgets are images

`kubectl gadget run <name>:latest` pulls the gadget image on demand. There is
**no `list-gadgets` subcommand**. To know what exists:

- Use the shortlist in `SKILL.md` and the grouped `references/gadget-catalog.md`.
- Run any candidate with `-h` to confirm it resolves and see its real interface.
- Browse the upstream catalog at <https://inspektor-gadget.io/docs/latest/gadgets/>
  (authoritative for the *shipped* set at a given release).
