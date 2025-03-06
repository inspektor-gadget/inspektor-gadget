---
title: 'Displaying Output'
sidebar_position: 620
---

By default, Inspektor Gadget allows you to display the output of each data
source in all the output modes supported by the [CLI
operator](../spec/operators/cli.md#output). Unless you have specific
requirements, we recommend using the CLI operator's default configuration.
However, for [Map Iterators](./gadget-intro.md#map-iterators) with a map value
type of `gadget_histogram_slot__u32` or `gadget_histogram_slot__u64` (TODO: Add
links), the output should be displayed as a chart, which the CLI operator
doesn't support. In such cases, you can use the [Otel
Metrics](../spec/operators/otel-metrics.md) operator to render the output as a
histogram by annotating the data source with [metrics.print:
"true"](../spec/operators/otel-metrics.md#metricsprint). The
[profile_blockio](../gadgets/profile_blockio.mdx) gadget is an example of this.

## Fields

The fields to be displayed in the output when using the `columns`, `json`,
`jsonpretty` or `yaml` output modes depend on the data source type:

- Tracers: The fields are all the elements of the event `struct` specified when
  defining the data source.
- Map Iterators: The fields are all the elements of the key and value `struct`s
  used to define the eBPF map to be iterated. As mentioned above, there is a
  special case for the map iterators with a map value type of
  `gadget_histogram_slot__u32` or `gadget_histogram_slot__u64`. In such cases,
  the data source created by the Otel Metrics operator will contain just one
  field called `text` which will carry the rendered histogram as a plain text.
- Snapshotters: The fields are all the elements of the snapshot entry `struct`
  specified when defining the data source.

## Custom Text Output

There are cases when you want to print custom output. This can be implemented by
using a [WASM](./gadget-wasm-api-go.md) module and some annotations on the
[metadata](./metadata.md) file.

First of all, annotate the datasource with the name of the output mode:

```yaml
datasources:
  mydatasource:
    annotations:
      cli.supported-output-modes: myoutputmode,myoutputmode1,myoutputmode2
      cli.default-output-mode: myoutputmode
```

Then, in the WASM module create the data source and a string field called `text`
that will be used to emit the data:

:::warning

The field needs to be called `text` to be recognized by the CLI operator.

:::

```go
var (
	textds    api.DataSource
	textField api.Field
)

//go:wasmexport gadgetInit
func gadgetInit() int32 {
	var err error
	textds, err = api.NewDataSource("mydatasource", api.DataSourceTypeSingle)
	if err != nil {
		api.Errorf("creating datasource: %s", err)
		return 1
	}

	textField, err = textds.AddField("text", api.Kind_String)
	if err != nil {
		api.Errorf("adding field: %s", err)
		return 1
	}

	return 0
}
```

Then, format your output as a string and emit it:

```go
//go:wasmexport gadgetStart
func gadgetStart() int32 {
	nd, err := textds.NewPacketSingle()
	if err != nil {
		api.Errorf("creating packet: %s", err)
		return 1
	}

	if err := textField.SetString(api.Data(nd), "hi there!!"); err != nil {
		api.Errorf("setting field: %s", err)
		return 1
	}

	if err := textds.EmitAndRelease(api.Packet(nd)); err != nil {
		api.Errorf("emitting packet: %s", err)
		return 1
	}

	return 0
}
```

```bash
$ sudo ig image build . -t hello-world
$ sudo ig run hello-world --verify-image=false
hi there!!
```
